-- State of xyno-sandbox under stdpath("state")/xyno-sandbox: the append-only log of exception
-- decisions (exceptions.log, JSON lines), the remembered per-project approvals and the projects
-- whose policy was shown (state.json), and a registry of live sandboxes (live/).
-- The directory is under $HOME and not in the writable list, so the sandboxed agent cannot edit
-- its own approvals; plan.validate_exception also refuses to make it writable.
local M = {}

--- Directory of the state files (override with M.dir_override in specs).
function M.dir()
  return M.dir_override or (vim.fn.stdpath("state") .. "/xyno-sandbox")
end

local function write_file(path, text, mode, append)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f, err = io.open(path, append and "ab" or "wb")
  if not f then
    return nil, err
  end
  f:write(text)
  f:close()
  vim.uv.fs_chmod(path, mode or tonumber("600", 8))
  return true
end

local function now_iso()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

-- ------------------------------------------------------------------- log

function M.log_path()
  return M.dir() .. "/exceptions.log"
end

--- Append one decision. entry: { project, kind, value, decision, scope?, reason? }.
--- kind "env" is logged with `name`, the path kinds with `path`.
--- @return boolean ok, string? err
function M.log(entry)
  local rec = {
    ts = now_iso(),
    project = entry.project,
    kind = entry.kind,
    decision = entry.decision,
    scope = entry.scope,
    reason = entry.reason,
  }
  if entry.kind == "env" then
    rec.name = entry.value
  elseif entry.kind == "host" then
    rec.host = entry.value
  else
    rec.path = entry.value
  end
  local ok, line = pcall(vim.json.encode, rec)
  if not ok then
    return false, line
  end
  return write_file(M.log_path(), line .. "\n", nil, true)
end

--- All log records, oldest first.
function M.read_log()
  local out = {}
  local f = io.open(M.log_path(), "r")
  if not f then
    return out
  end
  for line in f:lines() do
    local ok, rec = pcall(vim.json.decode, line)
    if ok and type(rec) == "table" then
      out[#out + 1] = rec
    end
  end
  f:close()
  return out
end

-- ----------------------------------------------------------------- state

local function state_path()
  return M.dir() .. "/state.json"
end

function M.load()
  local f = io.open(state_path(), "r")
  local st
  if f then
    local ok, v = pcall(vim.json.decode, f:read("*a"))
    f:close()
    if ok and type(v) == "table" then
      st = v
    end
  end
  st = st or {}
  st.approvals = type(st.approvals) == "table" and st.approvals or {}
  st.seen = type(st.seen) == "table" and st.seen or {}
  st.next_id = tonumber(st.next_id) or 1
  return st
end

function M.save(st)
  local tmp = state_path() .. ".tmp"
  local ok, text = pcall(vim.json.encode, st)
  if not ok then
    return false, text
  end
  local w, err = write_file(tmp, text)
  if not w then
    return false, err
  end
  local r, rerr = vim.uv.fs_rename(tmp, state_path())
  return r and true or false, rerr
end

--- Remembered approvals of a project: { { id, kind, value, ts }, ... }
function M.approvals(project)
  local st = M.load()
  return vim.deepcopy(st.approvals[project] or {})
end

--- Every project with approvals: { [project] = list }
function M.all_approvals()
  local st = M.load()
  local out = {}
  for p, l in pairs(st.approvals) do
    if #l > 0 then
      out[p] = l
    end
  end
  return out
end

--- Remember an approval (idempotent per project, kind and value). Returns the record.
function M.remember(project, kind, value)
  local st = M.load()
  local list = st.approvals[project] or {}
  for _, a in ipairs(list) do
    if a.kind == kind and a.value == value then
      return a
    end
  end
  local rec = { id = st.next_id, kind = kind, value = value, ts = now_iso() }
  st.next_id = st.next_id + 1
  list[#list + 1] = rec
  st.approvals[project] = list
  assert(M.save(st))
  return rec
end

--- Revoke a remembered approval by id. Returns the removed record or nil.
function M.revoke(project, id)
  local st = M.load()
  local list = st.approvals[project] or {}
  for i, a in ipairs(list) do
    if a.id == id then
      table.remove(list, i)
      st.approvals[project] = #list > 0 and list or nil
      assert(M.save(st))
      return a
    end
  end
end

function M.seen(project)
  return M.load().seen[project] ~= nil
end

function M.mark_seen(project)
  local st = M.load()
  if not st.seen[project] then
    st.seen[project] = now_iso()
    M.save(st)
  end
end

-- ------------------------------------------------------------ live registry

local function live_dir()
  return M.dir() .. "/live"
end

local function alive(pid)
  local r = vim.uv.kill(pid, 0)
  return r == 0
end

--- Register a live sandbox of this nvim; returns its file name.
function M.live_add(project, id)
  local name = ("%d-%s"):format(vim.uv.os_getpid(), id)
  write_file(live_dir() .. "/" .. name, project .. "\n")
  return name
end

function M.live_remove(name)
  if name then
    vim.uv.fs_unlink(live_dir() .. "/" .. name)
  end
end

--- Is a sandbox of another registration (not `except`) live for this project? Stale entries of
--- dead processes are dropped.
function M.live_others(project, except)
  local found = false
  for name in vim.fs.dir(live_dir()) do
    if name ~= except then
      local pid = tonumber(name:match("^(%d+)%-"))
      local f = io.open(live_dir() .. "/" .. name, "r")
      local p = f and f:read("l")
      if f then
        f:close()
      end
      if pid and not alive(pid) then
        vim.uv.fs_unlink(live_dir() .. "/" .. name)
      elseif p == project then
        found = true
      end
    end
  end
  return found
end

return M
