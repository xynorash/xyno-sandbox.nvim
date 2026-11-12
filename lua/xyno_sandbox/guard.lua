-- What a run changed in the project tree that acts OUTSIDE the sandbox later.
--
-- Two jobs, both on the real filesystem (the plan is pure and cannot do them):
--
--  1. PLANTED NAMES. Files and directories whose names make a tool of yours run something
--     (`.cargo/config.toml`, `.envrc`, `.claude/settings.json`, `.vscode/tasks.json`, a nested `.git`
--     with hooks, `mise.toml`, `rust-toolchain.toml`, ...: plan.WATCH_NAMES) are read-only in the
--     sandbox where they exist, and masked where they are absent in the shallowest directories
--     (plan.SUBDIR_MASK_MAX). Everywhere else a run can still create one, so a snapshot is taken at
--     launch and compared when the run ends: every NEW protected name is copied into a quarantine
--     directory under the state dir (nothing is lost), removed from the project, and the project is
--     marked dirty: the next launch is refused until you reviewed the quarantine (:XynoSandboxReview,
--     then :XynoSandboxReview clear).
--
--  2. FILES THE AGENT MAY EDIT THAT RUN LATER. Makefile, justfile, package.json, Cargo.toml, build.rs,
--     CI workflows... cannot be locked (the agent has to edit them); a hash of each is kept at launch and
--     a summary of what changed (lines added and removed) is reported when the run ends.
--
-- It is bounded (directories, time) and says when a bound stopped the walk.
local plan_mod = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local M = {}

M.MAX_DIRS = 20000
M.MAX_DEPTH = 40
M.MAX_MS = 1500
-- the directories in SKIP_DIRS are walked too, for the protected names only (a cargo config under target/debug, an .envrc in
-- node_modules/x), with a budget of their own so that a huge build tree cannot use up the main one
M.SKIP_MAX_DIRS = 4000
M.SKIP_MAX_MS = 700
M.REVIEW_MAX_BYTES = 128 * 1024
M.REVIEW_KEEP_BYTES = 4 * 1024 * 1024 -- text kept in memory for the diff summary (more: hashes only)
M.QUARANTINE_FILE_MAX = 1024 * 1024
M.QUARANTINE_ENTRIES_MAX = 300
-- walked in a second pass with the smaller budget above (M.SKIP_MAX_DIRS / M.SKIP_MAX_MS), after everything else
M.SKIP_DIRS = { target = true, node_modules = true, [".git"] = true, [".venv"] = true, venv = true, __pycache__ = true }
-- their content changes by itself while you work (the index, the IDE's workspace file): only their
-- appearance counts, never a change inside
M.NOISY = { [".git"] = true, [".idea"] = true }

local function is_review(name, dir)
  for _, n in ipairs(plan_mod.REVIEW_NAMES) do
    if n == name then
      return true
    end
  end
  return dir:sub(-18) == "/.github/workflows"
end

local function sig_of(st)
  return ("%s:%d:%d.%d"):format(st.type, st.size or 0, st.mtime and st.mtime.sec or 0, st.mtime and st.mtime.nsec or 0)
end

local function list(path)
  local out = {}
  local h = vim.uv.fs_scandir(path)
  while h do
    local name, ty = vim.uv.fs_scandir_next(h)
    if not name then
      break
    end
    out[#out + 1] = { name, ty }
  end
  table.sort(out, function(a, b)
    return a[1] < b[1]
  end)
  return out
end

-- signature of a protected directory: its whole listing (bounded), so a file planted inside changes it
local function dir_sig(path)
  local parts, n = {}, 400
  local function rec(p, rel, d)
    for _, e in ipairs(list(p)) do
      n = n - 1
      if n < 0 then
        return
      end
      local st = vim.uv.fs_lstat(p .. "/" .. e[1])
      if st then
        parts[#parts + 1] = rel .. e[1] .. "=" .. sig_of(st)
        if st.type == "directory" and d < 6 then
          rec(p .. "/" .. e[1], rel .. e[1] .. "/", d + 1)
        end
      end
    end
  end
  rec(path, "", 0)
  return table.concat(parts, "|")
end

local function read_small(path, max)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local data = f:read(max + 1)
  f:close()
  if data and #data > max then
    return nil
  end
  return data
end

local function ident(st)
  return ("%.0f:%.0f"):format(st.dev or 0, st.ino or 0)
end

--- Walk `project` and record the protected names and the review files. The directories of SKIP_DIRS are
--- walked after the rest with a budget of their own. A bound that stopped the walk is recorded:
--- `truncated` (main budget), `skip_truncated` (the second pass), `depth_cut` (a directory below MAX_DEPTH).
--- @param project string
--- @return { protected: table<string,string>, ino: table<string,string>, review: table<string,table>, dirs: integer, truncated: boolean, skip_truncated: boolean, depth_cut: boolean, why?: string }
function M.snapshot(project)
  local snap = {
    protected = {},
    ino = {},
    review = {},
    dirs = 0,
    skip_dirs = 0,
    truncated = false,
    skip_truncated = false,
    depth_cut = false,
  }
  local watch, slashed = {}, {}
  for _, n in ipairs(plan_mod.WATCH_NAMES) do
    if n:find("/", 1, true) then
      slashed[#slashed + 1] = n
    else
      watch[n] = true
    end
  end
  local kept = 0
  local function record_protected(path, noisy)
    local st = vim.uv.fs_lstat(path)
    if st then
      local sig = sig_of(st)
      if st.type == "directory" and not noisy then
        sig = sig .. "#" .. dir_sig(path)
      elseif noisy then
        sig = st.type -- appearance only
      end
      snap.protected[path] = sig
      snap.ino[path] = ident(st)
    end
  end
  local function record_review(path)
    local st = vim.uv.fs_lstat(path)
    if not st or st.type ~= "file" then
      return
    end
    local rec = { sig = sig_of(st), size = st.size }
    local data = st.size <= M.REVIEW_MAX_BYTES and read_small(path, M.REVIEW_MAX_BYTES) or nil
    if data then
      rec.sha = vim.fn.sha256(data)
      if kept + #data <= M.REVIEW_KEEP_BYTES then
        rec.text = data
        kept = kept + #data
      end
    end
    snap.review[path] = rec
  end
  local skipped = {}
  -- one breadth-first pass over `queue`; directories of SKIP_DIRS go to `skipped` (first pass) or are entered (second)
  local function pass(queue, second)
    local t0 = vim.uv.hrtime()
    local max_dirs, max_ms = second and M.SKIP_MAX_DIRS or M.MAX_DIRS, second and M.SKIP_MAX_MS or M.MAX_MS
    local count = 0
    local qi = 1
    while qi <= #queue do
      local dir, depth = queue[qi][1], queue[qi][2]
      qi = qi + 1
      count = count + 1
      local over
      if count > max_dirs then
        over = "more than " .. max_dirs .. " directories"
      elseif (vim.uv.hrtime() - t0) / 1e6 > max_ms then
        over = "more than " .. max_ms .. " ms"
      end
      if over then
        if second then
          snap.skip_truncated = true
          snap.skip_why = over .. " inside target, node_modules, virtualenvs"
        else
          snap.truncated, snap.why = true, over
        end
        break
      end
      if second then
        snap.skip_dirs = snap.skip_dirs + 1
      else
        snap.dirs = snap.dirs + 1
      end
      local present = {}
      for _, e in ipairs(list(dir)) do
        local name, ty = e[1], e[2]
        present[name] = true
        local path = dir .. "/" .. name
        if watch[name] then
          record_protected(path, M.NOISY[name])
        end
        if is_review(name, dir) then
          record_review(path)
        end
        if ty == nil or ty == "unknown" then
          local st = vim.uv.fs_lstat(path)
          ty = st and st.type
        end
        if ty == "directory" and not watch[name] then
          if depth >= M.MAX_DEPTH then
            snap.depth_cut = true
          elseif M.SKIP_DIRS[name] and not second then
            skipped[#skipped + 1] = { path, depth + 1 }
          else
            queue[#queue + 1] = { path, depth + 1 }
          end
        end
      end
      if present[".config"] then
        for _, rel in ipairs(slashed) do
          if vim.uv.fs_lstat(dir .. "/" .. rel) then
            record_protected(dir .. "/" .. rel, false)
          end
        end
      end
    end
  end
  pass({ { project, 0 } }, false)
  if #skipped > 0 then
    pass(skipped, true)
  end
  return snap
end

local function count_lines(text)
  local n = 0
  for _ in (text or ""):gmatch("[^\n]*\n?") do
    n = n + 1
  end
  return n
end

--- Lines added and removed between two texts (nil, nil when either text was not kept).
local function line_delta(a, b)
  if not a or not b then
    return nil, nil
  end
  local ok, hunks = pcall(vim.diff, a, b, { result_type = "indices" })
  if not ok or type(hunks) ~= "table" then
    return nil, nil
  end
  local plus, minus = 0, 0
  for _, h in ipairs(hunks) do
    minus = minus + h[2]
    plus = plus + h[4]
  end
  return plus, minus
end

--- What differs between a launch snapshot and a snapshot taken now.
--- @return { planted: string[], modified: string[], removed: string[], moved: { from: string, to: string }[], incomplete: string[], partial: string[], review: { path: string, change: string, plus?: integer, minus?: integer }[] }
function M.compare(before, after)
  local res = { planted = {}, modified = {}, removed = {}, review = {}, moved = {}, incomplete = {}, partial = {} }
  -- a directory that was RENAMED during the run (mv sub sub_old) shows its protected names under a new path: they are the
  -- same inodes as before, not new files
  local gone = {}
  for p in pairs(before.protected) do
    if after.protected[p] == nil and before.ino and before.ino[p] then
      gone[before.ino[p]] = p
    end
  end
  for p, sig in pairs(after.protected) do
    local from = before.protected[p] == nil and after.ino and gone[after.ino[p] or ""] or nil
    if from then
      res.moved[#res.moved + 1] = { from = from, to = p }
      gone[after.ino[p]] = nil
    elseif before.protected[p] == nil then
      res.planted[#res.planted + 1] = p
    elseif before.protected[p] ~= sig then
      res.modified[#res.modified + 1] = p
    end
  end
  local moved_from = {}
  for _, m in ipairs(res.moved) do
    moved_from[m.from] = true
  end
  for p in pairs(before.protected) do
    if after.protected[p] == nil and not moved_from[p] then
      res.removed[#res.removed + 1] = p
    end
  end
  -- a bound that stopped the walk now but not at launch means the tree grew past what can be checked: whatever was
  -- created beyond it is unknown. Fail closed (dirty). A tree that was already too large at launch is only reported.
  for _, b in ipairs({
    { "truncated", "the project walk stopped (" .. tostring(after.why) .. ")" },
    {
      "skip_truncated",
      "the walk inside target, node_modules and virtualenvs stopped (" .. tostring(after.skip_why) .. ")",
    },
    { "depth_cut", "directories deeper than " .. M.MAX_DEPTH .. " levels were not entered" },
  }) do
    if after[b[1]] then
      table.insert(before[b[1]] and res.partial or res.incomplete, b[2])
    end
  end
  for p, a in pairs(after.review) do
    local b = before.review[p]
    if not b then
      res.review[#res.review + 1] =
        { path = p, change = "created", plus = a.text and count_lines(a.text) - 1 or nil, minus = 0 }
    elseif (a.sha or a.sig) ~= (b.sha or b.sig) then
      local plus, minus = line_delta(b.text, a.text)
      res.review[#res.review + 1] = { path = p, change = "changed", plus = plus, minus = minus }
    end
  end
  for p, b in pairs(before.review) do
    if not after.review[p] then
      res.review[#res.review + 1] =
        { path = p, change = "deleted", plus = 0, minus = b.text and count_lines(b.text) - 1 or nil }
    end
  end
  table.sort(res.moved, function(x, y)
    return x.to < y.to
  end)
  table.sort(res.planted)
  table.sort(res.modified)
  table.sort(res.removed)
  table.sort(res.review, function(x, y)
    return x.path < y.path
  end)
  return res
end

-- ------------------------------------------------------------- quarantine

local function copy_tree(src, dest, budget, depth)
  local st = vim.uv.fs_lstat(src)
  if not st then
    return
  end
  budget.n = budget.n - 1
  if budget.n < 0 then
    budget.cut = true
    return
  end
  if st.type == "link" then
    local target = vim.uv.fs_readlink(src)
    if target then
      vim.fn.mkdir(vim.fs.dirname(dest), "p")
      vim.uv.fs_symlink(target, dest)
    end
  elseif st.type == "directory" then
    vim.fn.mkdir(dest, "p")
    if depth < 8 then
      for _, e in ipairs(list(src)) do
        copy_tree(src .. "/" .. e[1], dest .. "/" .. e[1], budget, depth + 1)
      end
    end
  elseif st.type == "file" then
    vim.fn.mkdir(vim.fs.dirname(dest), "p")
    if st.size <= M.QUARANTINE_FILE_MAX then
      local data = read_small(src, M.QUARANTINE_FILE_MAX)
      if data then
        local f = io.open(dest, "wb")
        if f then
          f:write(data)
          f:close()
          vim.uv.fs_chmod(dest, tonumber("600", 8))
        end
      end
    else
      budget.cut = true
    end
  end
end

local function safe_key(project)
  return (project:gsub("[^%w]", "_")):sub(-80) .. "-" .. vim.fn.sha256(project):sub(1, 8)
end

local function dirty_path(project)
  return store.dir() .. "/dirty/" .. safe_key(project) .. ".json"
end

--- Copy `paths` (planted names) into the quarantine and remove them from the project. Returns
--- { dir, moved = { { path, ok } }, cut }.
function M.quarantine(project, paths)
  local stamp = os.date("!%Y%m%dT%H%M%SZ")
  local dir = ("%s/quarantine/%s/%s"):format(store.dir(), safe_key(project), stamp)
  local moved, cut = {}, false
  vim.fn.mkdir(dir, "p")
  vim.uv.fs_chmod(dir, tonumber("700", 8))
  for _, p in ipairs(paths) do
    local rel = p:sub(1, #project + 1) == project .. "/" and p:sub(#project + 2) or vim.fs.basename(p)
    local budget = { n = M.QUARANTINE_ENTRIES_MAX }
    copy_tree(p, dir .. "/" .. rel, budget, 0)
    cut = cut or budget.cut or false
    local rc = vim.fn.delete(p, "rf") -- (never follows a symlink)
    moved[#moved + 1] = { path = p, ok = rc == 0 }
  end
  return { dir = dir, moved = moved, cut = cut }
end

--- Mark the project dirty (the next launch is refused until cleared).
function M.mark_dirty(project, info)
  local rec = {
    project = project,
    ts = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    planted = info.planted or {},
    quarantine = info.quarantine,
    failed = info.failed or {},
    modified = info.modified or {},
    incomplete = info.incomplete or {},
  }
  local ok, text = pcall(vim.json.encode, rec)
  if not ok then
    return false
  end
  local path = dirty_path(project)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = io.open(path, "wb")
  if not f then
    return false
  end
  f:write(text)
  f:close()
  vim.uv.fs_chmod(path, tonumber("600", 8))
  return true
end

--- The dirty record of a project or nil.
function M.dirty(project)
  local f = io.open(dirty_path(project), "rb")
  if not f then
    return nil
  end
  local raw = f:read("*a")
  f:close()
  local ok, rec = pcall(vim.json.decode, raw)
  if ok and type(rec) == "table" then
    return rec
  end
  -- a record that cannot be read still blocks: it exists for a reason
  return { project = project, planted = {}, unreadable = true }
end

function M.clear_dirty(project)
  return vim.uv.fs_unlink(dirty_path(project)) and true or false
end

--- The refusal text of a dirty project.
function M.dirty_reason(rec)
  local planted = rec.planted or {}
  local shown = {}
  for i = 1, math.min(5, #planted) do
    shown[#shown + 1] = planted[i]
  end
  local text = ""
  if #planted > 0 then
    text = (
      "a previous sandbox run created %d file%s that run outside the sandbox (%s%s) and they were removed from the project;"
      .. " a copy is in %s."
    ):format(
      #planted,
      #planted == 1 and "" or "s",
      table.concat(shown, ", "),
      #planted > 5 and ", ..." or "",
      rec.quarantine or "the state directory"
    )
  end
  if rec.incomplete and #rec.incomplete > 0 then
    text = text
      .. (#planted > 0 and " " or "")
      .. ("The end-of-run check of the project tree could not be completed (%s), so more may have been created."):format(
        table.concat(rec.incomplete, "; ")
      )
  end
  if text == "" then
    text = "a previous sandbox run left this project marked for review."
  end
  return text .. " Review it (:XynoSandboxReview), then clear the mark with :XynoSandboxReview clear"
end

--- The report text of a finished run (nil when nothing changed).
function M.report(res)
  local lines = {}
  if #res.review > 0 then
    local parts = {}
    for _, r in ipairs(res.review) do
      local d = (r.plus and r.minus) and (" +%d -%d"):format(r.plus, r.minus) or ""
      parts[#parts + 1] = ("%s %s%s"):format(r.change, r.path, d)
    end
    lines[#lines + 1] = ("files that run on your machine later were edited (review before you build or run them): %s"):format(
      table.concat(vim.list_slice(parts, 1, 8), "; ") .. (#parts > 8 and ("; ... " .. #parts .. " in all") or "")
    )
  end
  if #res.modified > 0 then
    lines[#lines + 1] = ("existing files that act outside the sandbox changed: %s"):format(
      table.concat(vim.list_slice(res.modified, 1, 8), ", ")
    )
  end
  return lines
end

return M
