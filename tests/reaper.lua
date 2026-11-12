-- Leftovers of a killed test run, and how the next run removes them.
-- A runner that is killed with SIGKILL cannot clean up: its private root (fake $HOME) and its scratch
-- directory stay. Both carry an ".owner" file with the runner's pid and start time; the NEXT run removes
-- every such directory whose runner is gone (a pid that was reused by another process has another start
-- time). Directories without an owner file (made by an older runner) go when they are over a day old.
-- Only directories with the runner's own name patterns, owned by the current user, are ever touched.
local M = {}

M.default_bases = { "/tmp", "/var/tmp" }

-- A runner that is killed with SIGKILL cannot clean up: its private root (fake $HOME) and its scratch
-- directory stay. Both carry an ".owner" file with the runner's pid and start time; the NEXT run removes
-- every such directory whose runner is gone (a pid that was reused by another process has another start
-- time). Directories without an owner file (made by an older runner) go when they are over a day old.
function M.proc_start(pid)
  local f = io.open("/proc/" .. pid .. "/stat", "rb")
  if not f then
    return nil
  end
  local line = f:read("a") or ""
  f:close()
  -- (the command name in parentheses may hold spaces: count fields after the last ")")
  local rest = line:match("%)%s+(.*)$")
  local n, start = 0, nil
  for field in (rest or ""):gmatch("%S+") do
    n = n + 1
    if n == 20 then -- field 22 of the line = 20th after "pid (comm)" state
      start = field
    end
  end
  return start
end

function M.owner_tag()
  local pid = vim.uv.os_getpid()
  return pid .. ":" .. tostring(M.proc_start(pid))
end

function M.mark_owner(dir)
  local f = io.open(dir .. "/.owner", "wb")
  if f then
    f:write(M.owner_tag())
    f:close()
  end
end

function M.owner_alive(tag)
  local pid, start = vim.trim(tag):match("^(%d+):(%S+)$")
  if not pid then
    return false
  end
  return M.proc_start(pid) == start
end

--- Remove the roots and scratch directories of runners that no longer exist. Returns how many.
function M.reap_stale(bases)
  local uid = vim.uv.getuid and vim.uv.getuid() or nil
  local n = 0
  for _, base in ipairs(bases) do
    for name, ty in vim.fs.dir(base) do
      local is_root = name:match("^xyno%-sandbox%-test%-") or name:match("^xyno%-run%-")
      local is_probe = name:match("^%.probe%-")
      local path = base .. "/" .. name
      -- (the type from the directory listing is the entry's own: a symlink is "link", never followed)
      local st = (is_root or is_probe) and ty == "directory" and vim.uv.fs_lstat(path) or nil
      if st and (not uid or st.uid == uid) then
        local stale
        local f = is_root and io.open(path .. "/.owner", "rb")
        if f then
          stale = not M.owner_alive(f:read("a") or "")
          f:close()
        else
          stale = os.time() - st.mtime.sec > (is_probe and 600 or 86400)
        end
        if stale then
          n = n + (vim.fn.delete(path, "rf") == 0 and 1 or 0)
        end
      end
    end
  end
  return n
end

--- The directories searched for leftovers: the places the runner creates its roots in (XYNO_TEST_REAP_BASES, a
--- colon separated list, replaces all of them: the specs of the reaper itself use private directories).
function M.bases(repo)
  local override = vim.env.XYNO_TEST_REAP_BASES
  if override and override ~= "" then
    local out = {}
    for b in override:gmatch("[^:]+") do
      if vim.uv.fs_stat(b) then
        out[#out + 1] = b
      end
    end
    return out
  end
  local bases = vim.list_extend({}, M.default_bases)
  local real = vim.uv.os_homedir() or ""
  for _, b in ipairs({
    vim.env.XYNO_TEST_BASE or "",
    real ~= "" and (real .. "/.cache") or "",
    vim.env.XDG_CACHE_HOME or "",
    repo .. "/.test-root",
  }) do
    if b:sub(1, 1) == "/" and vim.uv.fs_stat(b) then
      bases[#bases + 1] = b
    end
  end
  return bases
end

return M
