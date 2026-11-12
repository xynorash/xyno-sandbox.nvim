-- Readiness probe: does bubblewrap really create a sandbox here? `bwrap` on PATH is not enough:
-- unprivileged user namespaces are off on some kernels (Debian), restricted by AppArmor
-- (Ubuntu 23.10+), or blocked by a container's seccomp profile. The probe runs the isolation
-- flags of the real launch with `true` as the command, asynchronously with a timeout, and caches
-- the verdict (a success for `ttl_ok` seconds, a failure for `ttl_fail`, so a fixed sysctl is
-- noticed soon). status() fails closed on a failed probe.
local plan = require("xyno_sandbox.plan")
local M = {}

M.timeout = 5000 -- ms
M.ttl_ok = 600 -- s
M.ttl_fail = 30 -- s

local cache = {} -- exepath -> { ok, reason, hint, at }
local inflight = {} -- exepath -> { callbacks }

local function read_sysctl(path)
  local f = io.open(path, "r")
  if not f then
    return nil
  end
  local v = f:read("l")
  f:close()
  return v and vim.trim(v) or nil
end
M.read_sysctl = read_sysctl -- replaceable in specs

--- Reason and fix hint for a failed `bwrap ... true`. Pure given the sysctl reader.
--- @param r { code: integer, stderr?: string, timed_out?: boolean }
--- @param sysctl? fun(path: string): string?
--- @return string reason, string? hint
function M.diagnose(r, sysctl)
  sysctl = sysctl or M.read_sysctl
  local err = vim.trim(r.stderr or "")
  if M.net and (err:lower():find("loopback", 1, true) or err:lower():find("rtm_newaddr", 1, true)
    or err:lower():find("network namespace", 1, true)) then
    return "bwrap cannot create an isolated network namespace (needed to filter egress): " .. err,
      'network egress cannot be enforced here; the agent is not started. network = "open" in setup() runs it with the network open'
  end
  if r.timed_out then
    return ("bwrap did not finish within %d s"):format(M.timeout / 1000),
      "something blocks namespace creation (a hung seccomp/LSM hook or a very loaded machine): run `bwrap --ro-bind / / true` in a shell"
  end
  local low = err:lower()
  if sysctl("/proc/sys/kernel/unprivileged_userns_clone") == "0" then
    return "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone = 0)",
      "enable them: `sudo sysctl kernel.unprivileged_userns_clone=1` (persist it in /etc/sysctl.d/)"
  end
  if sysctl("/proc/sys/user/max_user_namespaces") == "0" then
    return "user namespaces are disabled (user.max_user_namespaces = 0)",
      "raise the limit: `sudo sysctl user.max_user_namespaces=15000` (persist it in /etc/sysctl.d/)"
  end
  if sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1" then
    return "AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns = 1)",
      "give bwrap an AppArmor profile that allows `userns` (the bubblewrap package ships one on recent Ubuntu), or set `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`"
  end
  if low:find("setting up uid map", 1, true) or low:find("no permissions to create", 1, true)
    or low:find("operation not permitted", 1, true) or low:find("creating new namespace failed", 1, true) then
    return "bwrap cannot create a user namespace: " .. (err ~= "" and err or "permission denied"),
      "check kernel.unprivileged_userns_clone, user.max_user_namespaces, AppArmor/SELinux policy, and whether you run inside a container whose seccomp profile blocks `unshare`/`clone` (Docker: --security-opt seccomp=unconfined or a profile that allows user namespaces)"
  end
  if low:find("can't mount proc", 1, true) or low:find("mount proc", 1, true) then
    return "bwrap cannot mount /proc: " .. err,
      "this looks like a container with a masked /proc; run the container with the permissions bubblewrap needs, or on the host"
  end
  if low:find("can't find source path", 1, true) or low:find("no such file", 1, true) then
    return "bwrap failed: " .. err, nil
  end
  return ("bwrap exited with %d%s"):format(r.code or -1, err ~= "" and (": " .. err) or ""), nil
end

M.net = false -- set by status(): probe with --unshare-net too (the network filter needs it)

local function key()
  local p = vim.fn.exepath("bwrap")
  return (p ~= "" and p or "bwrap") .. (M.net and "+net" or "")
end

local function fresh(entry)
  if not entry then
    return false
  end
  local ttl = entry.ok and M.ttl_ok or M.ttl_fail
  return os.time() - entry.at < ttl
end

--- Cached verdict { ok, reason?, hint?, at } or nil when unknown or stale.
function M.cached()
  local e = cache[key()]
  return fresh(e) and e or nil
end

function M.reset()
  cache = {}
end

local function record(k, r)
  local e = { at = os.time() }
  if r.code == 0 and not r.timed_out then
    e.ok = true
  else
    e.ok = false
    e.reason, e.hint = M.diagnose(r)
  end
  cache[k] = e
  return e
end

local function spawn(opts, on_exit)
  local argv = plan.probe_argv(M.net)
  local ok, obj = pcall(vim.system, argv, { text = true, timeout = M.timeout }, on_exit)
  if not ok then
    return nil, tostring(obj)
  end
  return obj
end

--- Run the probe asynchronously; `cb(entry)` runs on the main loop. A probe already in flight is
--- joined. `force` ignores the cache.
function M.run(cb, force)
  local k = key()
  if not force and fresh(cache[k]) then
    if cb then
      cb(cache[k])
    end
    return
  end
  if inflight[k] then
    if cb then
      table.insert(inflight[k], cb)
    end
    return
  end
  inflight[k] = { cb }
  local obj, err = spawn({}, function(res)
    vim.schedule(function()
      local e = record(k, { code = res.code, stderr = res.stderr, timed_out = res.signal == 15 or res.code == 124 })
      local cbs = inflight[k] or {}
      inflight[k] = nil
      for _, f in ipairs(cbs) do
        f(e)
      end
    end)
  end)
  if not obj then
    inflight[k] = nil
    local e = record(k, { code = -1, stderr = err })
    if cb then
      cb(e)
    end
  end
end

--- Blocking probe (used by wrap() when nothing is cached): same command, same timeout.
function M.run_sync(force)
  local k = key()
  if not force and fresh(cache[k]) then
    return cache[k]
  end
  local obj, err = spawn({})
  if not obj then
    return record(k, { code = -1, stderr = err })
  end
  local res = obj:wait(M.timeout + 1000)
  if not res then
    pcall(obj.kill, obj, 9)
    return record(k, { code = 124, timed_out = true })
  end
  return record(k, { code = res.code, stderr = res.stderr, timed_out = res.signal == 15 or res.code == 124 })
end

return M
