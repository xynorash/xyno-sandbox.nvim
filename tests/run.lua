-- Spec runner. Usage (from the repository root):
--   nvim -l tests/run.lua                  every tests/*_spec.lua, one nvim each
--   nvim -l tests/run.lua tests/x_spec.lua one spec file in this nvim
-- One line per test (ok / FAIL / SKIP), a final
--   RESULT passed=N failed=N skipped=N
-- line, and exit code 0 only without failures.
local repo = vim.fs.dirname(vim.fs.dirname(debug.getinfo(1, "S").source:sub(2)))
if repo == "" or repo == "." then
  repo = vim.uv.cwd()
end
vim.opt.runtimepath:prepend(repo)

-- Names that sandbox guards create in a project directory. A spec that leaves one in /tmp breaks
-- every unrelated spec and tool that looks for a repository or an .envrc there, so a new one fails the run.
local STRAYS =
  { ".git", ".envrc", ".exrc", ".mcp.json", ".mise.toml", ".nvim.lua", ".nvimrc", ".cargo", ".claude", ".vscode" }
local function strays()
  local out = {}
  for _, n in ipairs(STRAYS) do
    if vim.uv.fs_lstat("/tmp/" .. n) then
      out[n] = true
    end
  end
  return out
end

-- ----------------------------------------------------------- hermetic environment
-- The parent process builds ONE private root (outside /tmp: the sandbox replaces /tmp with an empty
-- tmpfs, so a $HOME there would not exist inside it) holding a fake $HOME with fake agent
-- credentials, and runs every spec file in a child whose HOME / TMPDIR / XDG_* point into it. The
-- suite therefore passes with any real $HOME (no ~/.claude/.credentials.json needed, nothing of
-- the user's is read or written) and the root is deleted at the end. Every process whose command
-- line names the root (bwrap, the in-sandbox relay) is a process the specs created: any that is
-- still alive after a spec file finished is killed and FAILS the run.
local function writable_dir(d)
  -- (a $HOME that does not exist, or a read-only base, raises E739: that is "not usable", not a crash)
  local ok = pcall(vim.fn.mkdir, d, "p")
  if not ok then
    return false
  end
  local probe = vim.uv.fs_mkdtemp(d .. "/.probe-XXXXXX")
  if probe then
    vim.uv.fs_rmdir(probe)
    return true
  end
  return false
end

local function bad_base(d)
  for _, r in ipairs({ "/tmp", "/var/tmp", "/dev/shm", "/run" }) do
    if d == r or d:sub(1, #r + 1) == r .. "/" then
      return true
    end
  end
  return false
end

-- ------------------------------------------------------- leftovers of a killed run
-- (tests/reaper.lua: the owner marks and the removal of the roots of runners that no longer exist)
local reaper = dofile(repo .. "/tests/reaper.lua")
local mark_owner, reap_stale = reaper.mark_owner, reaper.reap_stale

local made_dirs = {} -- directories this run created only to hold the root (removed at the end when empty)

--- A private root outside /tmp, or nil when nowhere is writable (the caller then skips the run).
local function make_root()
  local real_home = vim.uv.os_homedir() or ""
  local cands = {}
  local xdg = vim.env.XDG_CACHE_HOME
  for _, c in ipairs({
    vim.env.XYNO_TEST_BASE or "",
    real_home ~= "" and (real_home .. "/.cache") or "",
    (xdg and xdg:sub(1, 1) == "/") and xdg or "",
    repo .. "/.test-root",
  }) do
    if c ~= "" then
      cands[#cands + 1] = c
    end
  end
  -- short paths first: the specs bind unix sockets below $HOME, and a socket path is limited to 107 bytes
  table.sort(cands, function(a, b)
    return (#a > 44 and 1 or 0) < (#b > 44 and 1 or 0)
  end)
  for _, base in ipairs(cands) do
    local existed = vim.uv.fs_stat(base) ~= nil
    if not bad_base(vim.uv.fs_realpath(base) or base) and writable_dir(base) then
      local root = vim.uv.fs_mkdtemp(base .. "/xyno-sandbox-test-XXXXXX")
      if root then
        root = vim.uv.fs_realpath(root)
        if not bad_base(root) then
          mark_owner(root)
          if not existed then
            made_dirs[#made_dirs + 1] = base
          end
          return root, real_home
        end
        vim.fn.delete(root, "rf")
      end
    end
  end
  return nil, real_home
end

local function write_file(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text)
  f:close()
end

--- Child environment: a fake home with fake credentials. Toolchains stay where they are (the
--- specs that build a crate need rustup) through CARGO_HOME / RUSTUP_HOME.
local function child_env(root, real_home)
  local home = root .. "/home"
  write_file(home .. "/.claude/.credentials.json", '{"claudeAiOauth":{"accessToken":"FAKE-xyno-sandbox-test-token"}}\n')
  write_file(home .. "/.claude.json", '{"numStartups":1}\n')
  -- scratch space stays under /tmp (several specs rely on /tmp being the host's tmpfs-hidden place),
  -- in a directory of this run so that its processes can be told apart
  -- The caller's TMPDIR is NOT honoured: a deep one makes every socket path of the net proxy exceed
  -- the 107 bytes of AF_UNIX, and the run would depend on the shell it was started from.
  local tmp = vim.uv.fs_mkdtemp("/tmp/xyno-run-XXXXXX")
  if not tmp then
    tmp = assert(vim.uv.fs_mkdtemp((vim.uv.os_getenv("TMPDIR") or "/var/tmp") .. "/xyno-run-XXXXXX"))
  end
  mark_owner(tmp)
  local env = {
    HOME = home,
    TMPDIR = tmp,
    XYNO_TEST_ROOT = root,
    XYNO_TEST_SCRATCH = tmp,
    XYNO_TEST_WORKER = "1",
    XDG_CONFIG_HOME = home .. "/.config",
    XDG_CACHE_HOME = home .. "/.cache",
    XDG_DATA_HOME = home .. "/.local/share",
    XDG_STATE_HOME = home .. "/.local/state",
  }
  -- No working bubblewrap (no binary, no user namespaces: a CI container): the specs that run
  -- commands inside a sandbox skip themselves (helpers.need_sandbox); the ones that only build and
  -- check plans and command lines still run, against a stub that always fails.
  local probe_cmd = require("xyno_sandbox.plan").probe_argv(true)
  local pr = vim.fn.executable("bwrap") == 1 and vim.system(probe_cmd, { text = true }):wait(15000) or nil
  if pr and pr.code == 0 then
    -- bubblewrap works here: a spec that then finds it unusable is a failure, not a skip
    env.XYNO_TEST_SANDBOX_OK = "1"
  end
  if not pr or pr.code ~= 0 then
    env.XYNO_TEST_SANDBOX_OK = "" -- (an outer run's mark must not survive into a nested one)
    env.XYNO_TEST_NO_SANDBOX = "1"
    io.stdout:write("NOTE no working bubblewrap here: the specs that run commands inside a sandbox are skipped\n")
    if vim.fn.executable("bwrap") ~= 1 then
      write_file(root .. "/fakebin/bwrap", "#!/bin/sh\necho 'bwrap: not installed (test stub)' >&2\nexit 1\n")
      vim.uv.fs_chmod(root .. "/fakebin/bwrap", tonumber("755", 8))
      env.PATH = root .. "/fakebin:" .. (vim.env.PATH or "")
    end
  end
  for var, rel in pairs({ CARGO_HOME = "/.cargo", RUSTUP_HOME = "/.rustup" }) do
    if not vim.env[var] and real_home ~= "" and vim.uv.fs_stat(real_home .. rel) then
      env[var] = real_home .. rel
    end
  end
  return env
end

--- Command lines (pid, text) of the live processes that mention `root` and are a sandbox or its relay.
local function survivors(root, tmp)
  local out = {}
  for name in vim.fs.dir("/proc") do
    local pid = tonumber(name)
    if pid and pid ~= vim.uv.os_getpid() then
      local f = io.open("/proc/" .. name .. "/cmdline", "rb")
      if f then
        local c = (f:read("a") or ""):gsub("%z", " ")
        f:close()
        if
          (c:find(root, 1, true) or c:find(tmp, 1, true)) and (c:find("relay.lua", 1, true) or c:find("bwrap", 1, true))
        then
          out[#out + 1] = { pid, c }
        end
      end
    end
  end
  return out
end

--- Every process below the pids of `list` ({ { pid, cmdline } }), from /proc/<pid>/stat.
local function descendants(list)
  local parent = {}
  for name in vim.fs.dir("/proc") do
    local pid = tonumber(name)
    if pid then
      local f = io.open("/proc/" .. name .. "/stat", "rb")
      local line = f and f:read("a") or ""
      if f then
        f:close()
      end
      local ppid = line:match("%)%s+%S+%s+(%d+)")
      if ppid then
        parent[pid] = tonumber(ppid)
      end
    end
  end
  local roots, out, seen = {}, {}, {}
  for _, s in ipairs(list) do
    roots[s[1]] = true
  end
  for pid in pairs(parent) do
    local p, hops = parent[pid], 0
    while p and p > 1 and hops < 64 do
      if roots[p] then
        if not seen[pid] then
          seen[pid] = true
          out[#out + 1] = pid
        end
        break
      end
      p, hops = parent[p], hops + 1
    end
  end
  return out
end

--- Wait briefly for the survivors to go (their sandbox may still be tearing down), then kill -9.
local function reap(root, tmp)
  local list
  for _ = 1, 20 do
    list = survivors(root, tmp)
    if #list == 0 then
      return {}
    end
    vim.wait(100)
  end
  -- what the survivors started (the `sleep` of `sh -c 'sleep 120; :'`: its command line names nothing of the run) is
  -- found BEFORE the parents die, while it still has them as its parent
  local kids = descendants(list)
  for _, s in ipairs(list) do
    vim.uv.kill(s[1], 9)
  end
  for _, pid in ipairs(kids) do
    vim.uv.kill(pid, 9)
  end
  -- wait until they are really gone (a loaded machine can take longer than a fixed pause)
  vim.wait(5000, function()
    return #survivors(root, tmp) == 0
  end, 50)
  return list
end

local FILE_TIMEOUT_MS = tonumber(vim.env.XYNO_TEST_FILE_TIMEOUT_MS) or 240000

-- The spec child runs in a process group of its own (detach = setsid), watched by a small shell process that is
-- not a child of this runner: when this runner disappears (kill -9 cannot be caught) the watchdog kills the whole
-- group and whatever still mentions the run's directories, so a spec that sleeps or hangs does not outlive it.
-- (The environment, not the command line, carries the directories: pkill -f must not match the watchdog itself.)
local WATCHDOG = [[
rpid=$1; rstart=$2; pg=$3
alive() {
  set -- $(sed 's/^.*) //' "/proc/$rpid/stat" 2>/dev/null)
  [ -n "$1" ] && [ "$1" != Z ] && [ "${20}" = "$rstart" ]
}
while alive; do
  kill -0 -- "-$pg" 2>/dev/null || exit 0
  sleep 0.5
done
kill -KILL -- "-$pg" 2>/dev/null
for d in "$WD_ROOT" "$WD_TMP"; do
  [ -n "$d" ] && pkill -KILL -f -- "$d" 2>/dev/null
done
exit 0
]]

local function run_child(argv, env, root)
  local child = vim.system(argv, { text = true, env = env, detach = true })
  local wd = vim.system({
    "sh",
    "-c",
    WATCHDOG,
    "xyno-watchdog",
    tostring(vim.uv.os_getpid()),
    tostring(reaper.proc_start(vim.uv.os_getpid())),
    tostring(child.pid),
  }, { detach = true, env = vim.tbl_extend("force", env, { WD_ROOT = root, WD_TMP = env.XYNO_TEST_SCRATCH }) })
  local r = child:wait(FILE_TIMEOUT_MS)
  if r.code == 124 or r.signal == 15 or r.signal == 9 then
    pcall(vim.uv.kill, -child.pid, 9) -- what the hung spec started
  end
  pcall(vim.uv.kill, -wd.pid, 9)
  pcall(wd.wait, wd, 2000)
  return r
end

local function run_all(files)
  local reaped = reaper.reap_stale(reaper.bases(repo))
  if reaped > 0 then
    io.stdout:write(("NOTE removed %d private root(s) of earlier runs that were killed\n"):format(reaped))
  end
  local root, real_home = make_root()
  if not root then
    -- nothing to build a private $HOME in (HOME=/nonexistent, a read-only checkout): say so and skip
    io.stdout:write("SKIP all specs (no writable directory outside /tmp for the test root: set XYNO_TEST_BASE)\n")
    io.stdout:write("RESULT passed=0 failed=0 skipped=1 xfailed=0\n")
    os.exit(0)
  end
  local env = child_env(root, real_home)
  local before = strays()
  local total = { passed = 0, failed = 0, skipped = 0, xfailed = 0 }
  if not files then
    files = vim.fn.glob(repo .. "/tests/*_spec.lua", true, true)
    table.sort(files)
  end
  for _, f in ipairs(files) do
    local r = run_child({ vim.v.progpath, "--headless", "-l", repo .. "/tests/run.lua", f }, env, root)
    if r.code == 124 or r.signal == 15 or r.signal == 9 then
      total.failed = total.failed + 1
      io.stdout:write(
        ("FAIL %s timed out after %d s (killed): a hang is a failure, not a pause\n"):format(
          vim.fs.basename(f),
          FILE_TIMEOUT_MS / 1000
        )
      )
    end
    io.stdout:write(r.stdout or "")
    io.stderr:write(r.stderr or "")
    -- the LAST RESULT line is the file's own (a failure message may quote a nested run's)
    local last
    for line in (r.stdout or ""):gmatch("RESULT [^\n]*") do
      last = line
    end
    for k in pairs(total) do
      total[k] = total[k] + tonumber((last or ""):match(k .. "=(%d+)") or 0)
    end
    if
      r.code ~= 0
      and not (r.stdout or ""):find("RESULT", 1, true)
      and not (r.code == 124 or r.signal == 15 or r.signal == 9)
    then
      total.failed = total.failed + 1
    end
    for n in pairs(strays()) do
      if not before[n] then
        before[n] = true
        total.failed = total.failed + 1
        io.stdout:write(
          ("FAIL %s left /tmp/%s behind (a sandbox placeholder leaked into a shared directory)\n"):format(
            vim.fs.basename(f),
            n
          )
        )
      end
    end
    for _, s in ipairs(reap(root, env.XYNO_TEST_SCRATCH)) do
      total.failed = total.failed + 1
      io.stdout:write(
        ("FAIL %s left a process behind (killed): pid %d %s\n"):format(vim.fs.basename(f), s[1], s[2]:sub(1, 160))
      )
    end
  end
  reaper.remove_tree(root)
  reaper.remove_tree(env.XYNO_TEST_SCRATCH)
  for _, d in ipairs(made_dirs) do
    vim.uv.fs_rmdir(d) -- only when empty
  end
  io.stdout:write(
    ("RESULT passed=%d failed=%d skipped=%d xfailed=%d\n"):format(
      total.passed,
      total.failed,
      total.skipped,
      total.xfailed
    )
  )
  os.exit(total.failed > 0 and 1 or 0)
end

local spec = _G.arg and _G.arg[1]
if vim.env.XYNO_TEST_WORKER ~= "1" then
  return run_all(spec and { vim.fn.fnamemodify(spec, ":p") } or nil)
end
spec = vim.fn.fnamemodify(spec, ":p")

vim.opt.runtimepath:prepend(repo)
for _, name in ipairs({ "helpers", "harness" }) do
  package.preload["xynotest." .. name] = function()
    return dofile(repo .. "/tests/" .. name .. ".lua")
  end
end

local harness = require("xynotest.harness")
harness.install()
if vim.env.XYNO_TEST_NO_SANDBOX == "1" then
  -- plan/argv structure specs need status() to say "bwrap"; the behavioural ones skip on the real run
  -- (until a spec resets the probe cache: the probe specs then see the real, failing verdict)
  local probe = require("xyno_sandbox.probe")
  local seeded, real_cached, real_reset = true, probe.cached, probe.reset
  probe.cached = function()
    return seeded and { ok = true, at = os.time() } or real_cached()
  end
  probe.reset = function()
    seeded = false
    return real_reset()
  end
end
local counts
local ok, err = xpcall(dofile, debug.traceback, spec)
if not ok then
  if harness.is_skip(err) then
    io.stdout:write(("SKIP %s (%s)\n"):format(vim.fs.basename(spec), err.reason))
    counts = { passed = 0, failed = 0, skipped = 1, xfailed = 0 }
  else
    io.stdout:write("FAIL loading " .. spec .. "\n" .. tostring(err) .. "\n")
    counts = { passed = 0, failed = 1, skipped = 0, xfailed = 0 }
  end
else
  counts = harness.run()
end
io.stdout:write(
  ("RESULT passed=%d failed=%d skipped=%d xfailed=%d\n"):format(
    counts.passed,
    counts.failed,
    counts.skipped,
    counts.xfailed or 0
  )
)
io.stdout:flush()
pcall(function()
  require("xynotest.helpers").cleanup()
end)
os.exit(counts.failed > 0 and 1 or 0)
