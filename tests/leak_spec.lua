-- Nothing a sandbox starts may outlive it: the bwrap process, the in-sandbox network relay (an
-- `nvim -l relay.lua` that used to ignore SIGTERM and stay behind by the hundred after test runs),
-- and the host-side proxy. Every spec here waits with a timeout, so a regression FAILS fast
-- instead of hanging.
local H = require("xynotest.helpers")
if H.os ~= "linux" then
  H.skip_file("needs linux")
end
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

--- Processes naming `marker`, without the shells that merely carry it in their arguments.
local function procs(marker)
  return vim.tbl_filter(function(p)
    return not p[2]:match("^sh ")
  end, H.procs(marker))
end

local RELAY = H.repo .. "/lua/xyno_sandbox/relay.lua"

--- Start the relay on the host (no sandbox) under a throw-away parent shell; returns the table
--- { parent = pid of the shell, dir, marker }.
local function host_relay()
  local dir = H.tmpdir()
  local marker = dir:match("([^/]+)$")
  vim.fn.mkdir(dir .. "/net", "p")
  vim.fn.writefile({}, dir .. "/net/proxy.sock") -- the relay only checks that the path exists
  local port = 20000 + (uv.hrtime() % 20000)
  local ready = dir .. "/ready"
  local script = ('"%s" -u NONE -i NONE --headless -l "%s" "%s" %d "%s" </dev/null >/dev/null 2>&1 & wait'):format(
    vim.v.progpath,
    RELAY,
    dir .. "/net/proxy.sock",
    port,
    ready
  )
  local sh = vim.system({ "sh", "-c", script, "xyno-leak-parent", marker })
  H.ok(
    vim.wait(10000, function()
      return uv.fs_stat(ready) ~= nil
    end, 50),
    "the relay did not come up"
  )
  return { sh = sh, dir = dir, marker = marker, ready = ready }
end

describe("the in-sandbox relay", function()
  it("exits on SIGTERM", function()
    local r = host_relay()
    local procs = procs(r.dir .. "/net/proxy.sock")
    H.eq(1, #procs, vim.inspect(procs))
    uv.kill(procs[1][1], 15)
    H.eq({}, H.wait_gone(r.dir .. "/net/proxy.sock", 4000), "the relay ignored SIGTERM")
    r.sh:kill(9)
  end)

  it("exits when its parent is gone", function()
    local r = host_relay()
    H.eq(1, #procs(r.dir .. "/net/proxy.sock"))
    r.sh:kill(9)
    H.eq({}, H.wait_gone(r.dir .. "/net/proxy.sock", 4000), "the relay outlived its parent")
  end)

  it("exits when the proxy's socket is gone", function()
    local r = host_relay()
    H.eq(1, #procs(r.dir .. "/net/proxy.sock"))
    uv.fs_unlink(r.dir .. "/net/proxy.sock")
    H.eq({}, H.wait_gone(r.dir .. "/net/proxy.sock", 4000), "the relay outlived its proxy socket")
    r.sh:kill(9)
  end)
end)

describe("a sandbox whose launcher dies", function()
  it("takes bwrap, the agent and the relay with it (--die-with-parent)", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap({ "sleep", "300" }, project, tmp)
    H.ok(cmd, err)
    -- a parent we can kill without touching bwrap itself
    local parent = vim.system({ "sh", "-c", '"$@" & wait', "xyno-leak-parent", unpack(cmd) }, { cwd = project })
    H.ok(
      vim.wait(10000, function()
        return #H.procs("proxy.sock") > 0
          and #H.procs(project) > 0
          and #H.procs("sleep 300") > 0
          and vim.iter(H.procs("relay.lua")):any(function(p)
            return p[2]:find(h.net_dir, 1, true)
          end)
      end, 100),
      "the sandbox did not come up"
    )
    parent:kill(9)
    local left = H.wait_gone(project, 5000)
    local why = ""
    for _, p in ipairs(left) do
      local f = io.open("/proc/" .. p[1] .. "/stat")
      why = why .. " [" .. p[1] .. ": " .. (f and (f:read("*a"):gsub("^%d+ %b() ", "")) or "gone") .. "]"
      if f then
        f:close()
      end
      local st = io.open("/proc/" .. p[1] .. "/status")
      if st then
        for line in st:lines() do
          if line:match("^State") or line:match("^Sig[PC]nd") or line:match("^ShdPnd") or line:match("^PPid") or line:match("^NSpid") then
            why = why .. " {" .. line:gsub("%s+", " ") .. "}"
          end
        end
        st:close()
      end
      local w = io.open("/proc/" .. p[1] .. "/wchan")
      if w then
        why = why .. " wchan=" .. w:read("*a")
        w:close()
      end
    end
    if #left > 0 then
      -- CI diagnostic: does the survivor die later, and what is every process of its pid namespace doing?
      local t0 = uv.hrtime()
      local late = H.wait_gone(project, 25000)
      why = why .. (" | gone after +%.1fs more: %s"):format((uv.hrtime() - t0) / 1e9, #late == 0 and "yes" or "NO")
      local diag = vim.system({
        "sh", "-c",
        "uname -r; bwrap --version; cat /proc/1/cmdline | tr '\\0' ' '; echo; "
          .. "ps -eo pid,ppid,pgid,sid,stat,wchan:30,etime,args --forest | cut -c1-180; "
          .. "for d in /proc/[0-9]*; do n=$(grep '^NSpid' $d/status 2>/dev/null | awk 'NF>2'); "
          .. "[ -n \"$n\" ] && { echo \"== $d $n\"; grep -E '^(Name|State|PPid|SigPnd|ShdPnd|SigBlk|SigIgn|SigCgt)' $d/status | tr '\\n' ' '; echo; "
          .. "cat $d/wchan; echo; cat $d/syscall; sudo -n cat $d/stack 2>&1 | head -20; }; done",
      }, { text = true }):wait()
      why = why .. "\nDIAG:\n" .. (diag.stdout or "") .. (diag.stderr or "")
    end
    local agent = procs("sleep 300")
    local relay_left = vim.tbl_filter(function(p)
      return p[2]:find(h.net_dir, 1, true)
    end, H.procs(h.net_dir))
    for _, p in ipairs(relay_left) do
      uv.kill(p[1], 9)
    end
    h.release()
    H.eq({}, left, "bwrap survived its parent; /proc stat (state ppid pgrp ...)" .. why)
    H.eq({}, relay_left, "the relay survived the sandbox")
    for _, p in ipairs(agent) do
      uv.kill(p[1], 9)
    end
    H.eq(
      {},
      vim.tbl_filter(function(p)
        return p[2] == "sleep 300 " or p[2] == "sleep 300"
      end, procs("sleep 300")),
      "the agent survived the sandbox"
    )
  end)

  it("the plan always carries --die-with-parent", function()
    local p = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    H.has(plan.argv(p), "--die-with-parent")
    H.has(plan.ISOLATION_FLAGS, "--die-with-parent")
  end)
end)

describe("release", function()
  it("closes the host-side proxy and removes its socket directory", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd, err)
    local sock = h.net_dir .. "/proxy.sock"
    H.ok(uv.fs_stat(sock), "the proxy socket exists while the sandbox is live")
    local pipe = uv.new_pipe(false)
    local ok_before
    pipe:connect(sock, function(e)
      ok_before = e == nil
    end)
    H.ok(
      vim.wait(2000, function()
        return ok_before ~= nil
      end),
      "no answer from the proxy"
    )
    H.ok(ok_before, "the proxy accepts connections while the sandbox is live")
    pipe:close()
    local proxy = h.proxy
    H.not_ok(proxy.closed)
    h.release()
    H.ok(proxy.closed, "the proxy was not closed on release")
    H.eq(nil, uv.fs_stat(h.net_dir), "the socket directory is removed on release")
    local after
    local p2 = uv.new_pipe(false)
    p2:connect(sock, function(e)
      after = e or "connected"
    end)
    H.ok(
      vim.wait(2000, function()
        return after ~= nil
      end),
      "connect to a closed proxy hung"
    )
    H.not_ok(after == "connected", "the proxy still accepts connections after release")
    p2:close()
  end)

  it("a normal run leaves no relay behind once the agent exited", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap({ "sleep", "1" }, project, tmp)
    H.ok(cmd, err)
    local net_dir = h.net_dir
    H.eq(0, vim.system(cmd, { cwd = project }):wait(30000).code)
    h.release()
    H.eq({}, H.wait_gone(net_dir, 4000), "a relay is still running after the sandbox ended")
    H.eq({}, H.wait_gone(project, 2000), "bwrap is still running after the sandbox ended")
  end)
end)

describe("tests/run.lua", function()
  it("fails the run, and kills the process AND what it started, when a spec leaves a sandbox process behind", function()
    local dir = H.tmpdir()
    -- a duration of its own (this nvim's pid): a concurrent suite run or an older leftover never matches
    local n = 100000 + vim.uv.os_getpid()
    local f = assert(io.open(dir .. "/leaky_spec.lua", "w"))
    f:write(([[
      it("starts something that stays", function()
        local scratch = assert(os.getenv("XYNO_TEST_SCRATCH"))
        vim.system({ "sh", "-c", "sleep %d; :", "relay.lua", scratch .. "/leak-marker" }, { detach = true })
        vim.wait(300)
      end)
    ]]):format(n))
    f:close()
    local r = vim
      .system(
        { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/leaky_spec.lua" },
        { text = true, env = { XYNO_TEST_WORKER = "0" } }
      )
      :wait(60000)
    local left = H.wait_gone("sleep " .. n, 3000) -- (the child of the killed sh: its command line has no marker)
    H.eq(1, r.code, r.stdout)
    H.match(r.stdout, "left a process behind", true)
    H.match(r.stdout, "failed=1", true)
    H.eq({}, left, "the survivor and its sleep were killed")
  end)
end)
