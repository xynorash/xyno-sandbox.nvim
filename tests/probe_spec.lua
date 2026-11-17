-- The readiness probe: status() fails closed when user namespaces do not work, with a precise hint.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local probe = require("xyno_sandbox.probe")

local saved = vim.deepcopy(sb.config)
local old_path = vim.env.PATH
after_each(function()
  sb.config = vim.deepcopy(saved)
  vim.env.PATH = old_path
  probe.reset()
  probe.read_sysctl = probe.read_sysctl_real or probe.read_sysctl
end)
probe.read_sysctl_real = probe.read_sysctl

local function fake_bwrap(script)
  local bin = H.tmpdir()
  local f = assert(io.open(bin .. "/bwrap", "w"))
  f:write("#!/bin/sh\n" .. script .. "\n")
  f:close()
  vim.uv.fs_chmod(bin .. "/bwrap", tonumber("755", 8))
  vim.env.PATH = bin .. ":" .. old_path
  probe.reset()
end

describe("diagnose", function()
  local function sysctl(map)
    return function(p)
      return map[p]
    end
  end
  it("names unprivileged_userns_clone", function()
    local r, hint = probe.diagnose(
      { code = 1, stderr = "bwrap: No permissions to create new namespace" },
      sysctl({ ["/proc/sys/kernel/unprivileged_userns_clone"] = "0" })
    )
    H.match(r, "kernel.unprivileged_userns_clone = 0", true)
    H.match(hint, "sysctl kernel.unprivileged_userns_clone=1", true)
  end)
  it("names max_user_namespaces", function()
    local r, hint = probe.diagnose({ code = 1, stderr = "x" }, sysctl({ ["/proc/sys/user/max_user_namespaces"] = "0" }))
    H.match(r, "max_user_namespaces", true)
    H.match(hint, "sysctl user.max_user_namespaces", true)
  end)
  it("names AppArmor", function()
    local r, hint = probe.diagnose(
      { code = 1, stderr = "x" },
      sysctl({ ["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"] = "1" })
    )
    H.match(r, "AppArmor", true)
    H.match(hint, "profile", true)
  end)
  it("explains a generic namespace failure (container seccomp, SELinux) with the stderr", function()
    local r, hint = probe.diagnose({ code = 1, stderr = "bwrap: setting up uid map: Permission denied" }, sysctl({}))
    H.match(r, "uid map", true)
    H.match(hint, "seccomp", true)
  end)
  it("a timeout says how long", function()
    local r = probe.diagnose({ code = 124, timed_out = true }, sysctl({}))
    H.match(r, "did not finish within", true)
  end)
  it("proc mount failure points at the container", function()
    local r, hint = probe.diagnose({ code = 1, stderr = "bwrap: Can't mount proc on /newroot/proc" }, sysctl({}))
    H.match(r, "/proc", true)
    H.match(hint, "container", true)
  end)
end)

describe("fail closed", function()
  it("a bwrap that cannot create a namespace makes status() refused, with reason and hint", function()
    fake_bwrap("echo 'bwrap: No permissions to create new namespace' >&2; exit 1")
    probe.read_sysctl = function(p)
      return p == "/proc/sys/kernel/unprivileged_userns_clone" and "0" or nil
    end
    local st = sb.status_blocking()
    H.eq("refused", st.mode)
    H.match(st.reason, "unprivileged_userns_clone", true)
    H.match(st.hint, "sysctl", true)
  end)

  it("wrap() refuses with the same reason and starts nothing", function()
    fake_bwrap("echo 'bwrap: setting up uid map: Permission denied' >&2; exit 1")
    local got, reason = sb.wrap({ "agent" }, H.tmpdir(), H.tmpdir())
    H.eq(nil, got)
    H.match(reason, "uid map", true)
    H.match(reason, "seccomp", true)
  end)

  it("allow_unsandboxed turns a failed probe into an explicit unsandboxed run, sandbox untouched otherwise", function()
    fake_bwrap("exit 1")
    sb.config.allow_unsandboxed = true
    local st = sb.status_blocking()
    H.eq("unsandboxed", st.mode)
    H.eq("allow_unsandboxed", st.via)
  end)

  it("a hanging bwrap is killed after the timeout and counts as failed", function()
    fake_bwrap("exec sleep 30")
    local old = probe.timeout
    probe.timeout = 300
    local t0 = vim.uv.hrtime()
    local st = sb.status_blocking()
    probe.timeout = old
    H.eq("refused", st.mode)
    H.match(st.reason, "did not finish", true)
    H.ok((vim.uv.hrtime() - t0) / 1e9 < 5, "returned quickly")
  end)
end)

describe("async and cached", function()
  it("status() does not block: pending first, then the verdict, and the second call is cached", function()
    fake_bwrap("sleep 0.3; exit 0")
    local t0 = vim.uv.hrtime()
    local st = sb.status()
    H.ok((vim.uv.hrtime() - t0) / 1e9 < 0.25, "status() returned before the probe finished")
    H.eq("bwrap", st.mode)
    H.eq("pending", st.ready)
    H.eq("sandbox: checking", sb.statusline())
    H.ok(
      vim.wait(5000, function()
        return probe.cached() ~= nil
      end, 20),
      "probe finished"
    )
    H.eq("ok", sb.status().ready)
    -- cached: remove the fake, the verdict stays
    local t1 = vim.uv.hrtime()
    H.eq("ok", sb.status().ready)
    H.ok((vim.uv.hrtime() - t1) / 1e9 < 0.1)
  end)

  it("check() reports through the callback and joins a running probe", function()
    fake_bwrap("sleep 0.2; echo nope >&2; exit 1")
    local got = {}
    sb.check(function(st)
      got[#got + 1] = st
    end)
    sb.check(function(st)
      got[#got + 1] = st
    end)
    H.ok(vim.wait(5000, function()
      return #got == 2
    end, 20))
    H.eq("refused", got[1].mode)
    H.eq("refused", got[2].mode)
  end)

  it("a failed verdict expires quickly so a fixed sysctl is noticed", function()
    fake_bwrap("exit 1")
    sb.status_blocking()
    H.ok(probe.cached(), "cached")
    local old = probe.ttl_fail
    probe.ttl_fail = -1
    H.eq(nil, probe.cached())
    probe.ttl_fail = old
  end)

  it("works against the real bwrap when it can", function()
    if vim.fn.executable("bwrap") ~= 1 then
      return require("xynotest.harness").skip("bwrap not found")
    end
    local st = sb.status_blocking()
    H.ok(st.mode == "bwrap" or st.mode == "refused")
    if st.mode == "refused" then
      H.ok(st.reason ~= "")
    else
      H.eq("ok", st.ready)
    end
  end)
end)

describe("statusline", function()
  it("shows on / OFF / refused and never errors", function()
    fake_bwrap("exit 0")
    sb.status_blocking()
    H.eq("sandbox: on", sb.statusline())
    H.eq("DiagnosticOk", sb.statusline_hl())
    sb.config.sandbox = false
    H.eq("sandbox: OFF", sb.statusline())
    H.eq("DiagnosticWarn", sb.statusline_hl())
    sb.config.sandbox = true
    vim.env.PATH = "/nonexistent-xyno-path"
    H.eq("sandbox: refused", sb.statusline())
    H.eq("DiagnosticError", sb.statusline_hl())
  end)

  it("counts running sandboxes and works as a lualine component (a plain function)", function()
    fake_bwrap("exit 0")
    sb.status_blocking()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local _, _, h = sb.wrap({ "true" }, project, tmp)
    H.eq("sandbox: on x1", sb.statusline())
    H.eq("string", type(sb.statusline()))
    h.release()
    H.eq("sandbox: on", sb.statusline())
  end)
end)
