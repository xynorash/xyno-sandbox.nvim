-- Sixth hardening round: one describe per finding (H1 launch path, F1 planted names in
-- subdirectories, F2 project files that run outside the sandbox, F3 content scan by signature, F4
-- survivors, F5 the claude.json copy).
local H = require("xynotest.helpers")
local harness = require("xynotest.harness")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local probe = require("xyno_sandbox.probe")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
local old_path = vim.env.PATH
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
  vim.env.PATH = old_path
  probe.reset()
end)

-- ------------------------------------------------------------------ H1
describe("H1: the bwrap that is checked is the bwrap that is launched", function()
  local function stub_dir()
    local bin = H.tmpdir() .. "/odd bin dir"
    vim.fn.mkdir(bin, "p")
    local f = assert(io.open(bin .. "/bwrap", "w"))
    f:write('#!/bin/sh\necho "STUB-BWRAP-RAN $0"\nexit 0\n')
    f:close()
    vim.uv.fs_chmod(bin .. "/bwrap", tonumber("755", 8))
    return bin
  end

  it("the readiness probe runs the absolute path found on PATH", function()
    local bin = stub_dir()
    vim.env.PATH = bin .. ":" .. old_path
    probe.reset()
    H.eq(bin .. "/bwrap", probe.bwrap_path())
    H.eq(bin .. "/bwrap", plan.probe_argv(false, probe.bwrap_path())[1])
  end)

  it("argv starts env with the absolute bwrap path, and the command runs with PATH unset", function()
    local bin = stub_dir()
    vim.env.PATH = bin .. ":" .. old_path
    probe.reset()
    local st = sb.status_blocking()
    H.eq("bwrap", st.mode)
    local project, tmp = H.tmpdir(), H.tmpdir()
    local p = assert(sb.plan({ "true" }, project, tmp))
    local argv = sb.argv(p)
    H.eq("/env", argv[1]:match("/env$"), "env is absolute too")
    H.eq(bin .. "/bwrap", vim.tbl_filter(function(a)
      return a:match("/bwrap$")
    end, argv)[1])
    H.not_ok(vim.tbl_contains(argv, "bwrap"), "no bare bwrap name left in the command line")
    local r = vim.system(argv, { clear_env = true, text = true }):wait(10000)
    H.match(r.stdout, "STUB-BWRAP-RAN", true, "with PATH unset the stub was found: " .. vim.inspect(r))
    H.eq(0, r.code)
  end)

  it("a plan built without a resolved path keeps the plain name (pure builder)", function()
    H.eq("bwrap", plan.probe_argv(false)[1])
  end)
end)
