-- The runner gives every spec file a private fake $HOME (outside /tmp, with fake agent
-- credentials), so the suite does not depend on the real user's files, and it copes with a machine
-- on which bubblewrap cannot work (CI containers).
local H = require("xynotest.helpers")

local function nested(body, env)
  local dir = H.tmpdir()
  local f = assert(io.open(dir .. "/inner_spec.lua", "w"))
  f:write(body)
  f:close()
  local e = vim.tbl_extend("force", { XYNO_TEST_WORKER = "0" }, env or {})
  local r = vim
    .system(
      { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/inner_spec.lua" },
      { text = true, env = e }
    )
    :wait(120000)
  return r.stdout or "", r.code, dir
end

describe("the spec environment", function()
  it("$HOME is a private directory outside /tmp that holds fake credentials", function()
    local home = vim.uv.os_homedir()
    local root = vim.env.XYNO_TEST_ROOT
    H.ok(root and root ~= "", "not started through tests/run.lua")
    H.eq(root .. "/home", home)
    H.not_ok(home:match("^/tmp/") or home:match("^/var/tmp/"), "a $HOME under /tmp does not exist inside the sandbox")
    H.match(table.concat(vim.fn.readfile(home .. "/.claude/.credentials.json"), "\n"), "FAKE", true)
    H.eq(home, vim.fn.expand("~"))
  end)

  it("the nested run's root and scratch directory are removed when it ends", function()
    local report = H.tmpdir() .. "/report"
    local out, code = nested(
      [[
      it("reports where it ran", function()
        vim.fn.writefile({ vim.env.XYNO_TEST_ROOT, vim.env.XYNO_TEST_SCRATCH, vim.uv.os_homedir() }, vim.env.XYNO_TEST_REPORT)
        assert(vim.uv.fs_stat(vim.uv.os_homedir() .. "/.claude/.credentials.json"))
      end)
    ]],
      { XYNO_TEST_REPORT = report }
    )
    H.eq(0, code, out)
    local paths = vim.fn.readfile(report)
    H.eq(3, #paths)
    H.not_ok(paths[1] == vim.env.XYNO_TEST_ROOT, "the inner run used its own root")
    H.eq(nil, vim.uv.fs_stat(paths[1]), "root removed")
    H.eq(nil, vim.uv.fs_stat(paths[2]), "scratch removed")
  end)
end)

describe("a machine without a working bubblewrap", function()
  it("keeps the plan specs running and skips the ones that need a sandbox (exit 0)", function()
    local bin = H.tmpdir()
    local f = assert(io.open(bin .. "/bwrap", "w"))
    f:write("#!/bin/sh\necho 'bwrap: No permissions to create new namespace' >&2\nexit 1\n")
    f:close()
    vim.uv.fs_chmod(bin .. "/bwrap", tonumber("755", 8))
    local out, code = nested(
      [[
      local H = require("xynotest.helpers")
      it("still builds a plan", function()
        local sb = require("xyno_sandbox")
        local project = H.tmpdir()
        local cmd, err = sb.wrap({ "true" }, project, H.tmpdir())
        assert(cmd, tostring(err))
        assert(table.concat(cmd, " "):find("--die-with-parent", 1, true))
      end)
      it("skips what needs a real sandbox", function()
        H.need_sandbox()
        error("must have been skipped")
      end)
    ]],
      { PATH = bin .. ":" .. vim.env.PATH }
    )
    H.eq(0, code, out)
    H.match(out, "no working bubblewrap", true)
    H.match(out, "skipped=1", true, out)
  end)
end)
