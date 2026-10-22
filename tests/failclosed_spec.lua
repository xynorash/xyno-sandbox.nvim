-- The wrapper fails closed on every platform. No OS gate: where there is no
-- backend (Windows, macOS, or Linux without bwrap) wrap() must refuse. The
-- "no backend" case is forced everywhere by emptying PATH, so it runs on
-- Linux too.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")

local saved = vim.deepcopy(sb.config)
local old_path = vim.env.PATH
after_each(function()
  sb.config = vim.deepcopy(saved)
  vim.env.PATH = old_path
end)

local function no_backend()
  vim.env.PATH = "/nonexistent-xyno-path"
end

describe("without a backend", function()
  it("loads and answers on this platform (" .. H.os .. ")", function()
    H.eq("function", type(sb.status))
    H.eq("function", type(sb.wrap))
  end)

  it("status() is refused when bwrap cannot be found", function()
    no_backend()
    H.eq("refused", sb.status().mode)
  end)

  it("wrap() returns nil plus a reason", function()
    no_backend()
    local got, reason = sb.wrap({ "agent" }, vim.uv.cwd(), vim.uv.cwd())
    H.eq(nil, got)
    H.ok(type(reason) == "string" and reason ~= "", "a reason comes with the refusal")
  end)

  it("only the two explicit booleans lead to an unsandboxed run", function()
    no_backend()
    local cmd = { "agent" }
    for _, v in ipairs({ 0, 1, "false", "true" }) do
      sb.config.sandbox = v
      sb.config.allow_unsandboxed = v
      H.eq("refused", sb.status().mode, vim.inspect(v))
    end
    sb.config.sandbox = false
    sb.config.allow_unsandboxed = false
    H.ok(sb.wrap(cmd, vim.uv.cwd(), vim.uv.cwd()) == cmd, "sandbox = false returns the command")
    H.eq("unsandboxed", sb.status().mode)
    sb.config.sandbox = true
    sb.config.allow_unsandboxed = true
    H.ok(sb.wrap(cmd, vim.uv.cwd(), vim.uv.cwd()) == cmd, "allow_unsandboxed returns the command")
    H.eq("allow_unsandboxed", sb.status().via)
  end)
end)
