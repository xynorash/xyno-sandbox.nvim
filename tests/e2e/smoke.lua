-- End-to-end smoke test: lazy.nvim loads the plugin from this checkout through
-- `dir =`, setup() runs, and every documented command exists.
--   LAZY_PATH=<lazy.nvim checkout> nvim --headless -u tests/e2e/smoke.lua
-- Run it with a clean XDG environment so nothing from a personal config leaks.
local repo = vim.fs.dirname(vim.fs.dirname(vim.fs.dirname(vim.fn.fnamemodify(debug.getinfo(1, "S").source:sub(2), ":p"))))
if repo == "" or repo == "." then
  repo = vim.uv.cwd()
end
local lazy_path = assert(vim.env.LAZY_PATH, "LAZY_PATH is not set")
vim.opt.runtimepath:prepend(lazy_path)

local function fail(msg)
  io.stdout:write("FAIL " .. msg .. "\n")
  os.exit(1)
end

local errors = {}
local orig = vim.notify
vim.notify = function(msg, level)
  if level and level >= vim.log.levels.ERROR then
    errors[#errors + 1] = msg
  end
end

require("lazy").setup({
  { dir = repo, name = "xyno-sandbox.nvim", main = "xyno_sandbox", opts = {} },
}, { lockfile = vim.fn.stdpath("state") .. "/lazy-lock.json", install = { missing = false }, checker = { enabled = false } })

-- lazy.nvim loads `opts` plugins on startup (VimEnter in headless -l mode is not
-- fired, so load explicitly)
require("lazy").load({ plugins = { "xyno-sandbox.nvim" } })

for _, cmd in ipairs({ "XynoSandboxStatus", "XynoSandboxRun" }) do
  if vim.fn.exists(":" .. cmd) ~= 2 then
    fail("command missing: " .. cmd)
  end
end
local ok, sb = pcall(require, "xyno_sandbox")
if not ok then
  fail("require xyno_sandbox: " .. tostring(sb))
end
for _, fn in ipairs({ "setup", "status", "wrap", "run", "scrub_names", "readonly_paths" }) do
  if type(sb[fn]) ~= "function" then
    fail("missing function: " .. fn)
  end
end
local st = sb.status()
if not vim.tbl_contains({ "bwrap", "refused", "unsandboxed" }, st.mode) then
  fail("odd status mode: " .. tostring(st.mode))
end
local seen = {}
vim.notify = function(msg)
  seen[#seen + 1] = msg
end
vim.cmd("XynoSandboxStatus")
if not (seen[1] and seen[1]:find("xyno-sandbox:", 1, true)) then
  fail("XynoSandboxStatus printed nothing")
end
if #errors > 0 then
  fail("errors during load: " .. table.concat(errors, "; "))
end
io.stdout:write("OK smoke: status=" .. st.mode .. "\n")
os.exit(0)
