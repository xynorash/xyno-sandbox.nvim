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

local function run_all()
  local total = { passed = 0, failed = 0, skipped = 0 }
  local files = vim.fn.glob(repo .. "/tests/*_spec.lua", true, true)
  table.sort(files)
  for _, f in ipairs(files) do
    local r = vim.system({ vim.v.progpath, "--headless", "-l", repo .. "/tests/run.lua", f }, { text = true }):wait(600000)
    io.stdout:write(r.stdout or "")
    io.stderr:write(r.stderr or "")
    for k in pairs(total) do
      total[k] = total[k] + tonumber((r.stdout or ""):match("RESULT .-" .. k .. "=(%d+)") or 0)
    end
    if r.code ~= 0 and not (r.stdout or ""):find("RESULT", 1, true) then
      total.failed = total.failed + 1
    end
  end
  io.stdout:write(("RESULT passed=%d failed=%d skipped=%d\n"):format(total.passed, total.failed, total.skipped))
  os.exit(total.failed > 0 and 1 or 0)
end

local spec = _G.arg and _G.arg[1]
if not spec then
  return run_all()
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
local counts
local ok, err = xpcall(dofile, debug.traceback, spec)
if not ok then
  if harness.is_skip(err) then
    io.stdout:write(("SKIP %s (%s)\n"):format(vim.fs.basename(spec), err.reason))
    counts = { passed = 0, failed = 0, skipped = 1 }
  else
    io.stdout:write("FAIL loading " .. spec .. "\n" .. tostring(err) .. "\n")
    counts = { passed = 0, failed = 1, skipped = 0 }
  end
else
  counts = harness.run()
end
io.stdout:write(("RESULT passed=%d failed=%d skipped=%d\n"):format(counts.passed, counts.failed, counts.skipped))
io.stdout:flush()
pcall(function()
  require("xynotest.helpers").cleanup()
end)
os.exit(counts.failed > 0 and 1 or 0)
