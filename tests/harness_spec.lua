-- The test harness itself: xfail is explicit and visible, an unexpected pass fails.
local H = require("xynotest.helpers")

local function run_spec(body)
  local dir = H.tmpdir()
  local f = assert(io.open(dir .. "/x_spec.lua", "w"))
  f:write(body)
  f:close()
  local r = vim.system({ vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/x_spec.lua" }, { text = true }):wait(60000)
  return r.stdout or "", r.code
end

describe("xfail", function()
  it("a failing xfail is reported XFAIL with its reason, counted as xfailed, exit code 0", function()
    local out, code = run_spec([[
      xfail("limit", "documented limit", function() error("boom") end)
      it("fine", function() end)
    ]])
    H.match(out, "XFAIL limit", true)
    H.match(out, "known limit: documented limit | ", true)
    H.match(out, "RESULT passed=1 failed=0 skipped=0 xfailed=1", true)
    H.eq(0, code)
  end)

  it("a passing xfail FAILS as XPASS and tells to turn it into a normal test", function()
    local out, code = run_spec([[ xfail("fixed", "was a bug", function() end) ]])
    H.match(out, "FAIL fixed", true)
    H.match(out, "XPASS", true)
    H.match(out, "failed=1", true)
    H.eq(1, code)
  end)

  it("a skip inside an xfail stays a skip", function()
    local out = run_spec([[ xfail("s", "r", function() skip("no sandbox here") end) ]])
    H.match(out, "SKIP s (no sandbox here)", true)
    H.match(out, "skipped=1 xfailed=0", true)
  end)

  it("needs a reason", function()
    local out = run_spec([[ xfail("no reason", nil, function() end) ]])
    H.match(out, "xfail needs a reason", true)
  end)
end)

describe("no silent skips of known bugs", function()
  it("the known_bug helper is gone from the specs", function()
    for _, f in ipairs(vim.fn.glob(H.repo .. "/tests/*_spec.lua", true, true)) do
      if not f:find("harness_spec", 1, true) then
        local text = table.concat(vim.fn.readfile(f), "\n")
        H.no_match(text, "known_bug", true, f)
        H.no_match(text, "KNOWN BUG", true, f)
      end
    end
  end)
end)
