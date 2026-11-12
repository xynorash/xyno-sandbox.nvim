-- Eighth round, the runner: a killed runner takes its spec child (and what that started) with it.
local H = require("xynotest.helpers")
local uv = vim.uv

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text or "x\n")
  f:close()
end

-- ------------------------------------------------------------------ (7) the runner
describe("tests/run.lua when the runner itself is killed (kill -9)", function()
  it("the spec child and what it started do not outlive it", function()
    local dir = H.tmpdir()
    local flag = dir .. "/started"
    write(
      dir .. "/hang_spec.lua",
      ([[
      it("starts a child and waits", function()
        vim.system({ "sh", "-c", "sleep 1203; :", "r8-leak-marker" })
        local f = io.open(%q, "w") f:write("1") f:close()
        vim.wait(90000)
      end)
    ]]):format(flag)
    )
    local obj = vim.system(
      { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/hang_spec.lua" },
      { text = true, env = { XYNO_TEST_WORKER = "0" } }
    )
    local started = vim.wait(30000, function()
      return uv.fs_stat(flag) ~= nil
    end, 50)
    uv.kill(obj.pid, 9)
    local nvim_left = {}
    local gone = vim.wait(15000, function()
      return #H.procs("r8-leak-marker") == 0 and #H.procs("sleep 1203") == 0
    end, 100)
    local left = {}
    for _, p in ipairs(H.procs("r8-leak-marker")) do
      left[#left + 1] = p
    end
    for _, p in ipairs(H.procs("sleep 1203")) do
      left[#left + 1] = p
    end
    for _, p in ipairs(left) do
      uv.kill(p[1], 9)
    end
    for _, p in ipairs(H.procs(dir .. "/hang_spec.lua")) do
      nvim_left[#nvim_left + 1] = p
      uv.kill(p[1], 9)
    end
    -- the killed runner cannot remove its own scratch directory and root: they carry its pid, so remove them here
    -- (otherwise every complete suite run leaves one /tmp/xyno-run-* directory until the NEXT run reaps it)
    local reaper = dofile(H.repo .. "/tests/reaper.lua")
    H.ok(reaper.remove_owned_by(obj.pid, reaper.bases(H.repo)) >= 1, "its scratch directory was found and removed")
    H.ok(started, "the spec started")
    H.ok(gone, "left behind: " .. vim.inspect(left))
    H.eq({}, nvim_left, "the spec's nvim is gone")
  end)
end)
