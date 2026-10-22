-- Commands, keymaps and the terminal launcher of xyno-sandbox.
local M = {}

local function notify(msg, level)
  vim.notify("xyno-sandbox: " .. msg, level or vim.log.levels.INFO)
end

--- One-line description of how an agent would run here.
function M.describe()
  local st = require("xyno_sandbox").status()
  if st.mode == "bwrap" then
    return "sandboxed (bubblewrap)"
  elseif st.mode == "unsandboxed" then
    return "UNSANDBOXED (" .. st.via .. "): " .. st.reason
  end
  return "refused: " .. st.reason
end

--- Start `cmd` (string[]) inside the sandbox in a terminal split. Refuses with
--- a one-line error notification when no sandbox is available and no explicit
--- opt-out is set; warns on every explicitly unsandboxed run.
--- @param cmd string[]
--- @param opts? { project?: string, tmp_dir?: string }
--- @return integer? job id
function M.run(cmd, opts)
  opts = opts or {}
  if type(cmd) ~= "table" or #cmd == 0 then
    notify("no command given", vim.log.levels.ERROR)
    return nil
  end
  local sandbox = require("xyno_sandbox")
  local project = opts.project or vim.uv.cwd()
  local tmp_dir = opts.tmp_dir or (vim.fn.stdpath("cache") .. "/xyno-sandbox")
  vim.fn.mkdir(tmp_dir, "p")
  local wrapped, err = sandbox.wrap(cmd, project, tmp_dir)
  if not wrapped then
    local hint = ". Set allow_unsandboxed = true in setup() to run it anyway."
    notify("refused to start " .. cmd[1] .. ": " .. tostring(err) .. hint, vim.log.levels.ERROR)
    return nil
  end
  if sandbox.status().mode == "unsandboxed" then
    notify("running " .. cmd[1] .. " WITHOUT a sandbox (" .. sandbox.status().reason .. ")", vim.log.levels.WARN)
  end
  vim.cmd("botright new")
  local job = vim.fn.jobstart(wrapped, { term = true })
  if job <= 0 then
    notify("could not start " .. cmd[1], vim.log.levels.ERROR)
    return nil
  end
  return job
end

function M.register(cfg)
  if cfg.commands then
    vim.api.nvim_create_user_command("XynoSandboxStatus", function()
      notify(M.describe())
    end, { desc = "Show how an agent would run (bubblewrap, unsandboxed or refused)" })
    vim.api.nvim_create_user_command("XynoSandboxRun", function(c)
      M.run(c.fargs)
    end, { nargs = "+", complete = "shellcmd", desc = "Run a command inside the bubblewrap sandbox" })
  end
  if type(cfg.keymaps) == "table" and cfg.keymaps.status then
    vim.keymap.set("n", cfg.keymaps.status, function()
      notify(M.describe())
    end, { desc = "Sandbox status" })
  end
end

return M
