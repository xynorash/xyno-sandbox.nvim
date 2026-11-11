-- Commands, keymaps, the launch confirm and the terminal launcher of xyno-sandbox.
local store = require("xyno_sandbox.store")
local M = {}

local function notify(msg, level)
  vim.notify("xyno-sandbox: " .. msg, level or vim.log.levels.INFO)
end

--- Is a UI attached? The preview is interactive, so a headless nvim never waits for it.
--- (Replaceable in specs.)
function M.has_ui()
  return #vim.api.nvim_list_uis() > 0
end

--- One-line description of how an agent would run here (with the fix hint when it is refused).
--- @param st? table a status() result
function M.describe(st)
  st = st or require("xyno_sandbox").status()
  local hint = st.hint and (" -> " .. st.hint) or ""
  if st.mode == "bwrap" then
    return st.ready == "pending" and "sandboxed (bubblewrap; readiness check running)" or "sandboxed (bubblewrap, user namespaces work)"
  elseif st.mode == "unsandboxed" then
    return "UNSANDBOXED (" .. st.via .. "): " .. st.reason .. hint
  end
  return "refused: " .. st.reason .. hint
end

--- Should the preview be shown before this launch?
function M.should_confirm(project)
  local mode = require("xyno_sandbox").config.preview
  if mode == "never" or not M.has_ui() then
    return false
  end
  return mode == "always" or not store.seen(project)
end

--- The launch-time preview. `cb(ok, plan_or_reason, once)`: ok is false when the operator cancelled
--- or nothing may start; otherwise plan is the plan that was shown (pass it to wrap as
--- opts.plan). Without a UI, with preview = "never", or when this project was shown already
--- (preview = "once") the plan comes back without a window.
--- @param cmd string[]
--- @param project string
--- @param tmp_dir string
--- @param cb fun(ok: boolean, plan: table|string|nil, once: table[]|nil)
function M.confirm(cmd, project, tmp_dir, cb)
  local sandbox = require("xyno_sandbox")
  M.last_cmd = { cmd[1] }
  for _, a in ipairs(cmd) do
    if require("xyno_sandbox.plan").skip_flag({ a }) then
      M.last_cmd[#M.last_cmd + 1] = a
    end
  end
  local st = sandbox.status()
  if st.mode == "refused" then
    return cb(false, st.reason .. (st.hint and (" (" .. st.hint .. ")") or ""))
  end
  if not M.should_confirm(project) then
    return cb(true, sandbox.plan(cmd, project, tmp_dir), {})
  end
  require("xyno_sandbox.ui").show({
    project = project,
    confirm = true,
    status = sandbox.status,
    build = function(once)
      return sandbox.plan(cmd, project, tmp_dir, { exceptions = once })
    end,
    on_done = function(go, plan, once)
      if go then
        store.mark_seen(project)
        cb(true, plan, once)
      else
        cb(false, "cancelled")
      end
    end,
  })
end

local function close_new_split(win, buf)
  if win and vim.api.nvim_win_is_valid(win) and #vim.api.nvim_list_wins() > 1 then
    pcall(vim.api.nvim_win_close, win, true)
  end
  if buf and vim.api.nvim_buf_is_valid(buf) then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end
end

local function launch(cmd, project, tmp_dir, plan, opts)
  local sandbox = require("xyno_sandbox")
  local wrapped, err, handle = sandbox.wrap(cmd, project, tmp_dir, { plan = plan })
  if not wrapped then
    local hint = ". Set allow_unsandboxed = true in setup() to run it anyway."
    notify("refused to start " .. cmd[1] .. ": " .. tostring(err) .. hint, vim.log.levels.ERROR)
    return nil
  end
  local function release()
    if handle then
      handle.release()
    end
  end
  if sandbox.status().mode == "unsandboxed" then
    notify("running " .. cmd[1] .. " WITHOUT a sandbox (" .. sandbox.status().reason .. ")", vim.log.levels.WARN)
  end
  -- never leave an empty split behind: the program must exist before the window opens
  if vim.fn.executable(wrapped[1]) ~= 1 then
    notify("could not start " .. cmd[1] .. ": " .. wrapped[1] .. " is not executable", vim.log.levels.ERROR)
    release()
    return nil
  end
  local prev_win = vim.api.nvim_get_current_win()
  vim.cmd("botright new")
  local win, buf = vim.api.nvim_get_current_win(), vim.api.nvim_get_current_buf()
  local ok, job = pcall(vim.fn.jobstart, wrapped, {
    term = true,
    on_exit = function(_, code)
      release()
      if opts.on_exit then
        opts.on_exit(code)
      end
    end,
  })
  if not ok or job <= 0 then
    notify("could not start " .. cmd[1] .. (ok and "" or (": " .. tostring(job))), vim.log.levels.ERROR)
    close_new_split(win, buf)
    if vim.api.nvim_win_is_valid(prev_win) then
      pcall(vim.api.nvim_set_current_win, prev_win)
    end
    release()
    return nil
  end
  if opts.on_start then
    opts.on_start(job)
  end
  return job
end

--- Start `cmd` (string[]) inside the sandbox in a terminal split. Refuses with a one-line error
--- notification when no sandbox is available and no explicit opt-out is set; warns on every
--- explicitly unsandboxed run. The policy preview comes first when the `preview` setting asks
--- for it and a UI is attached: then the job starts after the operator confirmed, and run()
--- returns nil (use opts.on_start to get the job id).
--- @param cmd string[]
--- @param opts? { project?: string, tmp_dir?: string, on_start?: fun(job: integer), on_exit?: fun(code: integer) }
--- @return integer? job id (nil when nothing was started yet or at all)
function M.run(cmd, opts)
  opts = opts or {}
  if type(cmd) ~= "table" or #cmd == 0 then
    notify("no command given", vim.log.levels.ERROR)
    return nil
  end
  local project = opts.project or vim.uv.cwd()
  local tmp_dir = opts.tmp_dir or (vim.fn.stdpath("cache") .. "/xyno-sandbox")
  vim.fn.mkdir(tmp_dir, "p")
  local sandbox = require("xyno_sandbox")
  if sandbox.status().mode == "unsandboxed" or not M.should_confirm(project) then
    return launch(cmd, project, tmp_dir, nil, opts)
  end
  M.confirm(cmd, project, tmp_dir, function(ok, plan)
    if ok then
      launch(cmd, project, tmp_dir, plan, opts)
    elseif plan ~= "cancelled" then
      notify("refused to start " .. cmd[1] .. ": " .. tostring(plan), vim.log.levels.ERROR)
    else
      notify("cancelled, nothing was started")
    end
  end)
  return nil
end

local function project_arg(c)
  return c.fargs[1] and vim.fn.fnamemodify(c.fargs[1], ":p"):gsub("/$", "") or (vim.fs.root(0, ".git") or vim.uv.cwd())
end

function M.register(cfg)
  local sandbox = require("xyno_sandbox")
  if cfg.commands then
    vim.api.nvim_create_user_command("XynoSandboxStatus", function(c)
      if c.bang then
        sandbox.check(function(st)
          notify(M.describe(st))
        end, true)
      else
        notify(M.describe(sandbox.status_blocking()))
      end
    end, { bang = true, desc = "Show how an agent would run (bubblewrap, unsandboxed or refused); ! re-checks" })

    vim.api.nvim_create_user_command("XynoSandboxPolicy", function(c)
      local project = project_arg(c)
      local cmd = cfg.agent_cmd or M.last_cmd or { "agent" }
      local tmp_dir = vim.fn.stdpath("cache") .. "/xyno-sandbox"
      sandbox.status_blocking()
      require("xyno_sandbox.ui").show({
        project = project, full = c.bang, status = sandbox.status,
        build = function(once)
          return sandbox.plan(cmd, project, tmp_dir, { exceptions = once })
        end,
        on_done = function(_, plan)
          if not plan then
            notify("refused: " .. sandbox.status().reason, vim.log.levels.ERROR)
          end
        end,
      })
    end, { bang = true, nargs = "?", complete = "dir",
      desc = "Show the sandbox policy for a project (writable, read-only, hidden, stripped env names); ! lists everything" })

    vim.api.nvim_create_user_command("XynoSandboxApprovals", function(c)
      local sub = c.fargs[1]
      local ex = require("xyno_sandbox.exceptions")
      if sub == "revoke" then
        local id = tonumber(c.fargs[2])
        local done = false
        for project, list in pairs(ex.list()) do
          for _, a in ipairs(list) do
            if a.id == id and not done then
              done = ex.revoke(project, id)
            end
          end
        end
        notify(done and ("revoked approval " .. id) or ("no approval with id " .. tostring(c.fargs[2])),
          done and vim.log.levels.INFO or vim.log.levels.WARN)
      elseif sub == "log" then
        vim.cmd("edit " .. vim.fn.fnameescape(store.log_path()))
        vim.bo.readonly = true
      else
        require("xyno_sandbox.ui").approvals()
      end
    end, { nargs = "*", complete = function() return { "revoke", "log" } end,
      desc = "List remembered sandbox exceptions (x revokes); `revoke {id}`; `log` opens the decision log" })

    vim.api.nvim_create_user_command("XynoSandboxRun", function(c)
      M.run(c.fargs)
    end, { nargs = "+", complete = "shellcmd", desc = "Run a command inside the bubblewrap sandbox" })
  end
  if type(cfg.keymaps) == "table" then
    if cfg.keymaps.status then
      vim.keymap.set("n", cfg.keymaps.status, function()
        notify(M.describe(sandbox.status_blocking()))
      end, { desc = "Sandbox status" })
    end
    if cfg.keymaps.policy then
      vim.keymap.set("n", cfg.keymaps.policy, "<Cmd>XynoSandboxPolicy<CR>", { desc = "Sandbox policy" })
    end
  end
end

return M
