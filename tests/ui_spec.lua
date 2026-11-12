-- The policy preview text, the launch-time confirm (always / once / never), exceptions from the
-- preview, and the launcher (no empty split, placeholder cleanup).
local H = require("xynotest.helpers")
local harness = require("xynotest.harness")
local sb = require("xyno_sandbox")
local run = require("xyno_sandbox.run")
local ui = require("xyno_sandbox.ui")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
local old_has_ui, old_select, old_input, old_show = run.has_ui, vim.ui.select, vim.ui.input, ui.show
local project, tmp

before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
  project, tmp = H.tmpdir(), H.tmpdir()
  vim.uv.os_setenv("XS_TEST_API_KEY", "TOPSECRETVALUE")
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
  run.has_ui, vim.ui.select, vim.ui.input, ui.show = old_has_ui, old_select, old_input, old_show
  vim.uv.os_unsetenv("XS_TEST_API_KEY")
  pcall(vim.api.nvim_del_user_command, "XynoSandboxPolicy")
  pcall(vim.api.nvim_del_user_command, "XynoSandboxApprovals")
  pcall(vim.api.nvim_del_user_command, "XynoSandboxStatus")
  pcall(vim.api.nvim_del_user_command, "XynoSandboxRun")
end)

local function need_bwrap()
  if sb.status_blocking().mode ~= "bwrap" then
    harness.skip("needs a working bwrap")
  end
end

local CMD = { "agent", "--dangerously-skip-permissions", "-p", "my private prompt" }

describe("preview text", function()
  it("shows writable, read-only, hidden, stripped NAMES, locked git, network and the permission line", function()
    need_bwrap()
    local p = sb.plan(CMD, project, tmp)
    local text = table.concat(ui.lines(p), "\n")
    H.match(text, "Writable (", true)
    H.match(text, project, true)
    H.match(text, "Read-only", true)
    H.match(text, "Hidden credential paths", true)
    H.match(text, "Stripped environment variables (names only, values are never shown)", true)
    H.match(text, "XS_TEST_API_KEY", true)
    H.match(text, "git directories locked", true)
    H.match(text, "network   FILTERED", true)
    H.match(text, "api.anthropic.com  [default]", true)
    H.match(text, "Agent permission prompts: OFF (--dangerously-skip-permissions)", true)
  end)

  it("never shows a value or the arguments of the command (the prompt)", function()
    need_bwrap()
    local text = table.concat(ui.lines(sb.plan(CMD, project, tmp), { full = true }), "\n")
    H.no_match(text, "TOPSECRETVALUE", true)
    H.no_match(text, "my private prompt", true)
    H.match(text, "agent (3 arguments not shown)", true)
  end)

  it("strip_skip_permissions changes the line and the command", function()
    need_bwrap()
    sb.config.strip_skip_permissions = true
    local p = sb.plan(CMD, project, tmp)
    local text = table.concat(ui.lines(p), "\n")
    H.match(text, "Agent permission prompts: ON", true)
    H.not_ok(vim.tbl_contains(sb.argv(p), "--dangerously-skip-permissions"))
  end)

  it("an unsandboxed plan says so loudly and still shows the permission line", function()
    sb.config.sandbox = false
    local text = table.concat(ui.lines(sb.plan(CMD, project, tmp)), "\n")
    H.match(text, "UNSANDBOXED", true)
    H.match(text, "Agent permission prompts: OFF", true)
  end)

  it("caps long lists and ':XynoSandboxPolicy!' (full) lists everything", function()
    local p = { mode = "bwrap", project = project, home = "/h", agent = { cmd = { "a" } }, network = "open", writable = {},
      git_locked = {}, readonly = {}, masks = {}, guard_files = {}, hidden = {}, exceptions = {}, rejected = {}, notes = {},
      env_kept = {}, env_strip = {} }
    for i = 1, 40 do
      p.env_strip[i] = "VAR_" .. i
    end
    local short = table.concat(ui.lines(p), "\n")
    H.match(short, "and 15 more", true)
    H.no_match(short, "VAR_40", true)
    H.match(table.concat(ui.lines(p, { full = true }), "\n"), "VAR_40", true)
  end)
end)

describe("the preview equals what runs", function()
  it("the argv of the shown plan is the wrapped command (same plan, same list)", function()
    need_bwrap()
    local p = sb.plan(CMD, project, tmp)
    local wrapped, _, h = sb.wrap(CMD, project, tmp, { plan = p })
    H.eq(sb.argv(p), wrapped)
    h.release()
  end)

  it("a plan whose guarded files appeared meanwhile is rebuilt, not run stale", function()
    need_bwrap()
    local p = sb.plan(CMD, project, tmp)
    H.has(vim.tbl_map(function(g) return g.path end, p.guard_files), project .. "/.envrc")
    vim.fn.writefile({ "export X=1" }, project .. "/.envrc")
    local wrapped, _, h = sb.wrap(CMD, project, tmp, { plan = p })
    local joined = table.concat(wrapped, "\0")
    H.no_match(joined, "--ro-bind\0" .. p.empty_file .. "\0" .. project .. "/.envrc", true)
    h.release()
  end)
end)

describe("launch-time confirm", function()
  local function stub_ui()
    local shown = {}
    ui.show = function(opts)
      shown[#shown + 1] = opts
      local plan = opts.build({})
      opts.on_done(opts._answer ~= false, plan, {})
    end
    return shown
  end

  it("preview = 'never' shows nothing and still hands back the plan", function()
    need_bwrap()
    run.has_ui = function() return true end
    sb.config.preview = "never"
    local shown = stub_ui()
    local ok, p
    sb.confirm(CMD, project, tmp, function(a, b) ok, p = a, b end)
    H.eq(true, ok)
    H.eq(0, #shown)
    H.eq("bwrap", p.mode)
  end)

  it("preview = 'always' shows before every launch", function()
    need_bwrap()
    run.has_ui = function() return true end
    sb.config.preview = "always"
    local shown = stub_ui()
    for _ = 1, 3 do
      sb.confirm(CMD, project, tmp, function() end)
    end
    H.eq(3, #shown)
  end)

  it("preview = 'once' shows the first launch of a project only, and remembers it", function()
    need_bwrap()
    run.has_ui = function() return true end
    sb.config.preview = "once"
    local shown = stub_ui()
    sb.confirm(CMD, project, tmp, function() end)
    sb.confirm(CMD, project, tmp, function() end)
    H.eq(1, #shown)
    sb.confirm(CMD, H.tmpdir(), tmp, function() end)
    H.eq(2, #shown, "another project is shown again")
  end)

  it("cancelling starts nothing and is not remembered as seen", function()
    need_bwrap()
    run.has_ui = function() return true end
    sb.config.preview = "once"
    ui.show = function(opts)
      opts.on_done(false, nil, {})
    end
    local ok, why
    sb.confirm(CMD, project, tmp, function(a, b) ok, why = a, b end)
    H.eq(false, ok)
    H.eq("cancelled", why)
    H.not_ok(store.seen(project))
  end)

  it("without a UI (headless) there is no window, whatever the setting", function()
    need_bwrap()
    run.has_ui = function() return false end
    sb.config.preview = "always"
    local shown = stub_ui()
    local ok
    sb.confirm(CMD, project, tmp, function(a) ok = a end)
    H.eq(true, ok)
    H.eq(0, #shown)
  end)

  it("a refused backend is reported to the callback, no window", function()
    run.has_ui = function() return true end
    local old = vim.env.PATH
    vim.env.PATH = "/nonexistent-xyno-path"
    local shown = stub_ui()
    local ok, why
    sb.confirm(CMD, project, tmp, function(a, b) ok, why = a, b end)
    vim.env.PATH = old
    H.eq(false, ok)
    H.match(why, "bwrap", true)
    H.eq(0, #shown)
  end)
end)

describe("real preview window", function()
  it("opens a float with the text; q closes it; <CR> launches in confirm mode", function()
    need_bwrap()
    local result
    local buf = ui.show({
      project = project, confirm = true, status = sb.status,
      build = function(once) return sb.plan(CMD, project, tmp, { exceptions = once }) end,
      on_done = function(go) result = go end,
    })
    H.eq("xyno-sandbox", vim.bo[buf].filetype)
    H.eq(false, vim.bo[buf].modifiable)
    H.match(table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n"), "Stripped environment variables", true)
    vim.api.nvim_feedkeys(vim.keycode("<CR>"), "x", false)
    H.eq(true, result)
    local result2
    local buf2 = ui.show({
      project = project, confirm = true,
      build = function(once) return sb.plan(CMD, project, tmp, { exceptions = once }) end,
      on_done = function(go) result2 = go end,
    })
    vim.api.nvim_feedkeys("q", "x", false)
    H.eq(false, result2)
    H.not_ok(vim.api.nvim_buf_is_valid(buf2))
  end)

  it("'e' approves one env var for this launch from the preview: logged, plan updated; refusing changes nothing", function()
    need_bwrap()
    local answers = {}
    vim.ui.select = function(items, opts, cb)
      local want = table.remove(answers, 1)
      for i, it in ipairs(items) do
        local label = type(it) == "table" and it.label or it
        if label:find(want, 1, true) then
          return cb(it, i)
        end
      end
      error("no item " .. want)
    end
    local final
    local buf = ui.show({
      project = project, confirm = true,
      build = function(once) return sb.plan(CMD, project, tmp, { exceptions = once }) end,
      on_done = function(go, plan, once) final = { go = go, plan = plan, once = once } end,
    })
    local function lines() return table.concat(vim.api.nvim_buf_get_lines(buf, 0, -1, false), "\n") end
    -- refuse first
    answers = { "XS_TEST_API_KEY through", "Refuse" }
    vim.api.nvim_feedkeys("e", "x", false)
    H.match(lines(), "XS_TEST_API_KEY", true)
    H.no_match(lines(), "Approved exceptions (1)", true)
    -- then approve once
    answers = { "XS_TEST_API_KEY through", "launch only" }
    vim.api.nvim_feedkeys("e", "x", false)
    H.match(lines(), "Approved exceptions (1)", true)
    H.match(lines(), "env XS_TEST_API_KEY  [once]", true)
    vim.api.nvim_feedkeys(vim.keycode("<CR>"), "x", false)
    H.eq(true, final.go)
    H.has(final.plan.env_kept, "XS_TEST_API_KEY")
    H.not_ok(vim.tbl_contains(final.plan.env_strip, "XS_TEST_API_KEY"))
    local log = store.read_log()
    H.eq(2, #log)
    H.eq("refused", log[1].decision)
    H.eq("approved", log[2].decision)
    H.eq("XS_TEST_API_KEY", log[2].name)
    H.eq({}, sb.approvals(project), "once is not remembered")
    -- and the launched argv really keeps the variable
    local wrapped, _, h = sb.wrap(CMD, project, tmp, { plan = final.plan })
    H.not_ok(vim.tbl_contains(wrapped, "XS_TEST_API_KEY"))
    h.release()
  end)
end)

describe("commands", function()
  it(":XynoSandboxPolicy opens the preview for the current project, '!' lists everything", function()
    need_bwrap()
    sb.setup({ agent_cmd = { "agent", "--dangerously-skip-permissions" } })
    local seen
    ui.show = function(opts) seen = opts end
    vim.cmd("XynoSandboxPolicy")
    H.eq(false, seen.full or false)
    H.ok(seen.build({}).mode == "bwrap")
    vim.cmd("XynoSandboxPolicy!")
    H.eq(true, seen.full)
    vim.cmd("XynoSandboxPolicy " .. vim.fn.fnameescape(project))
    H.eq(project, seen.project)
  end)

  it(":XynoSandboxApprovals lists remembered approvals and 'revoke {id}' withdraws one", function()
    sb.setup({})
    sb.approve(project, "env", "A_TOKEN", "project")
    local id = sb.approvals(project)[1].id
    local lines, index = ui.approval_lines(sb.approvals(), "/nowhere")
    H.match(table.concat(lines, "\n"), "env A_TOKEN", true)
    H.eq({ project = project, id = id }, index[4])
    local got = H.capture_notify(function()
      vim.cmd("XynoSandboxApprovals revoke " .. id)
    end)
    H.match(got[1][1], "revoked approval", true)
    H.eq({}, sb.approvals(project))
    local got2 = H.capture_notify(function()
      vim.cmd("XynoSandboxApprovals revoke 999")
    end)
    H.eq(vim.log.levels.WARN, got2[1][2])
  end)

  it("the approvals window revokes the entry under the cursor with x", function()
    sb.setup({})
    sb.approve(project, "env", "A_TOKEN", "project")
    vim.cmd("XynoSandboxApprovals")
    local row
    for i, l in ipairs(vim.api.nvim_buf_get_lines(0, 0, -1, false)) do
      if l:find("A_TOKEN", 1, true) then
        row = i
      end
    end
    vim.api.nvim_win_set_cursor(0, { row, 0 })
    vim.api.nvim_feedkeys("x", "x", false)
    H.eq({}, sb.approvals(project))
    vim.api.nvim_feedkeys("q", "x", false)
  end)

  it(":XynoSandboxStatus mentions the hint when refused", function()
    sb.setup({})
    local old = vim.env.PATH
    vim.env.PATH = "/nonexistent-xyno-path"
    local got = H.capture_notify(function()
      vim.cmd("XynoSandboxStatus")
    end)
    vim.env.PATH = old
    H.match(got[1][1], "refused: bwrap not found", true)
  end)
end)

describe("run()", function()
  local function wins()
    return #vim.api.nvim_list_wins(), #vim.api.nvim_list_bufs()
  end

  it("leaves no empty split when the program cannot be started", function()
    sb.config.sandbox = false
    local w0, b0 = wins()
    local job
    local got = H.capture_notify(function()
      job = sb.run({ "/nonexistent/xyno-agent" }, { project = project, tmp_dir = tmp })
    end)
    H.eq(nil, job)
    local w1, b1 = wins()
    H.eq(w0, w1, "no split left behind")
    H.eq(b0, b1, "no buffer left behind")
    local errs = vim.tbl_filter(function(g) return g[2] == vim.log.levels.ERROR end, got)
    H.eq(1, #errs)
    H.match(errs[1][1], "could not start", true)
  end)

  it("with a sandbox: releases the private copy and the placeholders when the job ends", function()
    H.need_sandbox()
    sb.setup({ preview = "never" })
    local job = sb.run({ "bash", "-c", "echo hi > made.txt" }, { project = project, tmp_dir = tmp })
    H.ok(job and job > 0)
    H.eq(0, vim.fn.jobwait({ job }, 20000)[1])
    H.ok(vim.wait(2000, function() return sb.running() == 0 end, 20), "handle released")
    H.eq(1, vim.fn.filereadable(project .. "/made.txt"))
    for _, rel in ipairs({ ".envrc", ".vscode", ".cargo", ".mise.toml" }) do
      H.eq(nil, vim.uv.fs_stat(project .. "/" .. rel), rel .. " placeholder removed after the run")
    end
    vim.cmd("silent! bwipeout!")
  end)

  it("with a UI the job starts after the confirm and on_start gets the job id", function()
    H.need_sandbox()
    sb.setup({ preview = "always" })
    run.has_ui = function() return true end
    ui.show = function(opts)
      opts.on_done(true, opts.build({}), {})
    end
    local started
    local ret = sb.run({ "true" }, { project = project, tmp_dir = tmp, on_start = function(j) started = j end })
    H.eq(nil, ret)
    H.ok(started and started > 0, "on_start called")
    vim.fn.jobwait({ started }, 20000)
    vim.cmd("silent! bwipeout!")
  end)
end)

describe("stale confirmed plans", function()
  it("a rebuilt plan keeps the exceptions approved for this launch", function()
    need_bwrap()
    local p = sb.plan(CMD, project, tmp, { exceptions = { { kind = "env", value = "XS_TEST_API_KEY", scope = "once" } } })
    H.has(p.env_kept, "XS_TEST_API_KEY")
    vim.fn.writefile({ "x" }, project .. "/.envrc") -- the guard assumed it absent: the plan is stale
    local wrapped, _, h = sb.wrap(CMD, project, tmp, { plan = p })
    H.eq(wrapped, sb.argv(h.plan))
    H.has(h.plan.env_kept, "XS_TEST_API_KEY")
    h.release()
  end)
end)
