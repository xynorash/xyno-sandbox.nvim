-- Runs a command-line coding agent inside bubblewrap. The whole filesystem is
-- read-only except the project, a scratch dir, and the few paths the agent and
-- cargo must write.
-- Everything that would later run UNSANDBOXED (git hooks/config, agent
-- settings/hooks/plugins, direnv, editor task files, cargo config, the agent
-- binary) is read-only even inside the writable binds. Credential dirs/files
-- are hidden, credential env vars are stripped, pid/ipc/uts namespaces are
-- unshared, capabilities dropped, nested user namespaces disabled.
-- Network stays open (the model needs it).
--
-- Fails CLOSED. bubblewrap exists only on Linux, so without a working
-- backend (Windows, macOS, Linux without bwrap) wrap() refuses (nil, reason)
-- and the agent does not start. Two explicit booleans (0, "false", 1 do
-- not count) lead to an unsandboxed run:
--   setup({ sandbox = false })             deliberate OFF, even where bwrap works
--   setup({ allow_unsandboxed = true })    run anyway when NO backend exists
--                                          (never disables a working sandbox)
-- Linux+bwrap: sandboxed (only sandbox=false turns it off). No backend:
-- refused (sandbox=false or allow_unsandboxed=true: unsandboxed).
local plan_mod = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local probe = require("xyno_sandbox.probe")

local M = {}

--- Policy switches. `sandbox` and `allow_unsandboxed` are read at every status()/wrap() call;
--- only the booleans `false` / `true` count (0, "false", 1, "true" do not). Either may also be a
--- function returning the value, evaluated at every call.
M.config = {
  sandbox = true, -- false: deliberate opt-out, run unsandboxed even where bwrap works
  allow_unsandboxed = false, -- true: run unsandboxed when NO backend exists
  keymaps = false, -- false, or { status = "<lhs>", policy = "<lhs>" }
  commands = true,
  preview = "once", -- the policy preview before a launch: "always" | "once" (per project) | "never"
  strip_skip_permissions = false, -- true: remove --dangerously-skip-permissions from the command
  policy = {}, -- additive policy lists, see validate_opts()
  agent_cmd = nil, -- command shown by :XynoSandboxPolicy when nothing was launched yet
}

local home = vim.uv.os_homedir()
local pwd = vim.uv.os_get_passwd() -- uid is -1 or the call fails on Windows
local uid = pwd and pwd.uid or -1

-- ------------------------------------------------------------------ options

local POLICY_LISTS = { "readonly", "writable", "hidden", "guard_dirs", "guard_files" }
local PREVIEW = { always = true, once = true, never = true }

local function str_list(name, v, errs, check)
  if type(v) ~= "table" or vim.islist and not vim.islist(v) then
    errs[#errs + 1] = name .. " must be a list of strings"
    return
  end
  for i, e in ipairs(v) do
    if type(e) ~= "string" or e == "" then
      errs[#errs + 1] = ("%s[%d] must be a non-empty string"):format(name, i)
    elseif check then
      local why = check(e)
      if why then
        errs[#errs + 1] = ("%s[%d] %q: %s"):format(name, i, e, why)
      end
    end
  end
end

local function path_check(allow_relative, forbid_whole)
  return function(e)
    if e:find("..", 1, true) and (e:match("^%.%./") or e:match("/%.%./") or e:match("/%.%.$") or e == "..") then
      return "'..' is not allowed"
    end
    local abs = e:sub(1, 1) == "/" or e:sub(1, 2) == "~/"
    if not abs and not allow_relative then
      return "must be absolute or start with ~/"
    end
    if forbid_whole and (e == "/" or e == "~" or e == "~/" or plan_mod.normalize(e) == home) then
      return "would expose all of / or $HOME"
    end
  end
end

--- Check setup() options; returns a list of problems (empty when valid).
--- policy = {
---   readonly    = { "rel/or/abs", ... }  extra read-only locks (project-relative, absolute, or ~/)
---   writable    = { "/abs", "~/x" }      extra writable paths (never / or $HOME)
---   hidden      = { "/abs", "~/x" }      extra hidden paths (dir -> empty tmpfs, file -> empty)
---   guard_dirs  = { "rel" }              dirs masked read-only when absent
---   guard_files = { "rel" }              files bound read-only (empty) when absent
---   scrub       = { contains = {}, prefix = {}, exact = {} }  more env var names to strip
---   scan_depth  = 8                      how deep nested .git / members are looked for (1..32)
--- }
--- The lists only ADD to the built-in policy; nothing can be removed from it.
function M.validate_opts(opts)
  local errs = {}
  local known = { sandbox = true, allow_unsandboxed = true, keymaps = true, commands = true, preview = true,
    strip_skip_permissions = true, policy = true, agent_cmd = true }
  for k in pairs(opts) do
    if not known[k] then
      errs[#errs + 1] = "unknown option " .. tostring(k)
    end
  end
  if opts.commands ~= nil and type(opts.commands) ~= "boolean" then
    errs[#errs + 1] = "commands must be a boolean"
  end
  if opts.preview ~= nil and not PREVIEW[opts.preview] then
    errs[#errs + 1] = 'preview must be "always", "once" or "never"'
  end
  if opts.strip_skip_permissions ~= nil and type(opts.strip_skip_permissions) ~= "boolean" then
    errs[#errs + 1] = "strip_skip_permissions must be a boolean"
  end
  if opts.agent_cmd ~= nil then
    str_list("agent_cmd", opts.agent_cmd, errs)
  end
  if opts.keymaps ~= nil and opts.keymaps ~= false and type(opts.keymaps) ~= "table" then
    errs[#errs + 1] = "keymaps must be false or a table"
  end
  local p = opts.policy
  if p ~= nil then
    if type(p) ~= "table" then
      errs[#errs + 1] = "policy must be a table"
    else
      local pknown = { scrub = true, scan_depth = true }
      for _, k in ipairs(POLICY_LISTS) do
        pknown[k] = true
      end
      for k in pairs(p) do
        if not pknown[k] then
          errs[#errs + 1] = "unknown policy key " .. tostring(k)
        end
      end
      if p.readonly ~= nil then str_list("policy.readonly", p.readonly, errs, path_check(true, false)) end
      if p.writable ~= nil then str_list("policy.writable", p.writable, errs, path_check(false, true)) end
      if p.hidden ~= nil then str_list("policy.hidden", p.hidden, errs, path_check(false, true)) end
      if p.guard_dirs ~= nil then str_list("policy.guard_dirs", p.guard_dirs, errs, path_check(true, true)) end
      if p.guard_files ~= nil then str_list("policy.guard_files", p.guard_files, errs, path_check(true, true)) end
      if p.scan_depth ~= nil and not (type(p.scan_depth) == "number" and p.scan_depth >= 1 and p.scan_depth <= 32
        and p.scan_depth == math.floor(p.scan_depth)) then
        errs[#errs + 1] = "policy.scan_depth must be an integer from 1 to 32"
      end
      if p.scrub ~= nil then
        if type(p.scrub) ~= "table" then
          errs[#errs + 1] = "policy.scrub must be a table"
        else
          for k in pairs(p.scrub) do
            if k ~= "contains" and k ~= "prefix" and k ~= "exact" then
              errs[#errs + 1] = "unknown policy.scrub key " .. tostring(k)
            end
          end
          for _, k in ipairs({ "contains", "prefix", "exact" }) do
            if p.scrub[k] ~= nil then
              str_list("policy.scrub." .. k, p.scrub[k], errs, function(e)
                if not e:match("^[%w_]+$") then
                  return "environment variable names use letters, digits and _"
                end
              end)
            end
          end
        end
      end
    end
  end
  return errs
end

--- A switch that may be a function (evaluated now).
local function flag(name)
  local v = M.config[name]
  if type(v) == "function" then
    local ok, r = pcall(v)
    if ok then
      v = r
    else
      v = nil
    end
  end
  return v
end

local function exists(p)
  return vim.uv.fs_stat(p) ~= nil
end

--- Names to `--unsetenv`, computed from the live environment (and policy.scrub).
--- @param env? table<string,string> defaults to vim.fn.environ()
--- @param file_login? boolean defaults to: ~/.claude/.credentials.json exists
--- @return string[]
function M.scrub_names(env, file_login)
  env = env or vim.fn.environ()
  if file_login == nil then
    file_login = exists(home .. "/.claude/.credentials.json")
  end
  return plan_mod.scrub_names(env, file_login, (M.config.policy or {}).scrub)
end

local function cfg_view()
  return {
    policy = M.config.policy or {},
    strip_skip_permissions = M.config.strip_skip_permissions == true,
  }
end

--- Paths re-bound read-only on top of the writable binds.
--- @param project string
--- @return string[] ro, string[] masks  masks: absent dirs to cover with an empty read-only tmpfs
function M.readonly_paths(project)
  local p = plan_mod.build({
    project = project, tmp_dir = "/nonexistent", cwd = vim.uv.cwd(), env = {}, home = home, uid = uid,
    config = cfg_view(), assume_claude_dir = false,
  })
  local ro, masks = {}, {}
  for _, r in ipairs(p.readonly) do
    ro[#ro + 1] = r.path
  end
  for _, m in ipairs(p.masks) do
    masks[#masks + 1] = m.path
  end
  return ro, masks
end

-- ------------------------------------------------------------------- status

--- How the agent would run here:
---   { mode = "bwrap", ready = "ok"|"pending" }
---   { mode = "unsandboxed", via = "sandbox=false"|"allow_unsandboxed", reason, hint? }
---   { mode = "refused", reason, hint? }
--- Never blocks: the user-namespace probe runs asynchronously (the first call starts it, `ready`
--- is "pending" until it finished). A failed probe counts as no backend (fail closed).
function M.status()
  if flag("sandbox") == false then
    return { mode = "unsandboxed", via = "sandbox=false", reason = "sandbox = false" }
  end
  local linux = vim.fn.has("linux") == 1
  local reason, hint
  if linux and vim.fn.executable("bwrap") == 1 then
    local c = probe.cached()
    if c and c.ok then
      return { mode = "bwrap", ready = "ok" }
    elseif not c then
      probe.run(function() end)
      return { mode = "bwrap", ready = "pending" }
    end
    reason, hint = c.reason, c.hint
  else
    reason = linux and "bwrap not found (install bubblewrap)"
      or ("no sandbox backend on " .. (vim.uv.os_uname().sysname or "this OS") .. ": bubblewrap exists only on Linux")
  end
  if flag("allow_unsandboxed") == true then
    return { mode = "unsandboxed", via = "allow_unsandboxed", reason = reason, hint = hint }
  end
  return { mode = "refused", reason = reason, hint = hint }
end

--- Like status(), but waits for the readiness probe (one short blocking run, cached).
function M.status_blocking()
  local st = M.status()
  if st.mode == "bwrap" and st.ready == "pending" then
    probe.run_sync()
    st = M.status()
  end
  return st
end

--- Probe now (async), then call cb(status). `force` re-runs a cached verdict.
function M.check(cb, force)
  if flag("sandbox") == false or vim.fn.has("linux") ~= 1 or vim.fn.executable("bwrap") ~= 1 then
    return cb(M.status())
  end
  probe.run(function()
    cb(M.status())
  end, force)
end

-- --------------------------------------------------------------------- plan

local aux_empty

local function aux_paths()
  aux_empty = aux_empty or (vim.fn.tempname() .. ".empty")
  return { empty = aux_empty, claude_json = vim.fn.tempname() .. ".claude.json" }
end

--- The plan for running `cmd` here: the structured policy the launcher and the preview share.
--- @param cmd string[]
--- @param project string
--- @param tmp_dir string
--- @param opts? { exceptions?: table[], aux?: table, cwd?: string }  exceptions: extra approvals (this launch only)
--- @return table? plan, string? reason  (a refused status gives nil, reason)
function M.plan(cmd, project, tmp_dir, opts)
  opts = opts or {}
  local st = M.status()
  if st.mode == "refused" then
    return nil, st.reason
  elseif st.mode == "unsandboxed" then
    return {
      version = 1, mode = "unsandboxed", via = st.via, reason = st.reason, project = project, tmp_dir = tmp_dir,
      agent = { cmd = cmd, skip_permissions = plan_mod.skip_flag(cmd) ~= nil, flag = plan_mod.skip_flag(cmd) },
      exceptions = {}, rejected = {}, notes = {}, writable = {}, hidden = {}, readonly = {}, masks = {},
      guard_files = {}, env_strip = {}, env_kept = {}, git_locked = {}, network = "open",
    }
  end
  local excs = {}
  for _, a in ipairs(store.approvals(project)) do
    excs[#excs + 1] = { kind = a.kind, value = a.value, scope = "project", id = a.id }
  end
  for _, e in ipairs(opts.exceptions or {}) do
    excs[#excs + 1] = e
  end
  return plan_mod.build({
    cmd = cmd, project = project, tmp_dir = tmp_dir, cwd = opts.cwd or vim.uv.cwd(), env = vim.fn.environ(),
    home = home, uid = uid, config = cfg_view(), aux = opts.aux or aux_paths(), exceptions = excs,
    state_dir = store.dir(),
  })
end

--- The bwrap command line of a plan (pure).
function M.argv(plan)
  return plan_mod.argv(plan)
end

-- ---------------------------------------------------------------- exceptions

--- Record the operator's decision on one exception (see xyno_sandbox.exceptions). Returns the
--- exception to pass as `opts.exceptions` for a "once" approval, or nil when refused.
function M.approve(project, kind, value, scope)
  return require("xyno_sandbox.exceptions").decide(project, "approved", { kind = kind, value = value }, scope)
end

function M.refuse(project, kind, value)
  return require("xyno_sandbox.exceptions").decide(project, "refused", { kind = kind, value = value })
end

--- Remembered approvals of `project`, or of every project when nil.
function M.approvals(project)
  return require("xyno_sandbox.exceptions").list(project)
end

function M.revoke(project, id)
  return require("xyno_sandbox.exceptions").revoke(project, id)
end

-- ------------------------------------------------------------------- handles

local live = {} -- id -> handle
local next_id = 0

--- Number of sandboxes started through wrap() that were not released yet.
function M.running()
  local n = 0
  for _ in pairs(live) do
    n = n + 1
  end
  return n
end

local function is_empty_leftover(path, kind)
  local st = vim.uv.fs_lstat(path)
  if not st then
    return false
  end
  if kind == "dir" then
    return st.type == "directory" and #vim.fn.readdir(path) == 0
  end
  -- bwrap creates the mount point as an empty read-only (0444) file
  return st.type == "file" and st.size == 0 and bit.band(st.mode, tonumber("222", 8)) == 0
end

local function release(h)
  if h.released then
    return
  end
  h.released = true
  live[h.id] = nil
  for _, f in ipairs(h.temp) do
    vim.uv.fs_unlink(f)
  end
  local others = false
  pcall(function()
    others = store.live_others(h.plan.project, h.reg)
  end)
  pcall(store.live_remove, h.reg)
  if others then
    return -- another sandbox of this project still mounts the placeholders: removing them would unmount
  end
  local items = {}
  for _, m in ipairs(h.plan.masks) do
    if m.cleanup then
      items[#items + 1] = { m.path, "dir" }
    end
  end
  for _, g in ipairs(h.plan.guard_files) do
    if g.cleanup then
      items[#items + 1] = { g.path, "file" }
    end
  end
  table.sort(items, function(a, b)
    return #a[1] > #b[1] -- children first
  end)
  for _, it in ipairs(items) do
    if is_empty_leftover(it[1], it[2]) then
      if it[2] == "dir" then
        vim.uv.fs_rmdir(it[1])
      else
        vim.uv.fs_unlink(it[1])
      end
    end
  end
end

--- Release every live sandbox (temp files, empty leftovers). Runs at VimLeavePre.
function M.cleanup()
  local all = {}
  for _, h in pairs(live) do
    all[#all + 1] = h
  end
  for _, h in ipairs(all) do
    h.release()
  end
end

local function stale(plan)
  for _, m in ipairs(plan.masks) do
    if m.cleanup and exists(m.path) then
      return true
    end
  end
  for _, g in ipairs(plan.guard_files) do
    if exists(g.path) then
      return true
    end
  end
  return false
end

local function prepare(plan)
  for _, d in ipairs(plan.needs.mkdir) do
    vim.fn.mkdir(d, "p")
  end
  local temp = {}
  if plan.empty_file and not exists(plan.empty_file) then
    vim.fn.writefile({}, plan.empty_file)
  end
  if plan.claude_json then
    -- a private COPY: it works, but nothing the sandbox writes reaches the real file
    local c = plan.claude_json
    if vim.uv.fs_copyfile(c.src, c.copy) then
      vim.uv.fs_chmod(c.copy, tonumber("600", 8))
      temp[#temp + 1] = c.copy
    else
      plan.claude_json = nil
    end
  end
  return temp
end

--- @param cmd string[] command to wrap
--- @param project string project root (writable)
--- @param tmp_dir string scratch dir of the agent (writable)
--- @param opts? { plan?: table, exceptions?: table[] }  plan: a plan from M.plan() (the one the
---   operator saw; rebuilt when the files it assumed absent appeared meanwhile)
--- @return string[]? wrapped command (the same table when explicitly unsandboxed); nil when refused
--- @return string? reason
--- @return table? handle  { plan, release() }: call release() when the process ended (removes the
---   private copy of the agent config and the empty placeholders the guards left in the project)
function M.wrap(cmd, project, tmp_dir, opts)
  assert(type(tmp_dir) == "string" and tmp_dir ~= "", "xyno_sandbox.wrap: tmp_dir is required")
  opts = opts or {}
  local st = M.status_blocking()
  if st.mode == "refused" then
    return nil, st.reason .. (st.hint and (" (" .. st.hint .. ")") or "")
  elseif st.mode == "unsandboxed" then
    return cmd
  end
  local plan = opts.plan
  local excs = opts.exceptions
  if plan and (plan.mode ~= "bwrap" or plan.project ~= project or stale(plan)) then
    -- keep what the operator approved for this launch when the plan has to be rebuilt
    excs = vim.list_extend(vim.deepcopy(excs or {}), vim.tbl_filter(function(e)
      return e.scope == "once"
    end, plan.exceptions or {}))
    plan = nil
  end
  plan = plan or M.plan(cmd, project, tmp_dir, { exceptions = excs })
  local temp = prepare(plan)
  next_id = next_id + 1
  local h = { id = next_id, plan = plan, temp = temp }
  h.reg = store.live_add(project, tostring(next_id) .. "-" .. tostring(vim.uv.hrtime()))
  h.release = function()
    release(h)
  end
  live[h.id] = h
  return plan_mod.argv(plan), nil, h
end

-- ------------------------------------------------------------- statusline

--- One short word for a statusline (lualine: `lualine_x = { require("xyno_sandbox").statusline }`).
--- Never blocks, never errors.
function M.statusline()
  local ok, st = pcall(M.status)
  if not ok then
    return "sandbox: ?"
  end
  local n = M.running()
  local runs = n > 0 and (" x" .. n) or ""
  if st.mode == "bwrap" then
    if st.ready == "pending" then
      return "sandbox: checking"
    end
    return "sandbox: on" .. runs
  elseif st.mode == "unsandboxed" then
    return "sandbox: OFF" .. runs
  end
  return "sandbox: refused"
end

--- Highlight group matching statusline(): DiagnosticOk / DiagnosticWarn / DiagnosticError.
function M.statusline_hl()
  local ok, st = pcall(M.status)
  if not ok or st.mode == "refused" then
    return "DiagnosticError"
  elseif st.mode == "unsandboxed" then
    return "DiagnosticWarn"
  end
  return st.ready == "pending" and "DiagnosticHint" or "DiagnosticOk"
end

-- ------------------------------------------------------------------- setup

--- Merge options and register the commands / keymaps. Invalid options raise an error and change
--- nothing.
--- @param opts? table see M.config and validate_opts()
function M.setup(opts)
  opts = opts or {}
  local errs = M.validate_opts(opts)
  if #errs > 0 then
    error("xyno_sandbox.setup: " .. table.concat(errs, "; "), 2)
  end
  local merged = vim.tbl_extend("force", M.config, opts)
  if opts.policy then
    merged.policy = vim.deepcopy(opts.policy)
  end
  M.config = merged
  require("xyno_sandbox.run").register(M.config)
  if not M._autocmd then
    M._autocmd = vim.api.nvim_create_autocmd("VimLeavePre", {
      group = vim.api.nvim_create_augroup("xyno_sandbox", { clear = true }),
      callback = function()
        pcall(M.cleanup)
      end,
    })
  end
end

--- The launch-time policy preview and confirm (see xyno_sandbox.run.confirm).
function M.confirm(cmd, project, tmp_dir, cb)
  return require("xyno_sandbox.run").confirm(cmd, project, tmp_dir, cb)
end

--- Run `cmd` wrapped in a terminal split (see xyno_sandbox.run).
function M.run(cmd, opts)
  return require("xyno_sandbox.run").run(cmd, opts)
end

return M
