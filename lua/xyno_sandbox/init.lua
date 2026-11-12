-- Runs a command-line coding agent inside bubblewrap. The whole filesystem is
-- read-only except the project, a scratch dir, and the few paths the agent and
-- cargo must write.
-- Everything that would later run UNSANDBOXED (git hooks/config, agent
-- settings/hooks/plugins, direnv, editor task files, cargo config, the agent
-- binary) is read-only even inside the writable binds. Credential dirs/files
-- are hidden, credential env vars are stripped, pid/ipc/uts namespaces are
-- unshared, capabilities dropped, nested user namespaces disabled.
-- Network egress is default-deny: the sandbox gets a private network namespace and reaches the
-- internet only through a local filtering proxy that allows a short list of host names
-- (xyno_sandbox.net). If that cannot be set up the agent does not start; network = "open" is the
-- explicit opt-out.
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

--- The hosts allowed by default (the agent's API, crates.io); copy it to extend: allow_hosts =
--- vim.list_extend(vim.deepcopy(require("xyno_sandbox").default_hosts), { "github.com" })
M.default_hosts = vim.deepcopy(require("xyno_sandbox.net").DEFAULT_HOSTS)

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
  home = "allowlist", -- "allowlist": $HOME is empty except explicitly allowed paths | "denylist": all of $HOME readable except the hidden credential paths
  expert_exceptions = false, -- true: "env" exceptions for variables that decide which code runs (LD_PRELOAD, PATH, ...) may be approved
  network = "filtered", -- "filtered" (default-deny egress, allowlist) | "open" (no restriction, shown as OPEN)
  allow_hosts = nil, -- nil: the default list (xyno_sandbox.default_hosts); a list REPLACES it
  policy = {}, -- additive policy lists, see validate_opts()
  agent_cmd = nil, -- command shown by :XynoSandboxPolicy when nothing was launched yet
}

local home = vim.uv.os_homedir()
local pwd = vim.uv.os_get_passwd() -- uid is -1 or the call fails on Windows
local uid = pwd and pwd.uid or -1

-- ------------------------------------------------------------------ options

local POLICY_LISTS = { "readonly", "writable", "hidden", "guard_dirs", "guard_files", "home_allow", "keep_run",
  "secret_files", "secret_allow", "claude_share" }
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
---   home_allow  = { "~/x" }              more $HOME paths shown read-only in home = "allowlist" mode
---   keep_run    = { "/run/x" }           paths under the masked /run bound back read-only (no sockets!)
---   project_secrets = true               hide .env, *.pem, ... in the project (false: do not)
---   secret_files = { "*.secret" }        more project file name globs to hide
---   secret_allow = { ".env.test" }       project file names (or project-relative paths) never hidden
---   claude_share = { "settings.json", "CLAUDE.md" }  names below ~/.claude shown read-only in the sandbox (allowlist view;
---                                        default none: the agent sees only its login and this project's transcripts)
---   content_scan = true                  look inside project files for known token formats (cloud/forge tokens,
---                                        private keys) and hide the files that contain one (false: do not)
---   tree_secrets = true                  hide secret NAMES (.ssh, .npmrc, credentials, secrets/ ...) inside the trees shown
---                                        whole from $HOME (a $PATH entry's parent, toolchains); false: do not
---   symlinks    = "warn"                 "warn" (list them in the preview) | "refuse" (do not start when a
---                                        symlink leaves the project and its target is readable)
--- }
--- The lists only ADD to the built-in policy; nothing can be removed from it.
function M.validate_opts(opts)
  local errs = {}
  local known = { sandbox = true, allow_unsandboxed = true, keymaps = true, commands = true, preview = true,
    strip_skip_permissions = true, policy = true, agent_cmd = true, network = true, allow_hosts = true,
    home = true, expert_exceptions = true }
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
  if opts.network ~= nil and opts.network ~= "filtered" and opts.network ~= "open" then
    errs[#errs + 1] = 'network must be "filtered" or "open"'
  end
  if opts.home ~= nil and opts.home ~= "allowlist" and opts.home ~= "denylist" then
    errs[#errs + 1] = 'home must be "allowlist" or "denylist"'
  end
  if opts.expert_exceptions ~= nil and type(opts.expert_exceptions) ~= "boolean" then
    errs[#errs + 1] = "expert_exceptions must be a boolean"
  end
  if opts.allow_hosts ~= nil then
    str_list("allow_hosts", opts.allow_hosts, errs, function(e)
      local _, why = require("xyno_sandbox.net").parse_entry(e)
      return why
    end)
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
      local pknown = { scrub = true, scan_depth = true, project_secrets = true, symlinks = true, content_scan = true, tree_secrets = true }
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
      if p.home_allow ~= nil then str_list("policy.home_allow", p.home_allow, errs, path_check(false, true)) end
      if p.keep_run ~= nil then
        str_list("policy.keep_run", p.keep_run, errs, function(e)
          local why = path_check(false, true)(e)
          if why then
            return why
          end
          if not (e:sub(1, 5) == "/run/" or e:sub(1, 9) == "/var/tmp/") then
            return "must be below /run or /var/tmp (the masked directories)"
          end
        end)
      end
      if p.claude_share ~= nil then
        str_list("policy.claude_share", p.claude_share, errs, function(e)
          if not plan_mod.claude_share_ok((e:gsub("^/+", ""))) then
            return "not shareable (the login is always shared; transcripts, history and sessions never are; no '..')"
          end
        end)
      end
      if p.secret_files ~= nil then
        str_list("policy.secret_files", p.secret_files, errs, function(e)
          if e:find("/", 1, true) then
            return "a file name glob, without a directory"
          end
        end)
      end
      if p.secret_allow ~= nil then str_list("policy.secret_allow", p.secret_allow, errs) end
      if p.project_secrets ~= nil and type(p.project_secrets) ~= "boolean" then
        errs[#errs + 1] = "policy.project_secrets must be a boolean"
      end
      if p.tree_secrets ~= nil and type(p.tree_secrets) ~= "boolean" then
        errs[#errs + 1] = "policy.tree_secrets must be a boolean"
      end
      if p.content_scan ~= nil and type(p.content_scan) ~= "boolean" then
        errs[#errs + 1] = "policy.content_scan must be a boolean"
      end
      if p.symlinks ~= nil and p.symlinks ~= "warn" and p.symlinks ~= "refuse" then
        errs[#errs + 1] = 'policy.symlinks must be "warn" or "refuse"'
      end
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

--- "open" only for the exact string "open" (a function returning it counts); anything else is
--- filtered, so a typo cannot open the network.
function M.net_mode()
  return flag("network") == "open" and "open" or "filtered"
end

local function cfg_view()
  return {
    network = M.net_mode(),
    allow_hosts = flag("allow_hosts"),
    policy = M.config.policy or {},
    strip_skip_permissions = M.config.strip_skip_permissions == true,
    home = flag("home") == "denylist" and "denylist" or "allowlist",
    expert_exceptions = flag("expert_exceptions") == true,
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
  probe.net = M.net_mode() == "filtered"
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
  probe.net = M.net_mode() == "filtered"
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
  return { empty = aux_empty, claude_json = vim.fn.tempname() .. ".claude.json", net_dir = vim.fn.tempname() .. ".net",
    git_dir = vim.fn.tempname() .. ".git" }
end

--- The plan for running `cmd` here: the structured policy the launcher and the preview share.
--- @param cmd string[]
--- @param project string
--- @param tmp_dir string
--- @param opts? { exceptions?: table[], aux?: table, cwd?: string, env?: table<string,string> }  exceptions:
---   extra approvals (this launch only); env: variables set or overridden on top of Neovim's own
---   environment (a false value removes one)
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
  local env = vim.fn.environ()
  for k, v in pairs(opts.env or {}) do
    env[k] = v or nil
  end
  return plan_mod.build({
    cmd = cmd, project = project, tmp_dir = tmp_dir, cwd = opts.cwd or vim.uv.cwd(), env = env,
    home = home, passwd_home = pwd and pwd.homedir, uid = uid, config = cfg_view(), aux = opts.aux or aux_paths(), exceptions = excs, nvim = vim.v.progpath,
    state_dir = store.dir(),
  })
end

--- The bwrap command line of a plan (pure).
function M.argv(plan)
  return plan_mod.argv(plan)
end

--- The plan of `project` without any exception: what an exception would be measured against (is
--- the path hidden at all, does a later read-only mount cover it).
function M.baseline(project)
  return plan_mod.build({
    project = project, tmp_dir = "/nonexistent-xyno-baseline", cwd = project, env = vim.fn.environ(), home = home,
    uid = uid, passwd_home = pwd and pwd.homedir, config = cfg_view(), cmd = { "agent" }, assume_claude_dir = false,
    state_dir = store.dir(),
  })
end

--- Validation context of exception decisions (see xyno_sandbox.exceptions).
function M.exception_context(project, kind)
  return {
    home = home, state_dir = store.dir(), probes = plan_mod.real_probes(),
    baseline = (kind == "unhide" or kind == "writable") and M.baseline(project) or nil,
    expert = cfg_view().expert_exceptions, scrub = (M.config.policy or {}).scrub,
    file_login = exists(home .. "/.claude/.credentials.json"),
  }
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
  if h.proxy then
    pcall(h.proxy.close)
  end
  if h.net_dir then
    vim.fn.delete(h.net_dir, "rf")
  end
  for _, f in ipairs(h.temp) do
    if vim.uv.fs_stat(f) and vim.uv.fs_stat(f).type == "directory" then
      vim.fn.delete(f, "rf")
    else
      vim.uv.fs_unlink(f)
    end
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

--- Remove the empty placeholders that a sandbox of a Neovim that has since died left in a project
--- (it could not release them), unless another live sandbox of that project still mounts them.
--- Only empty files and empty directories recorded by wrap() are touched. Returns how many.
function M.reap_orphans()
  local n = 0
  local list = store.live_orphans()
  table.sort(list, function(a, b)
    return #a[1] > #b[1]
  end)
  for _, it in ipairs(list) do
    if it[2] == "temp" then
      -- only what wrap() itself creates: <nvim tmpdir>/<n>.claude.json | .net | .git, never a symlink
      local st = vim.uv.fs_lstat(it[1])
      local name = vim.fs.basename(it[1])
      if st and st.type ~= "link" and (name:match("%.claude%.json$") or name:match("%.net$") or name:match("%.git$")) then
        n = n + (vim.fn.delete(it[1], "rf") == 0 and 1 or 0)
      end
    elseif is_empty_leftover(it[1], it[2]) and not store.live_others(it[3], nil) then
      if it[2] == "dir" then
        n = n + (vim.uv.fs_rmdir(it[1]) and 1 or 0)
      else
        n = n + (vim.uv.fs_unlink(it[1]) and 1 or 0)
      end
    end
  end
  return n
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

--- The agent's user config without the other projects: ~/.claude.json keeps a record per project
--- directory (trusted-folder state, MCP servers with their arguments, recent prompts). The copy the
--- sandbox gets holds the current project's entry only. A file that does not parse is not shared at
--- all (the agent then starts from a fresh config). The copy is private (0600).
--- @return boolean
function M.write_scrubbed_claude_json(src, dest, project)
  local f = io.open(src, "rb")
  if not f then
    return false
  end
  local raw = f:read("*a")
  f:close()
  local ok, data = pcall(vim.json.decode, raw)
  if not ok or type(data) ~= "table" then
    return false
  end
  data = require("xyno_sandbox.sanitize").claude_json(data, { project, vim.uv.fs_realpath(project) })
  local out = assert(vim.uv.fs_open(dest, "w", tonumber("600", 8)))
  vim.uv.fs_write(out, vim.json.encode(data))
  vim.uv.fs_close(out)
  vim.uv.fs_chmod(dest, tonumber("600", 8))
  return true
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
    local ok = M.write_scrubbed_claude_json(c.src, c.copy, c.project)
    if ok then
      temp[#temp + 1] = c.copy
    else
      plan.claude_json = nil
    end
  end
  if plan.needs.git_configs and #plan.needs.git_configs > 0 then
    vim.fn.mkdir(plan.needs.git_dir, "p", tonumber("700", 8))
    temp[#temp + 1] = plan.needs.git_dir
    for _, g in ipairs(plan.needs.git_configs) do
      local f = io.open(g.src, "rb")
      local text = f and f:read("*a")
      if f then
        f:close()
      end
      -- an unreadable config becomes an empty one: never the original
      local clean = text and require("xyno_sandbox.sanitize").git_config(text) or "# xyno-sandbox: this git config could not be read\n"
      local out = assert(io.open(g.copy, "wb"))
      out:write(clean)
      out:close()
      vim.uv.fs_chmod(g.copy, tonumber("600", 8))
    end
  end
  return temp
end

local relay_source

--- Start the filtering proxy of a filtered plan: the socket directory (0700, read-only inside the
--- sandbox), the relay script next to it, the listener. Returns the handle fields or nil, reason.
--- Nothing is left behind on failure.
local function start_net(plan, project)
  local n = plan.net
  local function fail(why)
    pcall(vim.fn.delete, n.dir, "rf")
    return nil, "network egress cannot be enforced (" .. why .. "); the agent is not started. "
      .. 'Set network = "open" in setup() to run it with an open network.'
  end
  if vim.fn.executable(n.nvim) ~= 1 then
    return fail(n.nvim .. " is not executable, the in-sandbox relay needs it")
  end
  vim.fn.delete(n.dir, "rf")
  if vim.fn.mkdir(n.dir, "p", tonumber("700", 8)) ~= 1 then
    return fail("cannot create " .. n.dir)
  end
  if not relay_source then
    local src = debug.getinfo(1, "S").source:sub(2):gsub("init%.lua$", "relay.lua")
    local f = io.open(src, "rb")
    relay_source = f and f:read("*a")
    if f then
      f:close()
    end
  end
  if not relay_source then
    return fail("relay.lua not found")
  end
  local f = io.open(n.relay, "wb")
  if not f then
    return fail("cannot write " .. n.relay)
  end
  f:write(relay_source)
  f:close()
  local hosts = {}
  for _, h in ipairs(n.hosts) do
    hosts[#hosts + 1] = h.host
  end
  local warned = {}
  local ok, proxy, err = pcall(require("xyno_sandbox.net").start, {
    sock = n.sock,
    hosts = hosts,
    on_decision = function(d)
      if d.allowed or warned[d.host] then
        return
      end
      warned[d.host] = true
      vim.schedule(function()
        pcall(store.log, { project = project, kind = "host", value = d.host .. ":" .. tostring(d.port), decision = "blocked",
          scope = "launch", reason = d.reason })
        vim.notify(("xyno-sandbox: blocked network access to %s:%s (%s). Allow it with e in :XynoSandboxPolicy."):format(
          d.host, tostring(d.port), d.reason), vim.log.levels.WARN)
      end)
    end,
  })
  if not ok then
    return fail(tostring(proxy))
  end
  if not proxy then
    return fail(tostring(err))
  end
  return { proxy = proxy, net_dir = n.dir }
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
  pcall(M.reap_orphans)
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
  plan = plan or M.plan(cmd, project, tmp_dir, { exceptions = excs, env = opts.env })
  if plan.blocked then
    return nil, plan.blocked
  end
  local netf
  if plan.net then
    local why
    netf, why = start_net(plan, project)
    if not netf then
      return nil, why
    end
  end
  local temp = prepare(plan)
  next_id = next_id + 1
  local h = { id = next_id, plan = plan, temp = temp }
  if netf then
    h.proxy, h.net_dir = netf.proxy, netf.net_dir
  end
  local items = {}
  for _, m in ipairs(plan.masks) do
    if m.cleanup then
      items[#items + 1] = { m.path, "dir" }
    end
  end
  for _, g in ipairs(plan.guard_files) do
    if g.cleanup then
      items[#items + 1] = { g.path, "file" }
    end
  end
  -- private copies and the socket directory: a next launch removes them when this nvim dies without
  -- running VimLeavePre (kill -9 leaves nvim's own tmpdir behind)
  for _, f in ipairs(temp) do
    items[#items + 1] = { f, "temp" }
  end
  if h.net_dir then
    items[#items + 1] = { h.net_dir, "temp" }
  end
  h.reg = store.live_add(project, tostring(next_id) .. "-" .. tostring(vim.uv.hrtime()), items)
  h.release = function()
    release(h)
  end
  h.blocked = function()
    return h.proxy and vim.tbl_filter(function(d)
      return not d.allowed
    end, h.proxy.decisions) or {}
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
