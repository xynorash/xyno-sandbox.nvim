-- The argument plan of the sandbox: a PURE function of its inputs.
--
--   plan = build({ project, tmp_dir, cwd, env, home, uid, config, probes, aux, exceptions, cmd })
--   argv = argv(plan)
--
-- build() touches nothing: every look at the filesystem goes through `probes`
-- (real ones in plan.real_probes(), a table-backed fake in the specs), the
-- environment is the `env` table, and the files the launcher must create
-- before bwrap runs (an empty file for hidden files, a private copy of the
-- agent's user config) are only NAMED in `aux`, listed in plan.needs. The
-- launcher (xyno_sandbox.wrap) and the preview (:XynoSandboxPolicy) both
-- consume the same plan, so what is shown is what runs.
local M = {}

-- ----------------------------------------------------------------- policy

-- Writable inside the sandbox (when they exist), relative to $HOME. Deliberately NOT here:
-- ~/.local/share/claude (the claude binary), ~/.cargo/bin, ~/.cargo/config.toml.
M.WRITABLE = {
  "/.claude", -- sessions/projects/todos/cache/...; exec-ish parts re-locked below
  "/.cache/claude",
  "/.local/state/claude",
  "/.cargo/registry",
  "/.cargo/git",
  "/.cargo/.package-cache", -- cargo's download locks (files)
  "/.cargo/.package-cache-mutate",
}

-- Re-bound read-only on top of the writable binds when they exist. Whatever an
-- agent planted here would run (or steer a tool) outside the sandbox later.
M.HOME_READONLY = {
  "/.claude/settings.json", "/.claude/settings.local.json", "/.claude/CLAUDE.md",
  "/.claude/keybindings.json", "/.claude/hooks", "/.claude/commands", "/.claude/agents",
  "/.claude/skills", "/.claude/plugins", "/.claude/output-styles",
  "/.claude/ide", -- IDE lock files make claude connect to a local server
  "/.claude/rules",
  "/.claude/chrome", -- chrome-native-host is a shell script Chrome launches unsandboxed
  "/.claude/security", -- the security-guidance hook imports from agent-sdk-venv here, unsandboxed
}

-- Same dirs, but when ABSENT the agent could create them (a later unsandboxed
-- claude would load them: prompt injection), so mask them with an empty
-- read-only dir (leaves one empty dir behind in ~/.claude).
M.HOME_MASK_IF_ABSENT = {
  "/.claude/hooks", "/.claude/commands", "/.claude/agents", "/.claude/skills", "/.claude/rules",
  "/.claude/output-styles", "/.claude/security",
}

-- Ephemeral inside the sandbox: claude sources these before running commands.
M.HOME_EPHEMERAL = { "/.claude/shell-snapshots", "/.claude/session-env" }

-- Project-relative auto-executing / tool-steering files (locked when present).
M.PROJECT_READONLY = {
  ".gitmodules", ".envrc", ".mise.toml", ".tool-versions", ".nvim.lua", ".nvimrc", ".exrc",
  ".vscode/tasks.json", ".vscode/settings.json",
  ".cargo", -- whole dir: config.toml sets runner / linker / rustflags and runs on the next cargo build
  ".vscode", -- whole dir, so tasks.json cannot be swapped by renaming the parent
  ".mcp.json",
}
-- Locked in workspace members too: cargo reads .cargo/config from every ancestor of the
-- directory it runs in; direnv reads the nearest .envrc.
M.MEMBER_READONLY = { ".cargo", ".envrc" }
-- Created empty-and-read-only when absent at the project root: a planted .cargo/config.toml is
-- the one that bites. .git too: without one the agent ran `git init` and planted
-- `core.fsmonitor = <cmd>` in .git/config, which the user's next unsandboxed `git status`
-- executed. .vscode: a planted tasks.json runs from the user's editor. The launcher removes the
-- empty leftovers when the run ends (see xyno_sandbox.wrap, handle.release).
M.PROJECT_MASK_IF_ABSENT = { ".cargo", ".git", ".vscode" }
-- Files that run unsandboxed later when planted. When absent they are bound to an empty
-- read-only file for the run (the launcher removes the placeholder afterwards).
M.PROJECT_GUARD_FILES = { ".envrc", ".mise.toml", ".nvim.lua", ".nvimrc", ".exrc", ".mcp.json" }
-- Project dir that is ALWAYS locked: read-only when present, otherwise masked.
M.PROJECT_MASKED = ".claude"

-- Hidden (dirs: empty tmpfs, files: an empty read-only file) when they exist. A denylist on a
-- read-only view of the whole filesystem, so best effort: anything not listed is readable.
M.HIDDEN = {
  -- shell/CLI credentials
  "/.ssh", "/.gnupg", "/.aws", "/.azure", "/.gsutil", "/.boto", "/.docker", "/.kube",
  "/.terraform.d", "/.vault-token", "/.netrc", "/.git-credentials", "/.npmrc", "/.pypirc",
  "/.cargo/credentials", "/.cargo/credentials.toml", "/.pub-cache/credentials.json",
  "/.android/adbkey", "/.pki", "/.password-store", "/.Xauthority", "/.pulse-cookie",
  -- ~/.config
  "/.config/gh", "/.config/git/credentials", "/.config/rclone", "/.config/pulumi",
  "/.config/helm", "/.config/gcloud", "/.config/op", "/.config/doctl", "/.config/hub",
  "/.config/Bitwarden", "/.config/1Password", "/.config/keepassxc", "/.config/pulse",
  "/.config/Slack", "/.config/discord", "/.config/Signal", "/.config/rustdesk",
  "/.config/winapps", "/.config/freerdp", "/.config/obs-studio", "/.config/JetBrains",
  "/.config/spotify", "/.config/herdr", "/.anydesk", "/.neuralstark-live",
  -- browsers / mail
  "/.config/google-chrome", "/.config/google-chrome-headless", "/.config/Google",
  "/.config/chromium", "/.config/BraveSoftware", "/.config/microsoft-edge",
  "/.config/vivaldi", "/.config/opera", "/.mozilla", "/.thunderbird", "/.cache/google-chrome",
  -- ~/.local/share
  "/.local/share/keyrings", "/.local/share/password-store", "/.local/share/gnome-keyring",
  "/.local/share/kwalletd", "/.local/share/TelegramDesktop", "/.local/share/fish",
  "/.local/share/winapps",
  -- remote-control keys of other claude sessions / the claude daemon
  "/.claude/daemon", "/.claude/sessions",
  -- every prompt typed in any project (readable, and it was writable too)
  "/.claude/history.jsonl",
}
-- Globs under $HOME (shell and tool histories).
M.HIDDEN_GLOBS = { "/.*_history*", "/.lesshst", "/.config/fish/fish_history" }
-- Absolute system paths: container/dbus sockets are root-equivalent (the user is in group
-- docker) or reach other services; /run/user holds the gpg/ssh agent, keyring, wayland and
-- session-bus sockets.
function M.hidden_system(uid)
  return {
    "/run/user/" .. uid,
    "/run/docker.sock", "/run/docker", "/run/containerd", "/run/podman", "/run/libvirt",
    "/run/dbus", "/run/snapd.socket", "/run/snapd-snap.socket",
    -- tailscaled.sock is mode 0666: `tailscale status` listed the peers and RunSSH was on
    "/run/tailscale", "/run/seatd.sock",
  }
end

-- Environment scrub: any variable whose name contains one of these ...
M.ENV_CONTAINS = {
  "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "CREDENTIAL", "PRIVATE_KEY",
  "ACCESS_KEY", "AUTH_SOCK", "AGENT_INFO", "PASSPHRASE", "ASKPASS",
}
-- ... or starts with one of these ...
M.ENV_PREFIX = {
  "AWS_", "AZURE_", "GOOGLE_", "GCP_", "GCLOUD_", "DOCKER_", "KUBE", "GH_", "GITHUB_", "GITLAB_",
  "NPM_", "CARGO_REGISTR", "VAULT_", "OPENAI_", "STRIPE_",
}
-- ... or is exactly one of these (session bus / display access).
M.ENV_EXACT = {
  DATABASE_URL = true, DBUS_SESSION_BUS_ADDRESS = true, DISPLAY = true, WAYLAND_DISPLAY = true,
  XAUTHORITY = true, SSH_AUTH_SOCK = true, GPG_AGENT_INFO = true, KUBECONFIG = true,
  MYSQL_PWD = true, SSHPASS = true, -- not a "PASSWORD" by name; a bare PWD would also be the cwd
}
-- Variables claude itself authenticates with. Kept only when login is NOT file based (no
-- ~/.claude/.credentials.json); with file-based login claude never reads them.
M.ENV_CLAUDE_AUTH = { "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN" }

-- Skipped by the directory walk (still locked when they ARE the project's own .git).
M.SCAN_SKIP = {
  target = true, node_modules = true, [".git"] = true, [".cache"] = true,
  [".venv"] = true, venv = true, __pycache__ = true, [".mypy_cache"] = true, [".tox"] = true,
}
M.SCAN_DEPTH = 8 -- nested .git and workspace members are found down to this depth
M.SCAN_MAX_DIRS = 20000 -- the walk stops here and the plan says so (plan.notes)

M.SKIP_PERMISSIONS_FLAGS = { "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions" }

M.ISOLATION_FLAGS = {
  "--die-with-parent",
  "--new-session", -- no controlling tty: TIOCSTI keystroke injection
  "--unshare-user", "--disable-userns", -- no nested bwrap / unshare -r
  "--unshare-pid", -- other processes (/proc/PID/environ, /proc/PID/root) invisible
  "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
  "--cap-drop", "ALL",
}

-- ----------------------------------------------------------------- probes

--- The filesystem as the plan builder sees it. Replace for a pure test.
function M.real_probes()
  local uv = vim.uv
  return {
    stat_type = function(p)
      local st = uv.fs_stat(p)
      return st and st.type or nil
    end,
    exists = function(p)
      return uv.fs_stat(p) ~= nil
    end,
    --- entries of a directory: { { name, type }, ... }
    list = function(dir)
      local out = {}
      local ok = pcall(function()
        for name, t in vim.fs.dir(dir) do
          out[#out + 1] = { name, t }
        end
      end)
      return ok and out or {}
    end,
    glob = function(pat)
      return vim.fn.glob(pat, true, true)
    end,
    --- first line of a file, or nil
    read_line = function(p)
      local f = io.open(p, "r")
      if not f then
        return nil
      end
      local l = f:read("l")
      f:close()
      return l or ""
    end,
    realpath = function(p)
      return uv.fs_realpath(p)
    end,
  }
end

-- ------------------------------------------------------------------ utils

local function copy_list(l)
  return vim.list_slice(l or {}, 1, #(l or {}))
end

--- Lexically normalised absolute path ("/a/./b//c/" -> "/a/b/c"); nil for relative paths and ".."
--- segments (never resolved: a path with ".." is rejected, not guessed).
function M.normalize(p)
  if type(p) ~= "string" or p:sub(1, 1) ~= "/" then
    return nil
  end
  local parts = {}
  for seg in p:gmatch("[^/]+") do
    if seg == ".." then
      return nil
    elseif seg ~= "." then
      parts[#parts + 1] = seg
    end
  end
  return "/" .. table.concat(parts, "/")
end

local function inside(p, dir)
  return p == dir or p:sub(1, #dir + 1) == dir .. "/"
end
M.inside = inside

local function claude_project_name(d)
  return (d:gsub("[^%w]", "-"))
end

-- --------------------------------------------------------------- scrubbing

--- Names to `--unsetenv`.
--- @param env table<string,string>
--- @param file_login boolean
--- @param extra? { contains?: string[], prefix?: string[], exact?: string[] } user patterns (additive)
--- @return string[]
function M.scrub_names(env, file_login, extra)
  extra = extra or {}
  local keep = {}
  if not file_login then
    for _, v in ipairs(M.ENV_CLAUDE_AUTH) do
      keep[v] = true
    end
  end
  local exact = {}
  for _, e in ipairs(extra.exact or {}) do
    exact[e:upper()] = true
  end
  local out = {}
  for name in pairs(env) do
    local u = name:upper()
    local hit = M.ENV_EXACT[u] or exact[u] or false
    for _, s in ipairs(M.ENV_CONTAINS) do
      hit = hit or u:find(s, 1, true) ~= nil
    end
    for _, s in ipairs(extra.contains or {}) do
      hit = hit or u:find(s:upper(), 1, true) ~= nil
    end
    for _, s in ipairs(M.ENV_PREFIX) do
      hit = hit or u:sub(1, #s) == s
    end
    for _, s in ipairs(extra.prefix or {}) do
      hit = hit or u:sub(1, #s) == s:upper()
    end
    if hit and not keep[name] then
      out[#out + 1] = name
    end
  end
  table.sort(out)
  return out
end

-- -------------------------------------------------------------- git / walk

--- Real gitdir (and shared commondir) behind a `.git` FILE ("gitdir: ..." of worktrees,
--- submodules and bare-repo layouts).
local function resolve_gitfile(probes, dotgit, dir)
  local out = {}
  local line = probes.read_line(dotgit) or ""
  local gd = line:match("^gitdir:%s*(.-)%s*$")
  if not gd or gd == "" then
    return out
  end
  if not gd:match("^/") then
    gd = dir .. "/" .. gd
  end
  gd = probes.realpath(gd)
  if not gd then
    return out
  end
  out[#out + 1] = gd
  local cd = probes.read_line(gd .. "/commondir")
  if cd and cd ~= "" then
    cd = probes.realpath(cd:match("^/") and cd or (gd .. "/" .. cd))
    if cd then
      out[#out + 1] = cd
    end
  end
  return out
end

--- One walk of the project down to `depth`: every `.git` (dir or file, plus the real gitdirs
--- behind `.git` files) and every workspace-member candidate (non-hidden directory).
--- @return { gits: string[], members: { dir: string, cargo: boolean }[], truncated: boolean }
local function walk(probes, project, depth)
  local gits, gseen, members = {}, {}, {}
  local visited, truncated = 0, false
  local function addgit(p)
    if not gseen[p] and probes.exists(p) then
      gseen[p] = true
      gits[#gits + 1] = p
    end
  end
  local function scan(dir, d)
    local dotgit = dir .. "/.git"
    local t = probes.stat_type(dotgit)
    if t then
      if t == "file" then
        for _, p in ipairs(resolve_gitfile(probes, dotgit, dir)) do
          addgit(p)
        end
      end
      addgit(dotgit)
    end
    if d >= depth then
      return
    end
    for _, e in ipairs(probes.list(dir)) do
      local name, ty = e[1], e[2]
      if ty == "directory" and not M.SCAN_SKIP[name] then
        visited = visited + 1
        if visited > M.SCAN_MAX_DIRS then
          truncated = true
          return
        end
        local sub = dir .. "/" .. name
        if name:sub(1, 1) ~= "." then
          members[#members + 1] = { dir = sub, cargo = probes.exists(sub .. "/Cargo.toml") }
        end
        scan(sub, d + 1)
        if truncated then
          return
        end
      end
    end
  end
  scan(project, 0)
  return { gits = gits, members = members, truncated = truncated }
end

local function own_project_dirs(probes, home, project, cwd)
  local out, seen = {}, {}
  for _, d in ipairs({ project, cwd, probes.realpath(project) or project, probes.realpath(cwd) or cwd }) do
    local dir = home .. "/.claude/projects/" .. claude_project_name(d)
    if not seen[dir] then
      seen[dir] = true
      out[#out + 1] = dir
    end
  end
  return out
end

--- The permission-bypass flag in `cmd`, or nil.
function M.skip_flag(cmd)
  for _, a in ipairs(cmd or {}) do
    if vim.tbl_contains(M.SKIP_PERMISSIONS_FLAGS, a) then
      return a
    end
  end
end

-- --------------------------------------------------------------- exceptions

M.EXCEPTION_KINDS = { env = true, unhide = true, writable = true }

--- May this exception be applied? Pure. `ctx` = { home, state_dir?, probes }.
--- @return boolean ok, string? reason
function M.validate_exception(exc, ctx)
  if type(exc) ~= "table" or not M.EXCEPTION_KINDS[exc.kind] then
    return false, "unknown exception kind " .. vim.inspect(exc and exc.kind)
  end
  local v = exc.value
  if type(v) ~= "string" or v == "" then
    return false, "empty value"
  end
  if exc.kind == "env" then
    if not v:match("^[%a_][%w_]*$") then
      return false, "not an environment variable name: " .. v
    end
    return true
  end
  local p = M.normalize(v)
  if not p then
    return false, "not an absolute path without '..': " .. v
  end
  if p == "/" or p == ctx.home then
    return false, "refusing to expose " .. p .. " as a whole"
  end
  if exc.kind == "writable" then
    if not ctx.probes.exists(p) then
      return false, "does not exist: " .. p
    end
    if ctx.state_dir and (inside(p, ctx.state_dir) or inside(ctx.state_dir, p)) then
      return false, "the approvals and the log live there: " .. p
    end
  end
  return true
end

-- ------------------------------------------------------------------ build

local function resolve_user_path(p, home, project)
  if p:sub(1, 2) == "~/" then
    return home .. p:sub(2)
  elseif p:sub(1, 1) == "/" then
    return M.normalize(p)
  end
  return project .. "/" .. p
end

--- Build the plan. Pure: see the file header.
--- @param input table
--- @return table plan
function M.build(input)
  local probes = input.probes or M.real_probes()
  local env = input.env or {}
  local home = assert(input.home, "plan.build: home is required")
  local project = assert(input.project, "plan.build: project is required")
  local tmp_dir = assert(input.tmp_dir, "plan.build: tmp_dir is required")
  local cfg = input.config or {}
  local policy = cfg.policy or {}
  local aux = input.aux or {}
  local exists = probes.exists
  local cwd = input.cwd or project
  local at_home = project == home or project == "/"

  local plan = {
    version = 1,
    mode = "bwrap",
    project = project,
    tmp_dir = tmp_dir,
    home = home,
    flags = copy_list(M.ISOLATION_FLAGS),
    network = "open",
    writable = {},
    hidden = {},
    readonly = {},
    masks = {},
    guard_files = {},
    ephemeral = {},
    env_strip = {},
    env_kept = {},
    exceptions = {},
    rejected = {},
    notes = {},
    needs = { mkdir = {}, empty_file = nil, claude_json = nil },
    projects = nil,
    claude_json = nil,
  }

  -- applicable exceptions
  local exc_by = { env = {}, unhide = {}, writable = {} }
  local vctx = { home = home, state_dir = input.state_dir, probes = probes }
  for _, e in ipairs(input.exceptions or {}) do
    local ok, why = M.validate_exception(e, vctx)
    if ok then
      local val = e.kind == "env" and e.value or M.normalize(e.value)
      if not exc_by[e.kind][val] then
        exc_by[e.kind][val] = true
        plan.exceptions[#plan.exceptions + 1] = { kind = e.kind, value = val, scope = e.scope }
      end
    else
      plan.rejected[#plan.rejected + 1] = { kind = e.kind, value = e.value, reason = why }
    end
  end

  -- ~/.claude is created by the launcher (the masks inside it need the parent)
  plan.needs.mkdir[#plan.needs.mkdir + 1] = home .. "/.claude"
  local claude_dir = exists(home .. "/.claude") or input.assume_claude_dir ~= false

  -- the agent command
  local cmd = copy_list(input.cmd or {})
  local skip = {}
  for _, f in ipairs(M.SKIP_PERMISSIONS_FLAGS) do
    skip[f] = true
  end
  local has_flag = M.skip_flag(cmd)
  plan.agent = { cmd = cmd, skip_permissions = has_flag ~= nil, flag = has_flag, stripped = false }
  if has_flag and cfg.strip_skip_permissions == true then
    local kept = {}
    for _, a in ipairs(cmd) do
      if not skip[a] then
        kept[#kept + 1] = a
      end
    end
    plan.agent.cmd = kept
    plan.agent.skip_permissions = false
    plan.agent.stripped = true
  end

  -- environment
  local file_login = input.file_login
  if file_login == nil then
    file_login = exists(home .. "/.claude/.credentials.json")
  end
  for _, n in ipairs(M.scrub_names(env, file_login, policy.scrub)) do
    if exc_by.env[n] then
      plan.env_kept[#plan.env_kept + 1] = n
    else
      plan.env_strip[#plan.env_strip + 1] = n
    end
  end

  -- writable
  local function writable(p, why)
    -- ~/.claude is created by the launcher before bwrap runs, so it counts as present
    if exists(p) or (p == home .. "/.claude" and claude_dir) then
      plan.writable[#plan.writable + 1] = { path = p, why = why }
    end
  end
  if not at_home then
    writable(project, "project")
  end
  writable(tmp_dir, "scratch")
  for _, rel in ipairs(M.WRITABLE) do
    writable(home .. rel, "agent/cargo cache")
  end
  for _, p in ipairs(policy.writable or {}) do
    local rp = resolve_user_path(p, home, project)
    if rp then
      writable(rp, "policy.writable")
    end
  end
  for _, e in ipairs(plan.exceptions) do
    if e.kind == "writable" then
      writable(e.value, "approved exception")
    end
  end

  -- hidden
  local function hide(p, why)
    local ty = probes.stat_type(p)
    if ty and not exc_by.unhide[p] then
      local kind = ty == "directory" and "dir" or "file"
      plan.hidden[#plan.hidden + 1] = { path = p, kind = kind, why = why }
      if kind == "file" then
        plan.needs.empty_file = aux.empty
      end
    end
  end
  for _, p in ipairs(M.hidden_system(input.uid or -1)) do
    hide(p, "system socket / session")
  end
  for _, p in ipairs(M.HIDDEN) do
    hide(home .. p, "credentials")
  end
  for _, g in ipairs(M.HIDDEN_GLOBS) do
    for _, p in ipairs(probes.glob(home .. g)) do
      hide(p, "history")
    end
  end
  for _, p in ipairs(policy.hidden or {}) do
    local rp = resolve_user_path(p, home, project)
    if rp then
      hide(rp, "policy.hidden")
    end
  end

  -- ~/.claude.json: a private copy
  local cj = home .. "/.claude.json"
  if exists(cj) and aux.claude_json then
    plan.claude_json = { src = cj, copy = aux.claude_json }
    plan.needs.claude_json = plan.claude_json
  end

  -- ~/.claude/projects: read-only except this project's own transcript dirs
  local own = own_project_dirs(probes, home, project, cwd)
  plan.projects = { dir = home .. "/.claude/projects", own = own }
  plan.needs.mkdir[#plan.needs.mkdir + 1] = plan.projects.dir
  for _, d in ipairs(own) do
    plan.needs.mkdir[#plan.needs.mkdir + 1] = d
  end

  -- read-only locks
  local seen = {}
  local function lock(p, why)
    if not seen[p] and exists(p) then
      seen[p] = true
      plan.readonly[#plan.readonly + 1] = { path = p, why = why }
    end
  end
  local w = walk(probes, project, tonumber(policy.scan_depth) or M.SCAN_DEPTH)
  if w.truncated then
    plan.notes[#plan.notes + 1] = ("directory walk stopped after %d directories: deeper .git and member"
      .. " directories are not locked"):format(M.SCAN_MAX_DIRS)
  end
  for _, p in ipairs(w.gits) do
    lock(p, "git")
  end
  if not at_home then
    for _, rel in ipairs(M.PROJECT_READONLY) do
      lock(project .. "/" .. rel, "project")
    end
    for _, rel in ipairs(policy.readonly or {}) do
      local rp = resolve_user_path(rel, home, project)
      if rp then
        lock(rp, "policy.readonly")
      end
    end
  else
    for _, rel in ipairs(policy.readonly or {}) do
      if rel:sub(1, 1) == "/" or rel:sub(1, 2) == "~/" then
        lock(resolve_user_path(rel, home, project), "policy.readonly")
      end
    end
  end
  local masks = {}
  local function mask(p, why, absent_project)
    masks[#masks + 1] = { path = p, why = why, cleanup = absent_project or nil }
  end
  if not at_home then
    for _, m in ipairs(w.members) do
      for _, rel in ipairs(M.MEMBER_READONLY) do
        lock(m.dir .. "/" .. rel, "member")
      end
      if m.cargo and not exists(m.dir .. "/.cargo") then
        mask(m.dir .. "/.cargo", "member .cargo", true)
      end
    end
  end
  for _, rel in ipairs(M.HOME_READONLY) do
    lock(home .. rel, "agent config")
  end
  for _, p in ipairs(probes.glob(home .. "/.claude/projects/*/memory")) do
    lock(p, "agent memory") -- MEMORY.md auto-loads into the next unsandboxed session
  end
  if claude_dir then
    for _, d in ipairs(own) do
      local mem = d .. "/memory"
      if not seen[mem] and not exists(mem) then
        seen[mem] = true
        mask(mem, "agent memory")
      end
    end
  end
  if not at_home then
    for _, rel in ipairs(M.PROJECT_MASK_IF_ABSENT) do
      if not exists(project .. "/" .. rel) then
        mask(project .. "/" .. rel, "absent " .. rel, true)
      end
    end
    for _, rel in ipairs(policy.guard_dirs or {}) do
      local rp = resolve_user_path(rel, home, project)
      if rp and not exists(rp) then
        mask(rp, "policy.guard_dirs", inside(rp, project))
      end
    end
    if not exists(project .. "/" .. M.PROJECT_MASKED) then
      mask(project .. "/" .. M.PROJECT_MASKED, "absent " .. M.PROJECT_MASKED, true)
    else
      lock(project .. "/" .. M.PROJECT_MASKED, "project")
    end
    -- absent files that would run unsandboxed when planted
    local gf = copy_list(M.PROJECT_GUARD_FILES)
    for _, rel in ipairs(policy.guard_files or {}) do
      gf[#gf + 1] = rel
    end
    local gseen = {}
    for _, rel in ipairs(gf) do
      local rp = resolve_user_path(rel, home, project)
      if rp and not gseen[rp] and not exists(rp) and aux.empty then
        gseen[rp] = true
        plan.guard_files[#plan.guard_files + 1] = { path = rp, why = "absent " .. rel, cleanup = inside(rp, project) or nil }
        plan.needs.empty_file = aux.empty
      end
    end
  end
  for _, rel in ipairs(M.HOME_MASK_IF_ABSENT) do
    if not exists(home .. rel) then
      mask(home .. rel, "absent agent config")
    end
  end
  plan.masks = masks
  for _, rel in ipairs(M.HOME_EPHEMERAL) do
    if exists(home .. rel) then
      plan.ephemeral[#plan.ephemeral + 1] = home .. rel
    end
  end

  -- git directories locked (a view of readonly for the preview)
  plan.git_locked = {}
  for _, r in ipairs(plan.readonly) do
    if r.why == "git" then
      plan.git_locked[#plan.git_locked + 1] = r.path
    end
  end
  for _, m in ipairs(plan.masks) do
    if m.why == "absent .git" then
      plan.git_locked[#plan.git_locked + 1] = m.path
    end
  end

  -- cwd inside the project, else the project
  local ins = cwd == project or project == "/" or cwd:sub(1, #project + 1) == project .. "/"
  plan.chdir = ins and cwd or project
  plan.empty_file = plan.needs.empty_file
  return plan
end

-- -------------------------------------------------------------------- argv

--- bwrap flags of the isolation, without any path (also what the readiness probe runs).
function M.probe_argv()
  local a = { "bwrap" }
  vim.list_extend(a, M.ISOLATION_FLAGS)
  vim.list_extend(a, { "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "true" })
  return a
end

--- The bwrap command line of a plan. Pure and deterministic: the same plan gives the same list.
--- @param plan table
--- @return string[]
function M.argv(plan)
  assert(plan.mode == "bwrap", "plan.argv: not a bwrap plan")
  assert(plan.empty_file or (#plan.guard_files == 0 and not plan.needs.empty_file), "plan.argv: aux.empty is missing")
  local a = { "bwrap" }
  vim.list_extend(a, plan.flags)
  vim.list_extend(a, { "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp" })
  for _, n in ipairs(plan.env_strip) do
    vim.list_extend(a, { "--unsetenv", n })
  end
  for _, w in ipairs(plan.writable) do
    vim.list_extend(a, { "--bind", w.path, w.path })
  end
  -- after the writable binds: hides inside ~/.claude must sit on top of it
  for _, h in ipairs(plan.hidden) do
    vim.list_extend(a, h.kind == "dir" and { "--tmpfs", h.path } or { "--ro-bind", plan.empty_file, h.path })
  end
  if plan.claude_json then
    vim.list_extend(a, { "--bind", plan.claude_json.copy, plan.claude_json.src })
  end
  -- ~/.claude/projects is read-only except this project's own transcript dirs: a bind mount
  -- point cannot be renamed, so `mv projects/<name> ...; mkdir -p projects/<name>/memory`
  -- cannot get round the memory mask
  vim.list_extend(a, { "--ro-bind", plan.projects.dir, plan.projects.dir })
  for _, d in ipairs(plan.projects.own) do
    vim.list_extend(a, { "--bind", d, d })
  end
  for _, r in ipairs(plan.readonly) do
    vim.list_extend(a, { "--ro-bind", r.path, r.path })
  end
  for _, m in ipairs(plan.masks) do
    -- project-relative masks (.cargo, .claude) would hit $HOME's own when the project is $HOME;
    -- the planner already left those out
    vim.list_extend(a, { "--tmpfs", m.path, "--remount-ro", m.path })
  end
  for _, g in ipairs(plan.guard_files) do
    vim.list_extend(a, { "--ro-bind", plan.empty_file, g.path })
  end
  for _, p in ipairs(plan.ephemeral) do
    vim.list_extend(a, { "--tmpfs", p })
  end
  vim.list_extend(a, { "--chdir", plan.chdir, "--" })
  return vim.list_extend(a, plan.agent.cmd)
end

return M
