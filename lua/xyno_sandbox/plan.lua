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
  "/.claude/.credentials.json", -- the login: the sandbox may use it, not rewrite it (the allowlist view binds it read-only too)
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
  -- editors and tools of other people on the team that act outside the sandbox: Zed tasks, JetBrains run
  -- configurations, Helix language servers, husky hooks (core.hooksPath), pre-commit hooks, dev containers,
  -- debugger init files
  ".zed", ".idea", ".helix", ".husky", ".devcontainer", ".pre-commit-config.yaml", ".lldbinit", ".gdbinit",
}
-- Locked in every subdirectory the project walk found (when PRESENT there): cargo reads .cargo/config from
-- every ancestor of the directory it runs in, direnv the nearest .envrc, claude the .claude of its
-- directory, the editors their own. A file that is ABSENT there can still be created (one mount per
-- directory and name would be thousands): the run reports those when it ends, see M.WATCH_NAMES.
M.MEMBER_READONLY = {
  ".cargo", ".envrc", ".mise.toml", ".nvim.lua", ".nvimrc", ".exrc", ".claude", ".mcp.json", ".vscode", ".zed", ".idea",
  ".helix", ".husky", ".devcontainer", ".pre-commit-config.yaml", ".lldbinit", ".gdbinit",
}
-- Names that act outside the sandbox when the agent creates them in a subdirectory: looked for at launch
-- and again when the run ends, and a new one is reported (not prevented, not removed).
M.WATCH_NAMES = vim.list_extend({ ".git" }, M.MEMBER_READONLY)
M.WATCH_DIRS_MAX = 400
-- Created empty-and-read-only when absent at the project root: a planted .cargo/config.toml is
-- the one that bites. .git too: without one the agent ran `git init` and planted
-- `core.fsmonitor = <cmd>` in .git/config, which the user's next unsandboxed `git status`
-- executed. .vscode: a planted tasks.json runs from the user's editor. The launcher removes the
-- empty leftovers when the run ends (see xyno_sandbox.wrap, handle.release).
M.PROJECT_MASK_IF_ABSENT = { ".cargo", ".git", ".vscode", ".zed", ".idea", ".helix", ".husky", ".devcontainer" }
-- Files that run unsandboxed later when planted. When absent they are bound to an empty
-- read-only file for the run (the launcher removes the placeholder afterwards).
M.PROJECT_GUARD_FILES = { ".envrc", ".mise.toml", ".nvim.lua", ".nvimrc", ".exrc", ".mcp.json", ".pre-commit-config.yaml", ".lldbinit", ".gdbinit" }
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
  -- package-index logins and key files of tools that are not in the list above
  "/.config/sops", "/.gem/credentials", "/.config/pypoetry/auth.toml", "/.pip/pip.conf", "/.config/pip/pip.conf", "/.npm/_logs",
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
-- Host directories replaced by an empty tmpfs: pathname unix sockets (ssh-agent, systemd varlink,
-- polkit, journal, dbus, docker, the user session in /run/user/<uid>, tmux, X11) bypass the network
-- filter and are not governed by file permissions the way the sandbox is, so none of these
-- directories is visible at all. Only what is explicitly kept (M.RUN_KEEP, policy.keep_run) is
-- bound back, read-only. /tmp is always an empty tmpfs (see M.argv).
M.MASKED_SYSTEM = { "/run", "/var/tmp" }
-- /var/run is a symlink to /run nearly everywhere; when it is a real directory it is masked too.
M.MASKED_IF_DIR = { "/var/run" }
-- Re-bound read-only under the masked /run when present (they hold no sockets): the NixOS system
-- profile that PATH points into, and its graphics drivers.
M.RUN_KEEP = { "/run/current-system", "/run/booted-system", "/run/opengl-driver" }
-- Environment variables that name a socket or directory the agent could be reached through; the
-- path is hidden as well when it lives outside the masked directories.
M.SOCKET_ENV = { "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY", "NVIM", "NVIM_LISTEN_ADDRESS" }

-- $HOME in "allowlist" mode (the default): $HOME is an empty tmpfs and only these paths (when they
-- exist) are bound back read-only, plus the project, the scratch directory, the writable agent and
-- cargo caches, the directory of the agent binary and the directories on $PATH that live under
-- $HOME. Credentials inside them (~/.cargo/credentials, ~/.config/git/credentials) stay hidden.
M.HOME_ALLOW = {
  "/.cargo", "/.rustup", -- toolchains (registry and git are writable, see WRITABLE)
  "/.local/share/claude", -- the agent binary
  "/.gitconfig", "/.config/git", -- git identity and settings
}

-- Toolchain directories named by environment variables; shown read-only (when they are under $HOME).
M.HOME_ALLOW_ENV = {
  "CARGO_HOME", "RUSTUP_HOME", "GOROOT", "GOPATH", "GOBIN", "NVM_DIR", "PYENV_ROOT", "VOLTA_HOME", "BUN_INSTALL",
  "DENO_INSTALL", "SDKMAN_DIR", "JAVA_HOME", "ANDROID_HOME", "ASDF_DIR", "ASDF_DATA_DIR", "MISE_DATA_DIR",
  "N_PREFIX", "PNPM_HOME", "RBENV_ROOT", "FNM_DIR", "NPM_CONFIG_PREFIX", "DOTNET_ROOT", "FLUTTER_ROOT",
}

-- Project secrets (matched against the lower-cased base name, `*` = any characters): hidden with
-- an empty read-only file. Templates (.env.example ...) are not secrets and stay readable.
M.PROJECT_SECRET_GLOBS = {
  ".env", ".env.*", "*.env", ".envrc.local", ".npmrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc",
  ".git-credentials", ".dockercfg", ".htpasswd", "credentials", "credentials.*", "secrets", "secrets.*",
  "secret.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "id_rsa", "id_dsa",
  "id_ecdsa", "id_ed25519", "*service-account*.json", "*service_account*.json", "client_secret*.json", "*-credentials.json",
  "*.tfvars", "terraform.tfstate", "terraform.tfstate.*", "*.tfstate", "kubeconfig", "*.kubeconfig",
  -- frameworks and clouds
  ".dev.vars", ".dev.vars.*", -- Cloudflare Workers
  "serviceaccountkey.json", "*serviceaccountkey*.json", "firebase-adminsdk*.json", "google-services.json",
  "googleservice-info.plist", "gha-creds-*.json", "credentials.tfrc.json", -- Firebase, Google, GitHub Actions, Terraform
  "wp-config.php", "wp-config-*.php", "local.settings.json", -- WordPress, Azure Functions
  "token", "tokens", "api_key", "api_keys", "apikey", "apikeys", "api-key", "api-keys", "password", "passwords", "passwd",
  "application-prod.*", "application-production.*", "appsettings.production.json", "appsettings.secrets.json",
  "master.key", "*.key.pem", "secrets.yml", "secrets.yaml", "secrets.json", "secrets.toml", ".secrets", -- Spring, .NET, Rails, generic
  "keystore.properties", "gradle.properties.local", "*.ppk", "*.p8", "*.pkcs12", "*.mobileprovision.secret",
  -- client configs that keep a password or token
  ".pgpass", ".my.cnf", ".mylogin.cnf", ".s3cfg", ".boto", ".yarnrc", ".sentryclirc", ".vault_pass", ".vault-password",
  "vault_pass*", "vault-password*", ".git-credentials", ".gem-credentials", "oauth2.json", "client_secrets.json",
  -- tool tokens and logins, editor backups of secrets, key variants
  ".vault-token", ".env~", ".env*~", ".secret", ".npmrc.*", ".npmrc~", ".pypirc.*", "auth.json", "rclone.conf", ".terraformrc",
  "terraform.rc", "creds.json", "creds.yml", "creds.yaml", "oauth_token", "oauth_token.*", "oauth-token", "wallet.dat",
  "sa.json", "serviceaccount.json", "*serviceaccount*.json", "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
  "*.pem.*", "*.key.*", "*.key~", "*.keystore.*", "*.jks.*", ".s3cfg.*", ".pgpass.*", "secret", "private.key", "private_key",
  "private_key.*", "privatekey.*",
}
-- Secrets that a base name alone cannot say (config.json): matched as the END of the path, lower-cased.
M.PROJECT_SECRET_PATHS = {
  ".docker/config.json", ".config/gh/hosts.yml", ".config/gh/config.yml", ".composer/auth.json", ".m2/settings.xml",
  ".m2/settings-security.xml", ".gradle/gradle.properties", ".cargo/credentials", ".cargo/credentials.toml", ".kube/config",
  ".config/gcloud/credentials.db", ".config/gcloud/application_default_credentials.json", ".azure/accesstokens.json",
  ".bundle/config", ".config/pip/pip.conf", ".config/helm/repositories.yaml", ".config/rclone/rclone.conf",
}
-- Names that mean "a secret" only as a data file: token.txt, api_keys.json ... but not tokenizer.rs or
-- api_key.rs (source code that merely handles keys stays readable).
do
  local bases = { "token", "tokens", "api_key", "api_keys", "apikey", "apikeys", "api-key", "api-keys", "password", "passwords",
    "passwd", "secret", "private_key", "privatekey", "access_token", "auth_token", "bearer_token" }
  local exts = { "txt", "json", "yml", "yaml", "ini", "cfg", "conf", "properties", "toml", "env", "dat", "text" }
  for _, b in ipairs(bases) do
    for _, e in ipairs(exts) do
      M.PROJECT_SECRET_GLOBS[#M.PROJECT_SECRET_GLOBS + 1] = b .. "." .. e
    end
  end
end
M.PROJECT_SECRET_EXCEPT = {
  ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults", ".env.schema", ".env.tpl",
  ".env.local.example", ".env.test.example", "example.env", "sample.env", "template.env",
}
-- Directories of that kind inside a project (hidden with an empty tmpfs).
M.PROJECT_SECRET_DIRS = { ".aws", ".ssh", ".gnupg", ".kube", ".azure", ".envs", ".secrets" }
-- Extra directory names that are hidden inside the TOOLCHAIN trees the sandbox shows from $HOME
-- (never inside the project, where a `secrets/` directory can be source code).
M.TREE_SECRET_DIRS = { ".aws", ".ssh", ".gnupg", ".kube", ".azure", ".envs", ".secrets", "secrets", "secret", ".secret", ".private", "private-keys" }
-- Directories the tree walk does not enter: package caches and build output (large, and no credentials of the user's).
M.TREE_SKIP = { registry = true, git = true, toolchains = true, node_modules = true, target = true, [".git"] = true, ["site-packages"] = true, pkg = true }

-- Exceptions that are refused outright (a decision, not a policy knob).
M.WRITABLE_FORBIDDEN = { "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/proc", "/sys", "/dev", "/run", "/var/run", "/root" }
-- Shared system directories that are refused as a whole (a project directory BELOW them is fine): a
-- writable bind of one would expose every other user's and every other program's files in it.
M.WRITABLE_FORBIDDEN_EXACT = {
  "/tmp", "/var", "/var/tmp", "/var/lib", "/var/cache", "/var/log", "/var/spool", "/mnt", "/media", "/srv", "/opt",
  "/home", "/dev/shm", "/nix", "/lost+found",
}
-- Under $HOME: files and directories that run, or steer tools, outside the sandbox later. The list
-- is GENERATED from the categories below (documented in the README): a path is a member when some
-- program of the user's, started later and outside the sandbox, reads it and ACTS on it (executes
-- it, sources it, loads it as a plugin or hook, takes a command line from it). A writable approval
-- is refused for such a path, for anything below it and for every parent of it (a writable
-- ~/.config would contain ~/.config/nvim). There is no override for this: expert_exceptions only
-- concerns environment variables.
M.CODE_RUNS_OUTSIDE = {
  { category = "shell startup files", paths = {
    "/.bashrc", "/.bash_profile", "/.bash_login", "/.bash_logout", "/.bash_aliases", "/.profile", "/.zshrc", "/.zshenv",
    "/.zprofile", "/.zlogin", "/.zlogout", "/.zsh", "/.zim", "/.zimrc", "/.oh-my-zsh", "/.inputrc", "/.config/zsh",
    "/.config/fish", "/.config/nushell", "/.config/xonsh", "/.xonshrc", "/.config/elvish", "/.cshrc", "/.tcshrc", "/.kshrc",
    "/.config/starship.toml", "/.pam_environment", "/.config/environment.d" } },
  { category = "login session and desktop", paths = {
    "/.xinitrc", "/.xprofile", "/.xsession", "/.xsessionrc", "/.Xresources", "/.Xdefaults", "/.config/autostart",
    "/.config/systemd", "/.local/share/systemd", "/.config/plasma-workspace", "/.config/i3", "/.config/sway",
    "/.config/hypr", "/.config/bspwm", "/.config/sxhkd", "/.config/awesome", "/.config/openbox", "/.config/xfce4",
    "/.local/share/applications", "/.local/share/dbus-1", "/.config/dbus-1", "/.local/share/gnome-shell" } },
  { category = "git", paths = { "/.gitconfig", "/.config/git", "/.git-templates", "/.config/gh" } },
  { category = "remote access", paths = { "/.ssh", "/.gnupg" } },
  { category = "editors and their plugins", paths = {
    "/.config/nvim", "/.local/share/nvim", "/.vim", "/.vimrc", "/.config/vim", "/.emacs", "/.emacs.d",
    "/.config/emacs", "/.config/helix", "/.config/zed", "/.local/share/zed", "/.config/Code", "/.config/Code - OSS",
    "/.config/VSCodium", "/.config/Cursor", "/.vscode", "/.vscode-oss", "/.cursor", "/.config/JetBrains", "/.config/sublime-text",
    "/.config/micro", "/.nanorc", "/.config/nano" } },
  { category = "terminals and multiplexers", paths = {
    "/.tmux.conf", "/.tmux", "/.config/tmux", "/.screenrc", "/.config/kitty", "/.config/alacritty", "/.config/wezterm",
    "/.wezterm.lua", "/.config/ghostty", "/.config/foot", "/.config/zellij" } },
  { category = "environment and version managers", paths = {
    "/.config/direnv", "/.local/share/direnv", "/.direnvrc", "/.config/mise", "/.local/share/mise", "/.mise.toml", "/.tool-versions",
    "/.asdf", "/.asdfrc", "/.config/asdf", "/.pyenv", "/.rbenv", "/.nvm", "/.sdkman", "/.jenv", "/.goenv", "/.nodenv", "/.volta",
    "/.config/nix", "/.nix-profile", "/.nix-defexpr", "/.config/home-manager", "/.config/nixpkgs", "/.config/devbox" } },
  { category = "toolchains and package manager configuration", paths = {
    "/.local/bin", "/bin", "/.cargo/bin", "/.cargo/config", "/.cargo/config.toml", "/.cargo/env", "/.rustup", "/go/bin",
    "/.npmrc", "/.yarnrc", "/.yarnrc.yml", "/.npm-global", "/.config/pip", "/.pip", "/.config/uv", "/.config/pypoetry",
    "/.gradle/init.d", "/.gradle/gradle.properties", "/.m2/settings.xml", "/.m2/toolchains.xml", "/.bunfig.toml", "/.bun/bin",
    "/.deno/bin", "/.config/conda", "/.condarc", "/.conda", "/.config/containers", "/.docker/config.json", "/.docker/cli-plugins" } },
  { category = "agents: hooks, commands, MCP servers", paths = {
    "/.claude/settings.json", "/.claude/settings.local.json", "/.claude/hooks", "/.claude/commands", "/.claude/agents",
    "/.claude/skills", "/.claude/plugins", "/.claude/CLAUDE.md", "/.claude/keybindings.json", "/.claude/.credentials.json", "/.claude.json", "/.mcp.json",
    "/.codex", "/.gemini", "/.config/opencode", "/.aider.conf.yml", "/.config/goose", "/.config/claude" } },
}
M.WRITABLE_FORBIDDEN_HOME = {}
for _, group in ipairs(M.CODE_RUNS_OUTSIDE) do
  for _, rel in ipairs(group.paths) do
    M.WRITABLE_FORBIDDEN_HOME[#M.WRITABLE_FORBIDDEN_HOME + 1] = rel
  end
end
-- The same, with the category (for the refusal message).
local function code_runs_category(rel)
  for _, group in ipairs(M.CODE_RUNS_OUTSIDE) do
    for _, r in ipairs(group.paths) do
      if r == rel then
        return group.category
      end
    end
  end
end
-- System secrets that "unhide" never reveals.
M.UNHIDE_FORBIDDEN = { "/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/security", "/root" }
-- Environment variables that decide which code runs; "env" exceptions for them need the expert flag.
M.ENV_DANGEROUS_EXACT = {
  PATH = true, LD_PRELOAD = true, LD_LIBRARY_PATH = true, LD_AUDIT = true, LD_DEBUG_OUTPUT = true, BASH_ENV = true,
  ENV = true, PYTHONPATH = true, PYTHONSTARTUP = true, PYTHONHOME = true, NODE_OPTIONS = true, NODE_PATH = true,
  PERL5OPT = true, PERL5LIB = true, RUBYOPT = true, RUBYLIB = true, GIT_SSH_COMMAND = true, GIT_EXEC_PATH = true,
  CARGO_BUILD_RUSTC_WRAPPER = true, RUSTC_WRAPPER = true, RUSTC_WORKSPACE_WRAPPER = true, RUSTFLAGS = true,
  SHELLOPTS = true, PS4 = true, PROMPT_COMMAND = true, IFS = true, HOME = true, SHELL = true,
}
M.ENV_DANGEROUS_PREFIX = { "LD_", "DYLD_", "BASH_FUNC_" }

-- Environment scrub: any variable whose name contains one of these ...
M.ENV_CONTAINS = {
  "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "CREDENTIAL", "PRIVATE_KEY",
  "ACCESS_KEY", "AUTH_SOCK", "AGENT_INFO", "PASSPHRASE", "ASKPASS", "JWT", "COOKIE", "BEARER",
}
-- ... or ends with one of these (OPENROUTER_KEY, SENTRY_DSN, BW_SESSION, ...) ...
M.ENV_SUFFIX = { "_KEY", "_DSN", "_SESSION", "_AUTH", "_PWD", "_PASS", "_SECRETS" }
-- ... except these, which a desktop session sets and which hold no secret.
M.ENV_SUFFIX_OK = { DESKTOP_SESSION = true }
-- ... or starts with one of these ...
M.ENV_PREFIX = {
  "AWS_", "AZURE_", "GOOGLE_", "GCP_", "GCLOUD_", "DOCKER_", "KUBE", "GH_", "GITHUB_", "GITLAB_",
  "NPM_", "CARGO_REGISTR", "VAULT_", "OPENAI_", "STRIPE_",
}
-- ... or is exactly one of these (session bus / display access).
M.ENV_EXACT = {
  DATABASE_URL = true, DBUS_SESSION_BUS_ADDRESS = true, DISPLAY = true, WAYLAND_DISPLAY = true,
  XAUTHORITY = true, SSH_AUTH_SOCK = true, GPG_AGENT_INFO = true, KUBECONFIG = true,
  NVIM = true, NVIM_LISTEN_ADDRESS = true, -- the editor's RPC socket: full control of the editor
  MYSQL_PWD = true, SSHPASS = true, -- not a "PASSWORD" by name; a bare PWD would also be the cwd
  KEY = true, DSN = true, SESSION = true, AUTH = true, SERPAPI = true, PASS = true, PGPASSFILE = true,
}
-- ... or whose VALUE looks like a secret (a known token format, a private key, credentials in a URL:
-- see xyno_sandbox.scan). The name decides first; this catches a token under a name nobody listed.
M.ENV_VALUE_SCAN = true
-- Variables claude itself authenticates with. Kept only when login is NOT file based (no
-- ~/.claude/.credentials.json); with file-based login claude never reads them.
M.ENV_CLAUDE_AUTH = { "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN" }

-- Skipped by the directory walk (still locked when they ARE the project's own .git).
M.SCAN_SKIP = {
  target = true, node_modules = true, [".git"] = true, [".cache"] = true,
  [".venv"] = true, venv = true, __pycache__ = true, [".mypy_cache"] = true, [".tox"] = true,
}
M.HARDLINK_CODE_MAX = 1500 -- files compared with the project's multi-link files (hard-link check of code that runs outside)
M.SCAN_DEPTH = 8 -- nested .git and workspace members are found down to this depth
M.TREE_DIRS_EACH = 600
M.TREE_MAX_DIRS = 2400
M.TREE_CACHE_S = 15 -- a real filesystem walk of a tree is reused this long (when the tree's top directory is unchanged) -- directories looked at in all the trees together (a count, so the result is the same every time)
M.TREE_DEPTH = 4 -- secret names are looked for this deep inside the toolchain trees shown from $HOME
M.SCAN_MAX_DIRS = 20000 -- the walk stops here and the plan says so (plan.notes)
M.SOCK_DEPTH = 24 -- sockets are looked for this deep, also inside target/ node_modules/ .cache/ .git/
M.SOCK_MAX_DIRS = 30000

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
    --- like stat_type, but a symlink is "link" (not followed)
    lstat_type = function(p)
      local st = uv.fs_lstat(p)
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
    --- { nlink, dev, ino } of a path (symlinks followed), or nil
    tree_cache = true,
    stat_info = function(p)
      local st = uv.fs_stat(p)
      return st and { nlink = st.nlink, dev = st.dev, ino = st.ino } or nil
    end,
    --- bounded scan of the project files (see xyno_sandbox.scan)
    scan_project = function(project, opts)
      return require("xyno_sandbox.scan").project(project, opts)
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
    for _, s in ipairs(M.ENV_SUFFIX) do
      hit = hit or (#u > #s and u:sub(-#s) == s and not M.ENV_SUFFIX_OK[u])
    end
    if not hit and M.ENV_VALUE_SCAN and type(env[name]) == "string" and #env[name] >= 12 and not M.ENV_DANGEROUS_EXACT[u] then
      hit = #require("xyno_sandbox.scan").text(env[name]) > 0
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

--- Lua pattern of a glob (`*` = any characters), anchored.
local function glob_pattern(g)
  return "^" .. g:gsub("[%^%$%(%)%%%.%[%]%+%-%?]", "%%%0"):gsub("%*", ".*") .. "$"
end

--- A matcher for base names: `globs` (`*` = any characters) minus `except`, case-insensitive, public keys
--- (`*.pub`) never. Built once per list: exact names are a set lookup, `prefix*` and `*suffix` are bucketed by
--- their first / last character, only the rest runs a Lua pattern. A walk over a directory of 100000 files
--- compiled every glob again for every file (18 s); this is a few hundred milliseconds.
--- @return fun(name: string): boolean
function M.secret_matcher(globs, except)
  local exact, ex_set, prefix, suffix, mixed = {}, {}, {}, {}, {}
  for _, e in ipairs(except or {}) do
    ex_set[e:lower()] = true
  end
  for _, g in ipairs(globs) do
    local l = g:lower()
    local stars = select(2, l:gsub("%*", ""))
    if stars == 0 then
      exact[l] = true
    elseif stars == 1 and l:sub(-1) == "*" and #l > 1 then
      local pre = l:sub(1, -2)
      local c = pre:sub(1, 1)
      prefix[c] = prefix[c] or {}
      table.insert(prefix[c], pre)
    elseif stars == 1 and l:sub(1, 1) == "*" and #l > 1 then
      local suf = l:sub(2)
      local c = suf:sub(-1)
      suffix[c] = suffix[c] or {}
      table.insert(suffix[c], suf)
    else
      mixed[#mixed + 1] = glob_pattern(l)
    end
  end
  return function(name)
    local n = name:lower()
    if n:sub(-4) == ".pub" or ex_set[n] then
      return false
    end
    if exact[n] then
      return true
    end
    local list = prefix[n:sub(1, 1)]
    if list then
      for _, pre in ipairs(list) do
        if n:sub(1, #pre) == pre then
          return true
        end
      end
    end
    list = suffix[n:sub(-1)]
    if list then
      for _, suf in ipairs(list) do
        if #n >= #suf and n:sub(-#suf) == suf then
          return true
        end
      end
    end
    for _, pat in ipairs(mixed) do
      if n:match(pat) then
        return true
      end
    end
    return false
  end
end

local matchers = setmetatable({}, { __mode = "k" })

--- Does base name `name` match a secret glob in `globs` (and no exception)? Case-insensitive.
function M.is_secret_name(name, globs, except)
  local c = matchers[globs]
  if not c or c.n ~= #globs or c.except ~= except or c.en ~= #(except or {}) then
    c = { n = #globs, except = except, en = #(except or {}), f = M.secret_matcher(globs, except) }
    matchers[globs] = c
  end
  return c.f(name)
end

--- One walk of the project down to `depth`: every `.git` (dir or file, plus the real gitdirs
--- behind `.git` files), every workspace-member candidate (non-hidden directory), the secret files
--- and sockets, and the symlinks.
--- @param opts? { secrets?: string[], except?: string[], secret_dirs?: string[] }
--- @return { gits: string[], members: { dir: string, cargo: boolean }[], secrets: { path: string, kind: string }[],
---   links: string[], truncated: boolean }
local function walk(probes, project, depth, opts)
  opts = opts or {}
  local gits, gseen, members = {}, {}, {}
  local secrets, links = {}, {}
  local visited, truncated = 0, false
  local skip = M.SCAN_SKIP
  local function addgit(p)
    if not gseen[p] and probes.exists(p) then
      gseen[p] = true
      gits[#gits + 1] = p
    end
  end
  local sdirs = {}
  for _, d in ipairs(opts.secret_dirs or {}) do
    sdirs[d] = true
  end
  local paths, plast = {}, {}
  for _, sfx in ipairs(opts.paths or {}) do
    paths[#paths + 1] = "/" .. sfx:lower()
    plast[sfx:lower():match("([^/]+)$")] = true -- (only a file with one of these base names can end in such a path)
  end
  -- Sockets are looked for EVERYWHERE below the project, also in the directories the rest of the walk
  -- skips (target, node_modules, .cache, .git) and below its depth: a pathname socket is connectable
  -- whatever its place. Own budget; the plan says when it ran out.
  local sock_visited, sock_truncated = 0, false
  local function sock_only(dir, d)
    if sock_truncated then
      return
    end
    if d > M.SOCK_DEPTH or sock_visited >= M.SOCK_MAX_DIRS then
      sock_truncated = true
      return
    end
    sock_visited = sock_visited + 1
    for _, e in ipairs(probes.list(dir)) do
      local name, ty = e[1], e[2]
      if ty == "socket" then
        secrets[#secrets + 1] = { path = dir .. "/" .. name, kind = "socket" }
      elseif ty == "directory" then
        sock_only(dir .. "/" .. name, d + 1)
      end
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
    local entries = probes.list(dir)
    for _, e in ipairs(entries) do
      local name, ty = e[1], e[2]
      if ty == "file" or ty == "link" then
        local hit = opts.secrets and M.is_secret_name(name, opts.secrets, opts.except)
        if not hit and #paths > 0 and plast[name:lower()] then
          local full = (dir .. "/" .. name):lower()
          for _, sfx in ipairs(paths) do
            if full:sub(-#sfx) == sfx then
              hit = true
              break
            end
          end
        end
        if hit then
          secrets[#secrets + 1] = { path = dir .. "/" .. name, kind = "file" }
        elseif ty == "link" then
          links[#links + 1] = dir .. "/" .. name
        end
      elseif ty == "socket" then
        secrets[#secrets + 1] = { path = dir .. "/" .. name, kind = "socket" }
      elseif ty == "directory" and sdirs[name] then
        secrets[#secrets + 1] = { path = dir .. "/" .. name, kind = "dir" }
      end
    end
    for _, e in ipairs(entries) do
      local name, ty = e[1], e[2]
      if ty == "directory" and not sdirs[name] then
        local sub = dir .. "/" .. name
        if d >= depth or skip[name] then
          sock_only(sub, d + 1)
        else
          visited = visited + 1
          if visited > M.SCAN_MAX_DIRS then
            truncated = true
            return
          end
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
  end
  scan(project, 0)
  return { gits = gits, members = members, secrets = secrets, links = links, truncated = truncated, sock_truncated = sock_truncated }
end

--- Secret names inside a toolchain tree shown from $HOME: breadth first (the top of the tree is always
--- looked at), `budget.dirs` directories in all, deterministic (a count, never a clock).
--- @return { path: string, kind: string }[] secrets, boolean truncated
local tree_cache = {}
local function walk_tree(probes, root, depth, opts, budget)
  local secrets, truncated, used = {}, false, 0
  local sdirs = {}
  for _, d in ipairs(M.TREE_SECRET_DIRS) do
    sdirs[d] = true
  end
  local paths, plast = {}, {}
  for _, sfx in ipairs(M.PROJECT_SECRET_PATHS) do
    paths[#paths + 1] = "/" .. sfx:lower()
    plast[sfx:lower():match("([^/]+)$")] = true
  end
  local queue, qi = { { root, 0 } }, 1
  while qi <= #queue do
    local dir, d = queue[qi][1], queue[qi][2]
    qi = qi + 1
    if budget.dirs <= 0 or used >= M.TREE_DIRS_EACH then
      truncated = true
      break
    end
    budget.dirs = budget.dirs - 1
    used = used + 1
    for _, e in ipairs(probes.list(dir)) do
      local name, ty = e[1], e[2]
      local full = dir .. "/" .. name
      if ty == "file" or ty == "link" then
        local hit = M.is_secret_name(name, opts.globs, opts.except)
        if not hit and plast[name:lower()] then
          local low = full:lower()
          for _, sfx in ipairs(paths) do
            if low:sub(-#sfx) == sfx then
              hit = true
              break
            end
          end
        end
        if hit then
          secrets[#secrets + 1] = { path = full, kind = "file" }
        end
      elseif ty == "socket" then
        secrets[#secrets + 1] = { path = full, kind = "socket" }
      elseif ty == "directory" then
        if sdirs[name] then
          secrets[#secrets + 1] = { path = full, kind = "dir" }
        elseif d < depth and not M.TREE_SKIP[name] then
          queue[#queue + 1] = { full, d + 1 }
        end
      end
    end
  end
  return secrets, truncated
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

M.EXCEPTION_KINDS = { env = true, unhide = true, writable = true, host = true }

local function dirname(p)
  local d = p:gsub("/[^/]*$", "")
  return d == "" and "/" or d
end

--- The overlay of `plan` (a read-only, hidden, masked or ephemeral mount applied AFTER the
--- writable binds) that covers `p`, or nil. A writable bind of such a path has no effect: the later
--- mount wins.
function M.shadow(plan, p)
  for _, list in ipairs({ plan.hidden or {}, plan.readonly or {}, plan.masks or {}, plan.guard_files or {} }) do
    for _, e in ipairs(list) do
      if inside(p, e.path) then
        return e.path
      end
    end
  end
  for _, e in ipairs(plan.ephemeral or {}) do
    if inside(p, e) then
      return e
    end
  end
end

--- Why `p` must never be made writable (a string), or nil. Both directions count: the path
--- itself, or a parent that contains one of the protected places.
function M.writable_forbidden(p, home, masked)
  if p == "/" then
    return "it is the whole filesystem"
  end
  for _, d in ipairs(M.WRITABLE_FORBIDDEN) do
    if inside(p, d) then
      return d .. " is a system path"
    end
  end
  if inside(home, p) then
    return "it contains $HOME"
  end
  for _, d in ipairs(M.WRITABLE_FORBIDDEN_EXACT) do
    if p == d then
      return d .. " is a shared system directory (approve a project directory below it)"
    end
  end
  -- a parent of a directory that the sandbox replaces with an empty tmpfs: the writable bind is
  -- applied AFTER the masks, so it would bring the host's content back
  local covered = { "/tmp", "/home" }
  vim.list_extend(covered, M.MASKED_SYSTEM)
  vim.list_extend(covered, M.MASKED_IF_DIR)
  vim.list_extend(covered, masked or {})
  for _, m in ipairs(covered) do
    if inside(m, p) then
      return "it contains " .. m .. ", which the sandbox hides (a writable bind would show it again)"
    end
  end
  for _, rel in ipairs(M.WRITABLE_FORBIDDEN_HOME) do
    local f = home .. rel
    if inside(p, f) or inside(f, p) then
      return f .. " would run, or steer tools, outside the sandbox later (" .. (code_runs_category(rel) or "code") .. ")"
    end
  end
end

local function is_dangerous_env(name)
  local u = name:upper()
  if M.ENV_DANGEROUS_EXACT[u] then
    return true
  end
  for _, pre in ipairs(M.ENV_DANGEROUS_PREFIX) do
    if u:sub(1, #pre) == pre then
      return true
    end
  end
  return false
end

--- May this exception be applied, and would it change anything? Pure.
--- ctx = { home, state_dir?, probes, baseline?, expert?, scrub?, file_login? }; `baseline` is a plan
--- built without exceptions: with it, "unhide" needs a path the policy really hides and "writable"
--- one that no later read-only mount covers (an approval that cannot take effect is refused, not
--- logged as approved).
--- @return boolean ok, string? reason
function M.validate_exception(exc, ctx)
  if type(exc) ~= "table" or not M.EXCEPTION_KINDS[exc.kind] then
    return false, "unknown exception kind " .. vim.inspect(type(exc) == "table" and exc.kind or nil)
  end
  local v = exc.value
  if type(v) ~= "string" or v == "" then
    return false, "empty value"
  end
  if exc.kind == "host" then
    local ent, why = require("xyno_sandbox.net").parse_entry(v)
    if not ent then
      return false, "not an allowlist host (" .. tostring(why) .. "): " .. v
    end
    return true
  end
  if exc.kind == "env" then
    if not v:match("^[%a_][%w_]*$") then
      return false, "not an environment variable name: " .. v
    end
    if is_dangerous_env(v) and not ctx.expert then
      return false, v .. " decides which code runs inside the sandbox; refused (setup({ expert_exceptions = true }) allows it)"
    end
    if #M.scrub_names({ [v] = "x" }, ctx.file_login == true, ctx.scrub) == 0 then
      return false, v .. " is not stripped by the policy: there is nothing to let through"
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
  local real = ctx.probes.realpath and ctx.probes.realpath(p) or nil
  local candidates = { p }
  if real and real ~= p then
    candidates[#candidates + 1] = real
  end
  if exc.kind == "unhide" then
    for _, q in ipairs(candidates) do
      for _, f in ipairs(M.UNHIDE_FORBIDDEN) do
        if inside(q, f) then
          return false, "never revealed: " .. f
        end
      end
    end
    if ctx.baseline then
      local hit = false
      for _, h in ipairs(ctx.baseline.hidden or {}) do
        hit = hit or h.path == p
      end
      if not hit then
        return false, "the policy does not hide " .. p .. " (nothing to show"
          .. (ctx.baseline.home_mode == "allowlist" and "; outside the home allowlist it is not visible anyway, see policy.home_allow" or "")
          .. ")"
      end
    end
    return true
  end
  -- writable
  if not ctx.probes.exists(p) then
    return false, "does not exist: " .. p
  end
  if ctx.state_dir and (inside(p, ctx.state_dir) or inside(ctx.state_dir, p)) then
    return false, "the approvals and the log live there: " .. p
  end
  for _, q in ipairs(candidates) do
    local masked = {}
    for _, m in ipairs(ctx.baseline and ctx.baseline.masked or {}) do
      masked[#masked + 1] = m.path
    end
    local why = M.writable_forbidden(q, ctx.home, masked)
    if why then
      return false, "refused" .. (q ~= p and (" (" .. p .. " resolves to " .. q .. ")") or "") .. ": " .. why
    end
    if ctx.baseline then
      local sh = M.shadow(ctx.baseline, q)
      if sh then
        return false, "no effect: " .. sh .. " is mounted read-only afterwards and wins over a writable " .. p
      end
    end
  end
  return true
end

--- May `rel` (a path below ~/.claude) be shared read-only? Not the login (always bound), not the
--- transcripts, history or session keys, and no ".." .
function M.claude_share_ok(rel)
  if rel == "" or rel:find("..", 1, true) then
    return false
  end
  local first = rel:match("^([^/]+)")
  for _, bad in ipairs({ ".credentials.json", "projects", "history.jsonl", "daemon", "sessions", "shell-snapshots", "session-env" }) do
    if first == bad then
      return false
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

local function basename(p)
  return p:match("([^/]*)$")
end

-- Project directories that are not a project: the sandbox never mounts them writable and never
-- leaves placeholders in them (a stray empty .git in /tmp made unrelated tools think /tmp is a
-- repository).
M.SHARED_ROOTS = {
  "/", "/tmp", "/var/tmp", "/dev/shm", "/run", "/var", "/usr", "/etc", "/opt", "/srv", "/mnt", "/media",
  "/home", "/root", "/boot", "/sys", "/proc", "/dev", "/bin", "/sbin", "/lib", "/lib64", "/nix",
}

--- Is `project` a shared system directory (or a parent of $HOME)?
function M.is_shared_root(project, home, uid)
  for _, r in ipairs(M.SHARED_ROOTS) do
    if project == r then
      return true
    end
  end
  return project == "/run/user/" .. tostring(uid or -1) or (home ~= project and inside(home, project))
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
  local lstat_type = probes.lstat_type or probes.stat_type
  local cwd = input.cwd or project
  local shared = M.is_shared_root(project, home, input.uid)
  local at_home = project == home or shared
  local net_mode = cfg.network == "open" and "open" or "filtered" -- anything but "open" is filtered
  local home_mode = cfg.home == "denylist" and "denylist" or "allowlist" -- anything but "denylist" is the allowlist
  -- ~/.claude: in the allowlist view the agent gets a THROW-AWAY directory holding only its login
  -- file (read-only), this project's transcripts and the names of policy.claude_share (read-only);
  -- other projects' transcripts, settings, history and sessions are not there. The denylist view
  -- keeps the old behaviour (the whole directory, writable, with the executable parts re-locked).
  local claude_minimal = home_mode == "allowlist"

  local plan = {
    version = 2,
    mode = "bwrap",
    project = project,
    tmp_dir = tmp_dir,
    home = home,
    home_mode = home_mode,
    flags = copy_list(M.ISOLATION_FLAGS),
    network = net_mode,
    writable = {},
    hidden = {},
    readonly = {},
    masks = {},
    masked = {},
    run_keep = {},
    homes = { masked = {}, allow = {}, rebind_home = false },
    home_allow = {},
    claude = { mode = claude_minimal and "minimal" or "full", credentials = nil, shared = {} },
    symlinks = {},
    guard_files = {},
    ephemeral = {},
    env_strip = {},
    env_kept = {},
    env_pass = {},
    exceptions = {},
    rejected = {},
    notes = {},
    needs = { mkdir = {}, empty_file = nil, claude_json = nil },
    projects = nil,
    claude_json = nil,
  }
  if shared then
    plan.notes[#plan.notes + 1] = project .. " is a shared system directory (or contains $HOME): it is not mounted writable"
      .. " and no guard placeholders are created in it; start the agent in a project directory"
  end

  -- network: filtered = private network namespace + the proxy's unix socket; open = untouched
  if net_mode == "filtered" then
    local net = require("xyno_sandbox.net")
    plan.flags[#plan.flags + 1] = "--unshare-net"
    local dir = aux.net_dir or (tmp_dir .. "/.xyno-net-unset")
    local hosts, seen = {}, {}
    local list = cfg.allow_hosts
    local from_default = list == nil
    for _, h in ipairs(list or net.DEFAULT_HOSTS) do
      local ent = net.parse_entry(h)
      if ent and not seen[ent.text] then
        seen[ent.text] = true
        hosts[#hosts + 1] = { host = ent.text, why = from_default and "default" or "allow_hosts" }
      end
    end
    plan.net = {
      dir = dir, sock = dir .. "/proxy.sock", relay = dir .. "/relay.lua", port = net.PORT,
      nvim = input.nvim or "nvim", hosts = hosts, seen = seen,
    }
  end

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

  -- ~/.claude is created by the launcher (the masks inside it need the parent)
  plan.needs.mkdir[#plan.needs.mkdir + 1] = home .. "/.claude"
  local claude_dir = exists(home .. "/.claude") or input.assume_claude_dir ~= false
  local file_login = input.file_login
  if file_login == nil then
    file_login = exists(home .. "/.claude/.credentials.json")
  end

  -- applicable exceptions
  local exc_by = { env = {}, unhide = {}, writable = {}, host = {} }
  local vctx = {
    home = home, state_dir = input.state_dir, probes = probes, file_login = file_login, scrub = policy.scrub,
    expert = cfg.expert_exceptions == true,
  }
  for _, e in ipairs(input.exceptions or {}) do
    local ok, why = M.validate_exception(e, vctx)
    if ok then
      local val
      if e.kind == "env" then
        val = e.value
      elseif e.kind == "host" then
        val = require("xyno_sandbox.net").parse_entry(e.value).text
      else
        val = M.normalize(e.value)
      end
      if not exc_by[e.kind][val] then
        exc_by[e.kind][val] = true
        plan.exceptions[#plan.exceptions + 1] = { kind = e.kind, value = val, scope = e.scope }
      end
    else
      plan.rejected[#plan.rejected + 1] = { kind = e.kind, value = e.value, reason = why }
    end
  end

  if plan.net then
    for _, e in ipairs(plan.exceptions) do
      if e.kind == "host" and not plan.net.seen[e.value] then
        plan.net.seen[e.value] = true
        plan.net.hosts[#plan.net.hosts + 1] = { host = e.value, why = "approved exception" }
      end
    end
    plan.net.seen = nil
  else
    local keep = {}
    for _, e in ipairs(plan.exceptions) do
      if e.kind == "host" then
        plan.rejected[#plan.rejected + 1] = { kind = e.kind, value = e.value, reason = "the network is open, there is no allowlist" }
      else
        keep[#keep + 1] = e
      end
    end
    plan.exceptions = keep
  end

  -- environment: the scrubbed names are neither passed to bwrap nor set in the sandbox. The launch
  -- starts bwrap with ONLY env_pass (`env -i`), so a stripped value never exists in any process of
  -- the sandbox (bwrap's own environment, /proc/1/environ, included).
  local strip_set = {}
  for _, n in ipairs(M.scrub_names(env, file_login, policy.scrub)) do
    if exc_by.env[n] then
      plan.env_kept[#plan.env_kept + 1] = n
    else
      plan.env_strip[#plan.env_strip + 1] = n
      strip_set[n] = true
    end
  end
  local pass = {}
  for name, value in pairs(env) do
    if not strip_set[name] and name ~= "" and not name:find("=", 1, true) then
      pass[#pass + 1] = name
    end
  end
  table.sort(pass)
  for _, name in ipairs(pass) do
    plan.env_pass[#plan.env_pass + 1] = { name, tostring(env[name]) }
  end

  -- writable
  local function writable(p, why)
    -- ~/.claude is created by the launcher before bwrap runs, so it counts as present
    if exists(p) or (p == home .. "/.claude" and claude_dir) then
      plan.writable[#plan.writable + 1] = { path = p, why = why, exception = why == "approved exception" or nil,
        policy = why == "policy.writable" or nil }
    end
  end
  if not at_home then
    writable(project, "project")
  end
  writable(tmp_dir, "scratch")
  for _, rel in ipairs(M.WRITABLE) do
    if not (claude_minimal and rel == "/.claude") then
      writable(home .. rel, "agent/cargo cache")
    end
  end
  local cargo_home = type(env.CARGO_HOME) == "string" and M.normalize(env.CARGO_HOME) or nil
  if cargo_home and cargo_home ~= home .. "/.cargo" then
    for _, sub in ipairs({ "/registry", "/git", "/.package-cache", "/.package-cache-mutate" }) do
      writable(cargo_home .. sub, "agent/cargo cache")
    end
  end
  for _, p in ipairs(policy.writable or {}) do
    local rp = resolve_user_path(p, home, project)
    local why = rp and M.writable_forbidden(rp, home)
    if why then
      plan.notes[#plan.notes + 1] = ("policy.writable %s is ignored: %s"):format(rp, why)
    elseif rp then
      writable(rp, "policy.writable")
    end
  end
  for _, e in ipairs(plan.exceptions) do
    if e.kind == "writable" then
      writable(e.value, "approved exception")
    end
  end

  -- masked host directories (pathname sockets) and the home view
  for _, p in ipairs(M.MASKED_SYSTEM) do
    if exists(p) then
      plan.masked[#plan.masked + 1] = { path = p, why = "host sockets and services" }
    end
  end
  for _, p in ipairs(M.MASKED_IF_DIR) do
    if lstat_type(p) == "directory" then
      plan.masked[#plan.masked + 1] = { path = p, why = "host sockets and services" }
    end
  end
  local function kept(p, why)
    for _, m in ipairs(plan.masked) do
      if inside(p, m.path) and exists(p) then
        plan.run_keep[#plan.run_keep + 1] = { path = p, why = why }
        return
      end
    end
  end
  for _, p in ipairs(M.RUN_KEEP) do
    kept(p, "kept read-only (no sockets)")
  end
  for _, p in ipairs(policy.keep_run or {}) do
    local rp = resolve_user_path(p, home, project)
    if rp then
      kept(rp, "policy.keep_run")
    end
  end

  -- other users' homes (and the real passwd home when it is not $HOME): an empty tmpfs. Whatever
  -- the sandbox needs from them (the project and the writable paths come later; toolchains,
  -- $PATH entries and the agent binary are re-bound read-only below) is shown again.
  local home_roots = {}
  do
    local seen_root = {}
    local function root(p, why)
      if not p or p == "/" or seen_root[p] or not exists(p) then
        return
      end
      if lstat_type(p) == "link" then
        p = probes.realpath and probes.realpath(p) or nil
        if not p or p == "/" or seen_root[p] then
          return
        end
      end
      seen_root[p] = true
      home_roots[#home_roots + 1] = p
      plan.homes.masked[#plan.homes.masked + 1] = { path = p, why = why }
    end
    root("/home", "other users' homes")
    local pw = input.passwd_home and M.normalize(input.passwd_home)
    if pw and pw ~= home and not inside(pw, "/home") then
      root(pw, "the account's own home, which is not $HOME")
    end
  end
  local function in_home_root(p)
    for _, r in ipairs(home_roots) do
      if inside(p, r) then
        return r
      end
    end
  end
  plan.homes.rebind_home = home_mode == "denylist" and in_home_root(home) ~= nil
  if home_mode == "allowlist" then
    local aseen = {}
    local function allow(p, why)
      if not (p and p ~= home and inside(p, home) and exists(p)) then
        return
      end
      if lstat_type(p) == "link" then
        -- bwrap cannot mount on a symlink: show what it points to (the link itself is not recreated)
        local real = probes.realpath and probes.realpath(p)
        if real and real ~= p then
          return allow(real, why)
        end
        return
      end
      for covered in pairs(aseen) do
        if inside(p, covered) then
          return
        end
      end
      aseen[p] = true
      plan.home_allow[#plan.home_allow + 1] = { path = p, why = why }
    end
    for _, rel in ipairs(M.HOME_ALLOW) do
      allow(home .. rel, "toolchain / git")
    end
    for _, p in ipairs(policy.home_allow or {}) do
      allow(resolve_user_path(p, home, project), "policy.home_allow")
    end
    for _, name in ipairs(M.HOME_ALLOW_ENV) do
      local v = type(env[name]) == "string" and M.normalize(env[name]) or nil
      if v then
        allow(v, "$" .. name)
      end
    end
    local not_roots = { [home .. "/.local"] = true, [home .. "/.config"] = true, [home .. "/.cache"] = true,
      [home .. "/.local/share"] = true, [home .. "/.local/state"] = true }
    for dir in (env.PATH or ""):gmatch("[^:]+") do
      local d = M.normalize(dir)
      if d and inside(d, home) and d ~= home then
        allow(d, "on $PATH")
        local parent = dirname(d)
        if basename(d) == "bin" and parent ~= home and not not_roots[parent] then
          allow(parent, "toolchain of a $PATH entry")
        end
      end
    end
    -- the agent binary itself
    local exe = cmd[1]
    if exe then
      local found
      if exe:find("/", 1, true) then
        found = exe:sub(1, 1) == "/" and M.normalize(exe) or nil
      else
        for dir in (env.PATH or ""):gmatch("[^:]+") do
          local c = dir .. "/" .. exe
          if exists(c) and lstat_type(c) ~= "directory" then
            found = c
            break
          end
        end
      end
      if found then
        allow(found, "agent command")
        local real = probes.realpath and probes.realpath(found)
        if real and real ~= found then
          allow(real, "agent command")
        end
      end
    end
  end

  -- toolchains and binaries that live in a hidden home but are named by $PATH, the environment or
  -- the command: shown read-only (their owner's credentials inside them stay hidden, see hide_creds)
  local other_owner = {}
  do
    local oseen = {}
    --- a directory below an owner's home that may be shown as a toolchain (not the home itself, not ~/.local ...)
    local function toolchain_root(p)
      local r = in_home_root(p)
      if not r or inside(p, home) then
        return false
      end
      local owner = r == "/home" and ("/home/" .. (p:match("^/home/([^/]+)") or "")) or r
      if p == owner or p == r then
        return false
      end
      for _, sub in ipairs({ "/.local", "/.config", "/.cache", "/.local/share", "/.local/state" }) do
        if p == owner .. sub then
          return false
        end
      end
      return true
    end
    local function allow_other(p, why)
      if not p or inside(p, home) or not in_home_root(p) or not exists(p) then
        return
      end
      if lstat_type(p) == "link" then
        local real = probes.realpath and probes.realpath(p)
        if real and real ~= p then
          return allow_other(real, why)
        end
        return
      end
      for covered in pairs(oseen) do
        if inside(p, covered) then
          return
        end
      end
      oseen[p] = true
      plan.homes.allow[#plan.homes.allow + 1] = { path = p, why = why }
      local r = in_home_root(p)
      local owner = r
      if r == "/home" then
        owner = "/home/" .. (p:match("^/home/([^/]+)") or "")
      end
      other_owner[owner] = true
    end
    for _, name in ipairs(M.HOME_ALLOW_ENV) do
      local v = type(env[name]) == "string" and M.normalize(env[name]) or nil
      if v then
        allow_other(v, "$" .. name)
      end
    end
    for dir in (env.PATH or ""):gmatch("[^:]+") do
      local d = M.normalize(dir)
      if d and in_home_root(d) and not inside(d, home) then
        allow_other(d, "on $PATH")
        -- symlinks in a $PATH directory (~/.local/bin/claude -> ~/.local/share/claude/versions/x)
        for _, e in ipairs(probes.list(d)) do
          if e[2] == "link" then
            local real = probes.realpath and probes.realpath(d .. "/" .. e[1])
            if real and in_home_root(real) then
              allow_other(real, "target of a $PATH link")
            end
          end
        end
        local parent = dirname(d)
        if basename(d) == "bin" and toolchain_root(parent) then
          allow_other(parent, "toolchain of a $PATH entry")
        end
      end
    end
    local exe = cmd[1]
    if exe then
      local found
      if exe:find("/", 1, true) then
        found = exe:sub(1, 1) == "/" and M.normalize(exe) or nil
      else
        for dir in (env.PATH or ""):gmatch("[^:]+") do
          local c = dir .. "/" .. exe
          if exists(c) and lstat_type(c) ~= "directory" then
            found = c
            break
          end
        end
      end
      if found then
        allow_other(found, "agent command")
        local real = probes.realpath and probes.realpath(found)
        if real and real ~= found then
          allow_other(real, "agent command")
        end
      end
    end
    if plan.net and plan.net.nvim and plan.net.nvim:sub(1, 1) == "/" then
      allow_other(plan.net.nvim, "the network relay's nvim")
      local real = probes.realpath and probes.realpath(plan.net.nvim)
      if real then
        allow_other(real, "the network relay's nvim")
        local bin = dirname(real)
        if basename(bin) == "bin" and toolchain_root(dirname(bin)) then
          allow_other(dirname(bin), "the network relay's nvim")
        end
      end
    end
  end

  -- hidden. In allowlist mode only what is mounted at all (the allowed trees) can be hidden.
  local function reachable(p)
    if not inside(p, home) and in_home_root(p) then
      for _, w in ipairs(plan.writable) do
        if inside(p, w.path) then
          return true
        end
      end
      for _, a in ipairs(plan.homes.allow) do
        if inside(p, a.path) then
          return true
        end
      end
      return false
    end
    if home_mode == "denylist" or not inside(p, home) then
      return true
    end
    for _, w in ipairs(plan.writable) do
      if inside(p, w.path) then
        return true
      end
    end
    for _, a in ipairs(plan.home_allow) do
      if inside(p, a.path) then
        return true
      end
    end
    return false
  end
  local hseen, unhide_used = {}, {}
  local link_seen = {}
  local hide
  hide = function(p, why)
    -- bwrap cannot mount on a symlink ("Can't mount on symlink destination"): hide what it points to
    -- (a project `.env -> ../secrets/env`, a dotfile manager's `~/.npmrc -> dotfiles/npmrc`). The link
    -- itself stays, and reads the hidden target.
    if lstat_type(p) == "link" then
      if not link_seen[p] then
        link_seen[p] = true
        local real = probes.realpath and probes.realpath(p)
        if real and real ~= p then
          hide(real, why)
        end
      end
      return
    end
    local ty = probes.stat_type(p)
    if ty and not hseen[p] and reachable(p) then
      if exc_by.unhide[p] then
        unhide_used[p] = true
        return
      end
      hseen[p] = true
      local kind = ty == "directory" and "dir" or "file"
      plan.hidden[#plan.hidden + 1] = { path = p, kind = kind, why = why }
      if kind == "file" then
        plan.needs.empty_file = aux.empty
      end
    end
  end
  local in_masked = function(p)
    if inside(p, "/tmp") then
      return true
    end
    for _, m in ipairs(plan.masked) do
      if inside(p, m.path) then
        return true
      end
    end
    return false
  end
  -- sockets named by the environment that live outside the masked directories
  for _, name in ipairs(M.SOCKET_ENV) do
    local val = env[name]
    if type(val) == "string" and val ~= "" then
      local cands = {}
      if name == "GPG_AGENT_INFO" then
        cands[1] = val:match("^([^:]+)")
      elseif name == "DBUS_SESSION_BUS_ADDRESS" then
        for path in val:gmatch("unix:path=([^,;]+)") do
          cands[#cands + 1] = path
        end
      elseif name == "WAYLAND_DISPLAY" then
        local xdg = env.XDG_RUNTIME_DIR
        cands[1] = val:sub(1, 1) == "/" and val or (xdg and xdg ~= "" and (xdg .. "/" .. val)) or nil
      else
        cands[1] = val
      end
      for _, c in ipairs(cands) do
        local p = c and M.normalize(c)
        if p and p ~= "/" and p ~= home and not in_masked(p) and not inside(project, p) and not inside(tmp_dir, p) then
          hide(p, "socket named by $" .. name)
        end
      end
    end
  end
  local function hide_creds(base)
    for _, p in ipairs(M.HIDDEN) do
      hide(base .. p, "credentials")
    end
    for _, g in ipairs(M.HIDDEN_GLOBS) do
      for _, p in ipairs(probes.glob(base .. g)) do
        hide(p, "history")
      end
    end
  end
  hide_creds(home)
  for owner in pairs(other_owner) do
    hide_creds(owner)
  end
  -- Secrets INSIDE the trees that are shown from $HOME (toolchains, the directories of $PATH entries
  -- and their parents, policy.home_allow): ~/dotfiles/bin on $PATH shows ~/dotfiles whole, with
  -- its .ssh, .npmrc and credentials. Hidden by name like the project's secrets; not by content.
  plan.tree_secrets = {}
  if policy.tree_secrets ~= false and (home_mode == "allowlist" or #plan.homes.allow > 0) then
    local trees, tseen = {}, {}
    for _, list in ipairs({ plan.home_allow, plan.homes.allow }) do
      for _, a in ipairs(list) do
        if not tseen[a.path] and probes.stat_type(a.path) == "directory" and not inside(project, a.path) then
          tseen[a.path] = true
          trees[#trees + 1] = a.path
        end
      end
    end
    local tglobs = vim.list_extend(copy_list(M.PROJECT_SECRET_GLOBS), policy.secret_files or {})
    local texcept = copy_list(M.PROJECT_SECRET_EXCEPT)
    for _, a in ipairs(policy.secret_allow or {}) do
      if not a:find("/", 1, true) then
        texcept[#texcept + 1] = a
      end
    end
    local budget = { dirs = M.TREE_MAX_DIRS }
    local gkey = table.concat(tglobs, ",") .. "|" .. table.concat(texcept, ",")
    for _, t in ipairs(trees) do
      local found, trunc
      local st = probes.tree_cache and vim.uv.fs_stat(t)
      local sig = st and (st.mtime.sec .. ":" .. st.mtime.nsec .. "|" .. gkey)
      local c = sig and tree_cache[t]
      if c and c.sig == sig and (vim.uv.hrtime() - c.at) / 1e9 < M.TREE_CACHE_S then
        found, trunc = c.found, c.trunc
      else
        found, trunc = walk_tree(probes, t, M.TREE_DEPTH, { globs = tglobs, except = texcept }, budget)
        if sig then
          tree_cache[t] = { sig = sig, at = vim.uv.hrtime(), found = found, trunc = trunc }
        end
      end
      for _, sec in ipairs(found) do
        if not hseen[sec.path] then
          hide(sec.path, "secret in the shown tree " .. t)
          if hseen[sec.path] then
            plan.tree_secrets[#plan.tree_secrets + 1] = sec.path
          end
        end
      end
      if trunc then
        plan.notes[#plan.notes + 1] = ("the tree %s is large: secret names deeper in it were not looked for"):format(t)
      end
    end
  end
  if cargo_home and cargo_home ~= home .. "/.cargo" then
    hide(cargo_home .. "/credentials", "credentials")
    hide(cargo_home .. "/credentials.toml", "credentials")
  end
  for _, p in ipairs(policy.hidden or {}) do
    local rp = resolve_user_path(p, home, project)
    if rp then
      hide(rp, "policy.hidden")
    end
  end

  -- ~/.claude in the allowlist view
  if claude_minimal then
    local cred = home .. "/.claude/.credentials.json"
    if exists(cred) then
      plan.claude.credentials = cred
    end
    local sseen = {}
    for _, name in ipairs(policy.claude_share or {}) do
      local rel = tostring(name):gsub("^/+", "")
      local path = home .. "/.claude/" .. rel
      if not sseen[path] and M.claude_share_ok(rel) and exists(path) then
        sseen[path] = true
        plan.claude.shared[#plan.claude.shared + 1] = { path = path, why = "policy.claude_share" }
      end
    end
  end

  -- ~/.claude.json: a private copy
  local cj = home .. "/.claude.json"
  if exists(cj) and aux.claude_json then
    plan.claude_json = { src = cj, copy = aux.claude_json, project = project }
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
  local w = { gits = {}, members = {}, secrets = {}, links = {}, truncated = false }
  if not shared then
    local want_secrets = policy.project_secrets ~= false and not at_home
    local globs, except
    if want_secrets then
      globs = vim.list_extend(copy_list(M.PROJECT_SECRET_GLOBS), policy.secret_files or {})
      except = copy_list(M.PROJECT_SECRET_EXCEPT)
      for _, a in ipairs(policy.secret_allow or {}) do
        if not a:find("/", 1, true) then
          except[#except + 1] = a
        end
      end
    end
    w = walk(probes, project, tonumber(policy.scan_depth) or M.SCAN_DEPTH, {
      secrets = globs, except = except, secret_dirs = want_secrets and M.PROJECT_SECRET_DIRS or nil,
      paths = want_secrets and M.PROJECT_SECRET_PATHS or nil,
    })
  end
  if w.sock_truncated then
    plan.notes[#plan.notes + 1] = ("socket search stopped (more than %d directories or deeper than %d levels below the project):"
      .. " a unix socket further down stays connectable from inside the sandbox"):format(M.SOCK_MAX_DIRS, M.SOCK_DEPTH)
  end
  if w.truncated then
    plan.notes[#plan.notes + 1] = ("directory walk stopped after %d directories: deeper .git and member"
      .. " directories, secrets and symlinks are not handled"):format(M.SCAN_MAX_DIRS)
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
  -- project secrets and sockets (after the credentials, so a policy exception can show one)
  local rel_allow = {}
  for _, a in ipairs(policy.secret_allow or {}) do
    if a:find("/", 1, true) then
      rel_allow[a] = true
    end
  end
  for _, s in ipairs(w.secrets) do
    local rel = s.path:sub(#project + 2)
    if not rel_allow[rel] then
      hide(s.path, s.kind == "socket" and "project socket" or "project secret")
    end
  end
  -- secrets no file name gives away (known token formats), and hard links to anything hidden
  plan.scan = { enabled = false, files = 0, truncated = false }
  plan.hardlinks = {}
  local multi = {}
  if not shared and not at_home and probes.scan_project then
    local content = policy.content_scan ~= false
    local sc = probes.scan_project(project, { content = content }) or {}
    plan.scan = { enabled = content, files = sc.files or 0, truncated = sc.truncated or false, why = sc.why, hits = #(sc.hits or {}),
      unread = sc.unread }
    multi = sc.multi or {}
    if sc.truncated then
      plan.notes[#plan.notes + 1] = ("project scan stopped (%s): files beyond that were not checked for secrets or hard links"):format(sc.why or "limit")
    end
    for _, h in ipairs(sc.hits or {}) do
      local rel = h.path:sub(#project + 2)
      if not rel_allow[rel] then
        hide(h.path, "project content: looks like a " .. h.kind)
      end
    end
  end
  if probes.stat_info and #multi > 0 then
    -- a project file that is a hard link of a credential in $HOME (or another owner's home), whether
    -- or not that credential is mounted at all: reading the link reads the credential
    local by_inode = {}
    for _, m in ipairs(multi) do
      by_inode[tostring(m.dev) .. ":" .. tostring(m.ino)] = by_inode[tostring(m.dev) .. ":" .. tostring(m.ino)] or {}
      table.insert(by_inode[tostring(m.dev) .. ":" .. tostring(m.ino)], m.path)
    end
    local bases = { home }
    for owner in pairs(other_owner) do
      bases[#bases + 1] = owner
    end
    local pw = input.passwd_home and M.normalize(input.passwd_home)
    if pw and pw ~= home then
      bases[#bases + 1] = pw
    end
    local nfound = 0
    local function check(p, d)
      if nfound > 600 then
        return
      end
      local t = probes.stat_type(p)
      if t == "file" then
        nfound = nfound + 1
        local info = probes.stat_info(p)
        local names = info and info.nlink and info.nlink > 1 and by_inode[tostring(info.dev) .. ":" .. tostring(info.ino)]
        for _, name in ipairs(names or {}) do
          hide(name, "hard link of the credential " .. p)
          plan.hardlinks[#plan.hardlinks + 1] = { path = p, links = info.nlink, masked = 1, unaccounted = 0, alias = name }
        end
      elseif t == "directory" and d < 4 then
        for _, e in ipairs(probes.list(p)) do
          check(p .. "/" .. e[1], d + 1)
        end
      end
    end
    for _, base in ipairs(bases) do
      for _, rel in ipairs(M.HIDDEN) do
        check(base .. rel, 0)
      end
      for _, g in ipairs(M.HIDDEN_GLOBS) do
        for _, p in ipairs(probes.glob(base .. g)) do
          check(p, 0)
        end
      end
    end
    -- A project name for a file that RUNS outside the sandbox later (a shell rc file, a git config or
    -- hook, direnv, an editor or agent hook...): the name is writable, the other name is the same
    -- inode, so a write through the project name plants code. The name is hidden (empty, read-only);
    -- names below a path that is mounted read-only anyway are fine. Files first, then directories
    -- under one budget, so a huge ~/.local/share/nvim cannot crowd out ~/.bashrc.
    local covered = {}
    local code = { stat = 0, queue = {}, stopped = false }
    local function match_code(p)
      local info = probes.stat_info(p)
      local names = info and info.nlink and info.nlink > 1 and by_inode[tostring(info.dev) .. ":" .. tostring(info.ino)]
      for _, name in ipairs(names or {}) do
        covered[name] = true
        if not M.shadow(plan, name) then
          hide(name, "hard link of " .. p .. ", which runs outside the sandbox")
          plan.hardlinks[#plan.hardlinks + 1] = { path = p, links = info.nlink, masked = 1, unaccounted = 0, alias = name, code = true }
        end
      end
    end
    local function visit(p, d)
      if code.stat >= M.HARDLINK_CODE_MAX then
        code.stopped = true
        return
      end
      code.stat = code.stat + 1
      local t = probes.stat_type(p)
      if t == "file" then
        match_code(p)
      elseif t == "directory" and d < 4 then
        code.queue[#code.queue + 1] = { p, d }
      end
    end
    for _, base in ipairs(bases) do
      for _, rel in ipairs(M.WRITABLE_FORBIDDEN_HOME) do
        visit(base .. rel, 0)
      end
    end
    for _, r in ipairs(plan.readonly) do
      if inside(r.path, project) then
        if r.why == "git" then
          for _, sub in ipairs({ "/config", "/hooks", "/info", "/config.worktree" }) do
            visit(r.path .. sub, 0)
          end
        else
          visit(r.path, 0)
        end
      end
    end
    local qi = 1
    while qi <= #code.queue and not code.stopped do
      local dir, d = code.queue[qi][1], code.queue[qi][2]
      qi = qi + 1
      for _, e in ipairs(probes.list(dir)) do
        visit(dir .. "/" .. e[1], d + 1)
      end
    end
    if code.stopped then
      plan.notes[#plan.notes + 1] = ("hard-link check of files that run outside the sandbox stopped after %d files:"
        .. " names beyond that were not compared with the project's multi-link files"):format(M.HARDLINK_CODE_MAX)
    end
    -- every other multi-link file: its other names cannot be seen from here
    local unknown = {}
    for _, m in ipairs(multi) do
      if not covered[m.path] and not M.shadow(plan, m.path) then
        local hid = false
        for _, h in ipairs(plan.hidden) do
          hid = hid or h.path == m.path
        end
        if not hid then
          unknown[#unknown + 1] = m.path
        end
      end
    end
    if #unknown > 0 then
      plan.multilinks = { count = #unknown, sample = vim.list_slice(unknown, 1, 5) }
      plan.notes[#plan.notes + 1] = ("%d project file%s ha%s other hard links that are not a known credential or a file that runs outside the sandbox"
        .. " (e.g. %s): a write through such a name also changes the other names, wherever they are"):format(
        #unknown, #unknown == 1 and "" or "s", #unknown == 1 and "s" or "ve", table.concat(vim.list_slice(unknown, 1, 3), ", "))
    end
  end
  if probes.stat_info then
    local snapshot = vim.list_slice(plan.hidden, 1, #plan.hidden)
    for _, h in ipairs(snapshot) do
      local info = h.kind == "file" and probes.stat_info(h.path) or nil
      if info and info.nlink and info.nlink > 1 then
        local found = 0
        for _, m in ipairs(multi) do
          if m.dev == info.dev and m.ino == info.ino and m.path ~= h.path then
            found = found + 1
            hide(m.path, "hard link of the hidden " .. h.path)
          end
        end
        local unaccounted = info.nlink - 1 - found
        plan.hardlinks[#plan.hardlinks + 1] = { path = h.path, links = info.nlink, masked = found, unaccounted = math.max(unaccounted, 0) }
        if unaccounted > 0 then
          plan.notes[#plan.notes + 1] = ("%s has %d more hard link%s outside the project (or beyond the scan): the sandbox hides this name only;"
            .. " another name that the sandbox shows would still read it"):format(h.path, unaccounted, unaccounted == 1 and "" or "s")
        end
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
  if not claude_minimal then
    for _, rel in ipairs(M.HOME_READONLY) do
      lock(home .. rel, "agent config")
    end
  end
  -- MEMORY.md auto-loads into the next unsandboxed session
  for _, p in ipairs(claude_minimal and {} or probes.glob(home .. "/.claude/projects/*/memory")) do
    lock(p, "agent memory")
  end
  if claude_minimal then
    for _, d in ipairs(own) do
      lock(d .. "/memory", "agent memory")
    end
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
  for _, rel in ipairs(claude_minimal and {} or M.HOME_MASK_IF_ABSENT) do
    if not exists(home .. rel) then
      mask(home .. rel, "absent agent config")
    end
  end
  plan.masks = masks
  -- subdirectories whose watched names are compared when the run ends (see M.WATCH_NAMES)
  plan.watch = { dirs = {}, names = M.WATCH_NAMES }
  if not at_home and not shared then
    for _, m in ipairs(w.members) do
      if #plan.watch.dirs < M.WATCH_DIRS_MAX then
        plan.watch.dirs[#plan.watch.dirs + 1] = m.dir
      end
    end
    if #w.members > 0 then
      plan.notes[#plan.notes + 1] = "files that run outside the sandbox (.cargo/config.toml, .envrc, .claude/settings.json, an editor's task file...)"
        .. " that the agent CREATES in a subdirectory are not prevented (the ones that exist are read-only); a new one is reported when the run ends"
    end
  end
  for _, rel in ipairs(M.HOME_EPHEMERAL) do
    if exists(home .. rel) then
      plan.ephemeral[#plan.ephemeral + 1] = home .. rel
    end
  end

  -- approved but ineffective: a writable path that a later read-only/hidden mount covers (the
  -- writable <project>/.git under the --ro-bind of .git), an unhide of a path the policy does not
  -- hide. Never reported as approved.
  local drop = {}
  for _, e in ipairs(plan.exceptions) do
    if e.kind == "writable" then
      local sh = M.shadow(plan, e.value)
      if sh then
        drop[e] = ("no effect: %s is mounted read-only afterwards and wins over a writable %s"):format(sh, e.value)
      end
    elseif e.kind == "unhide" and not unhide_used[e.value] then
      drop[e] = "the policy does not hide " .. e.value .. " (nothing to show)"
    end
  end
  if next(drop) then
    local keep = {}
    for _, e in ipairs(plan.exceptions) do
      if drop[e] then
        plan.rejected[#plan.rejected + 1] = { kind = e.kind, value = e.value, reason = drop[e] }
        if e.kind == "writable" then
          for i = #plan.writable, 1, -1 do
            if plan.writable[i].exception and plan.writable[i].path == e.value then
              table.remove(plan.writable, i)
            end
          end
        end
      else
        keep[#keep + 1] = e
      end
    end
    plan.exceptions = keep
  end
  for i = #plan.writable, 1, -1 do
    local wr = plan.writable[i]
    local sh = wr.policy and M.shadow(plan, wr.path)
    if sh then
      plan.notes[#plan.notes + 1] = ("policy.writable %s has no effect: %s is mounted read-only afterwards"):format(wr.path, sh)
      table.remove(plan.writable, i)
    end
  end

  -- symlinks that leave the project: listed with what the sandbox would let through
  local function visible(p)
    for _, h in ipairs(plan.hidden) do
      if inside(p, h.path) then
        return false
      end
    end
    for _, list in ipairs({ plan.writable, plan.home_allow, plan.run_keep }) do
      for _, e in ipairs(list) do
        if inside(p, e.path) then
          return true
        end
      end
    end
    if inside(p, "/tmp") then
      return false
    end
    for _, m in ipairs(plan.masked) do
      if inside(p, m.path) then
        return false
      end
    end
    if home_mode == "allowlist" and inside(p, home) then
      return false
    end
    if in_home_root(p) and not inside(p, home) then
      for _, a in ipairs(plan.homes.allow) do
        if inside(p, a.path) then
          return true
        end
      end
      return false
    end
    return true
  end
  local real_project = probes.realpath(project) or project
  local readable = 0
  for _, l in ipairs(w.links) do
    if not hseen[l] then
      local target = probes.realpath(l)
      if target and not inside(target, project) and not inside(target, real_project) and not inside(target, tmp_dir) then
        local r = visible(target)
        readable = readable + (r and 1 or 0)
        plan.symlinks[#plan.symlinks + 1] = { path = l, target = target, readable = r }
      end
    end
  end
  if readable > 0 and policy.symlinks == "refuse" then
    local first = vim.tbl_filter(function(s)
      return s.readable
    end, plan.symlinks)[1]
    plan.blocked = ("%d project symlink(s) point outside the project and their targets are readable in the sandbox"
      .. " (first: %s -> %s); policy.symlinks = \"refuse\""):format(readable, first.path, first.target)
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

  -- sanitized copies of git configs (remote URLs with tokens, credential helpers)
  plan.git_configs = {}
  if aux.git_dir then
    local gseen2 = {}
    local function add_config(src)
      if not gseen2[src] and probes.stat_type(src) == "file" then
        gseen2[src] = true
        plan.git_configs[#plan.git_configs + 1] = { src = src, copy = ("%s/%d.config"):format(aux.git_dir, #plan.git_configs + 1) }
      end
    end
    for _, g in ipairs(w.gits) do
      if probes.stat_type(g) == "directory" then
        add_config(g .. "/config")
        for _, mc in ipairs(probes.glob(g .. "/modules/*/config")) do
          add_config(mc)
        end
      end
    end
    for _, rel in ipairs({ "/.gitconfig", "/.config/git/config" }) do
      local f = home .. rel
      for _, a in ipairs(plan.home_allow) do
        if inside(f, a.path) then
          add_config(f)
          break
        end
      end
    end
    if #plan.git_configs > 0 then
      plan.needs.git_dir = aux.git_dir
      plan.needs.git_configs = plan.git_configs
    end
  end

  -- cwd inside the project, else the project
  local ins = cwd == project or project == "/" or cwd:sub(1, #project + 1) == project .. "/"
  plan.chdir = ins and cwd or project
  plan.empty_file = plan.needs.empty_file
  return plan
end


-- -------------------------------------------------------------------- argv

-- Runs inside the sandbox before the agent: start the relay, wait until it listens, or refuse to
-- start the agent (fail closed). The relay dies with the sandbox's pid namespace.
M.NET_SCRIPT = [[nv=$1; d=$2; p=$3; shift 3
r=/tmp/.xyno-net-ready
rm -f "$r"
XDG_RUNTIME_DIR=/tmp "$nv" -u NONE -i NONE --headless -l "$d/relay.lua" "$d/proxy.sock" "$p" "$r" </dev/null >/tmp/.xyno-net-relay.log 2>&1 &
i=0
while [ ! -e "$r" ]; do
  i=$((i+1))
  if [ "$i" -gt 100 ]; then
    echo "xyno-sandbox: the network relay did not start, the agent is NOT started (setup network = open turns the filter off)" >&2
    cat /tmp/.xyno-net-relay.log >&2 2>/dev/null
    exit 125
  fi
  sleep 0.1
done
exec "$@"]]

--- bwrap flags of the isolation, without any path (also what the readiness probe runs).
function M.probe_argv(net)
  local a = { "bwrap" }
  vim.list_extend(a, M.ISOLATION_FLAGS)
  if net then
    a[#a + 1] = "--unshare-net"
  end
  vim.list_extend(a, { "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "true" })
  return a
end

-- Number of arguments of the bwrap options the plan uses (for splitting an op into its options).
M.FLAG_ARITY = {
  ["--bind"] = 2, ["--ro-bind"] = 2, ["--setenv"] = 2, ["--unsetenv"] = 1, ["--tmpfs"] = 1, ["--dev"] = 1, ["--proc"] = 1,
  ["--remount-ro"] = 1, ["--chdir"] = 1, ["--cap-drop"] = 1,
}

--- Split the arguments of an op into single bwrap options: { { "--tmpfs", "/x" }, { "--remount-ro", "/x" } }.
function M.split_options(args)
  local out, i = {}, 1
  while i <= #args do
    local n = M.FLAG_ARITY[args[i]] or 0
    out[#out + 1] = vim.list_slice(args, i, i + n)
    i = i + 1 + n
  end
  return out
end

--- Every bwrap option of a plan, in the order bwrap applies them, as { section, why, args } records.
--- This is the ONE place the arguments are decided: argv() flattens it and the preview renders it,
--- so what is shown is what runs (a spec diffs the preview against the real command line).
--- @param plan table
--- @return { section: string, why: string, args: string[] }[]
function M.ops(plan)
  local ops = {}
  local function add(section, why, ...)
    ops[#ops + 1] = { section = section, why = why, args = { ... } }
  end
  ops[#ops + 1] = { section = "isolation", why = "namespaces, capabilities, no controlling terminal", args = copy_list(plan.flags or {}) }
  add("base", "the whole filesystem, read-only", "--ro-bind", "/", "/")
  add("base", "private device nodes", "--dev", "/dev")
  add("base", "fresh /proc of the sandbox's own pid namespace", "--proc", "/proc")
  add("base", "empty /tmp: the host's /tmp is invisible", "--tmpfs", "/tmp")
  for _, m in ipairs(plan.masked or {}) do
    add("sockets", m.why, "--tmpfs", m.path)
  end
  for _, k in ipairs(plan.run_keep or {}) do
    add("sockets", k.why, "--ro-bind", k.path, k.path)
  end
  local homes = plan.homes or { masked = {}, allow = {} }
  for _, h in ipairs(homes.masked) do
    add("homes", h.why .. ": hidden (empty tmpfs)", "--tmpfs", h.path)
  end
  if homes.rebind_home then
    add("homes", "your own home, read-only again (home = \"denylist\")", "--ro-bind", plan.home, plan.home)
  end
  for _, a in ipairs(homes.allow) do
    add("homes", a.why .. " (read-only)", "--ro-bind", a.path, a.path)
  end
  if plan.home_mode == "allowlist" then
    add("home", "empty $HOME: only the paths below are visible", "--tmpfs", plan.home)
    for _, a in ipairs(plan.home_allow or {}) do
      add("home", a.why, "--ro-bind", a.path, a.path)
    end
  end
  for _, n in ipairs(plan.env_strip or {}) do
    add("env", "stripped", "--unsetenv", n)
  end
  for _, w in ipairs(plan.writable or {}) do
    add("writable", w.why, "--bind", w.path, w.path)
  end
  -- after the writable binds: hides inside ~/.claude must sit on top of it
  for _, h in ipairs(plan.hidden or {}) do
    if h.kind == "dir" then
      add("hidden", h.why, "--tmpfs", h.path)
    else
      add("hidden", h.why, "--ro-bind", plan.empty_file, h.path)
    end
  end
  local cl = plan.claude or { mode = "full", shared = {} }
  if cl.mode == "minimal" then
    add("claude", "agent state of this run only (nothing of the real ~/.claude, thrown away at exit)", "--tmpfs", plan.home .. "/.claude")
    if cl.credentials then
      add("claude", "the agent's login, read-only", "--ro-bind", cl.credentials, cl.credentials)
    end
    for _, sh in ipairs(cl.shared) do
      add("claude", sh.why .. ", read-only", "--ro-bind", sh.path, sh.path)
    end
  end
  if plan.claude_json then
    add("claude_json", "private copy of the agent's user config", "--bind", plan.claude_json.copy, plan.claude_json.src)
  end
  -- ~/.claude/projects is read-only except this project's own transcript dirs: a bind mount
  -- point cannot be renamed, so `mv projects/<name> ...; mkdir -p projects/<name>/memory`
  -- cannot get round the memory mask
  local projects = plan.projects or { dir = (plan.home or "") .. "/.claude/projects", own = {} }
  if cl.mode ~= "minimal" then
    add("projects", "agent transcripts of all projects, read-only", "--ro-bind", projects.dir, projects.dir)
  end
  for _, d in ipairs(projects.own) do
    add("projects", "this project's transcripts, writable", "--bind", d, d)
  end
  for _, r in ipairs(plan.readonly or {}) do
    add("readonly", r.why, "--ro-bind", r.path, r.path)
  end
  for _, g in ipairs(plan.git_configs or {}) do
    add("git", "credentials removed from the copy", "--ro-bind", g.copy, g.src)
  end
  for _, m in ipairs(plan.masks or {}) do
    -- project-relative masks (.cargo, .claude) would hit $HOME's own when the project is $HOME;
    -- the planner already left those out
    add("masks", m.why, "--tmpfs", m.path, "--remount-ro", m.path)
  end
  for _, g in ipairs(plan.guard_files or {}) do
    add("guards", g.why, "--ro-bind", plan.empty_file, g.path)
  end
  for _, p in ipairs(plan.ephemeral or {}) do
    add("ephemeral", "claude sources these before running commands", "--tmpfs", p)
  end
  if plan.net then
    local n = plan.net
    -- the only way out: the proxy's socket directory (read-only), reached through the relay on the
    -- sandbox's own loopback
    add("net", "the proxy's socket directory (the only way out)", "--ro-bind", n.dir, n.dir)
    local url = "http://127.0.0.1:" .. n.port
    for _, name in ipairs({ "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy" }) do
      add("setenv", "route through the local relay", "--setenv", name, url)
    end
    add("setenv", "no direct connections", "--setenv", "NO_PROXY", "")
    add("setenv", "no direct connections", "--setenv", "no_proxy", "")
  end
  return ops
end

--- The command line of a plan. Pure and deterministic: the same plan gives the same list.
--- bwrap itself is started with an EMPTY environment plus env_pass (`env -i`): the stripped names
--- never exist in any process of the sandbox, not even in bwrap's own (/proc/1/environ).
--- @param plan table
--- @return string[]
function M.argv(plan)
  assert(plan.mode == "bwrap", "plan.argv: not a bwrap plan")
  assert(plan.empty_file or (#plan.guard_files == 0 and not plan.needs.empty_file), "plan.argv: aux.empty is missing")
  local a = { "env", "-i" }
  for _, kv in ipairs(plan.env_pass) do
    a[#a + 1] = kv[1] .. "=" .. kv[2]
  end
  a[#a + 1] = "bwrap"
  for _, op in ipairs(M.ops(plan)) do
    vim.list_extend(a, op.args)
  end
  local cmd = plan.agent.cmd
  vim.list_extend(a, { "--chdir", plan.chdir, "--" })
  if plan.net then
    local n = plan.net
    vim.list_extend(a, { "sh", "-c", M.NET_SCRIPT, "xyno-net", n.nvim, n.dir, tostring(n.port) })
  end
  return vim.list_extend(a, cmd)
end

return M
