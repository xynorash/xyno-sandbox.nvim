# Changelog

## Unreleased

### Third hardening round

A second independent verification found the following; each has a spec in `tests/round3_spec.lua` or `tests/survivors_spec.lua` that fails when the fix is removed (mutation table below).

- **Hard links to `$HOME` credentials**: `ln ~/.ssh/id_rsa proj/x.txt` was readable in both home views; the credential list is now compared by inode with the project's multi-link files and the project name is hidden.
- **Secrets inside shown trees**: `$PATH` entries show their parent whole (`~/dotfiles/bin` shows `~/dotfiles/.ssh`); secret names are now hidden inside every shown tree (breadth first, bounded, package caches skipped). `policy.tree_secrets`.
- **Environment scrub by value**: known token formats and URL credentials are stripped under any variable name; new name shapes `*_KEY`, `*_DSN`, `*_SESSION`, `*_AUTH`, `JWT`, `COOKIE`, `BEARER`, `SESSION`, `AUTH`, `SERPAPI`.
- **Sockets**: searched everywhere below the project, also in `target/`, `node_modules/`, `.cache/`, `.git/` and deeper than 8 levels (own budget, noted in the plan when exhausted).
- **More secret names**: `.vault-token`, `.env~`, `.envs/`, `auth.json`, `rclone.conf`, `.terraformrc`, `.secret`, `.npmrc.bak`, `id_rsa.bak`, `id_ed25519_sk`, `wallet.dat`, `creds.json`, `oauth_token`, `sa.json`, `serviceaccount.json`, and by path `.docker/config.json`, `.config/gh/hosts.yml`, `.composer/auth.json`, `.m2/settings.xml`, `.gradle/gradle.properties`. Public keys (`*.pub`) stay readable.
- **Content scan**: a placeholder is judged on the matched token, not on the line (`TOKEN=ghp_... # example` was skipped); long lines are read; the preview counts what was not read (large, binary, by extension).
- **`~/.claude.json` copy**: API keys, e-mail and name, anonymous id, old history, MCP server `env`/`headers` and token-looking strings are removed.
- **kill -9 of Neovim**: the private copies and the socket directory are recorded and removed by the next launch.
- **Suite**: ignores the caller's `TMPDIR`; skips socket specs whose path exceeds `AF_UNIX`'s limit; works from a checkout under `/tmp`; a sandbox that does not start while bubblewrap works is a failure (not 90 skips); a hanging spec file is killed after 240 s and fails the run; the process-survivor check waits for the kill instead of a fixed 300 ms (the old flake). Mutation survivors of the previous round now have specs (submodule configs, every sanitizer branch, the URL guard, `/var/run`, `/run` keep list, `$NVIM`, relay SIGHUP and bind address, a second `release()`, the approval front door, capabilities).

Behaviour changes: variables ending in `_KEY`, `_DSN`, `_SESSION`, `_AUTH` are no longer passed to the sandbox (approve one with an `env` exception); MCP servers of `~/.claude.json` lose their `env` and `headers`.


Mutation check of the third round (each edit applied to a copy of the repository, the named spec file(s) run, the edit reverted by deleting the copy):

| mutation | edit | spec file | result |
|---|---|---|---|
| hardlink_cred | changes: for _, base in ipairs(bases) do -> for _, base in ipairs({}) do | round3_spec.lua | killed |
| tree_off | changes: if policy.tree_secrets ~= false and (home_mod -> if false and (home_mode | round3_spec.lua | killed |
| tree_skip | changes: elseif d < depth and not M.TREE_SKIP[name] th -> elseif d < depth then | round3_spec.lua | killed |
| tree_dirs | changes: M.TREE_SECRET_DIRS = { ".aws", ".ssh", ".gnup -> M.TREE_SECRET_DIRS = { ".aws", ".gn | round3_spec.lua | killed |
| env_value | changes: M.ENV_VALUE_SCAN = true -> M.ENV_VALUE_SCAN = false | round3_spec.lua | killed |
| env_suffix | changes: for _, s in ipairs(M.ENV_SUFFIX) do -> for _, s in ipairs({}) do | round3_spec.lua | killed |
| env_suffix_ok | changes: M.ENV_SUFFIX_OK = { DESKTOP_SESSION = true } -> M.ENV_SUFFIX_OK = {} | round3_spec.lua | killed |
| env_contains | changes: "PASSPHRASE", "ASKPASS", "JWT", "COOKIE", "BE -> "PASSPHRASE", "ASKPASS", | round3_spec.lua | killed |
| env_exact | removes: KEY = true, DSN = true, SESSION = true, AUTH = true, SERPAPI | round3_spec.lua | killed |
| sock_skipped_dirs | changes: sock_only(sub, d + 1) -> local _ = sub | round3_spec.lua | killed |
| sock_note | changes: if w.sock_truncated then -> if false then | round3_spec.lua | killed |
| sock_depth | changes: M.SOCK_DEPTH = 24 -> M.SOCK_DEPTH = 6 | round3_spec.lua | killed |
| name_vault | changes: ".vault-token", ".env~", ".env*~", ".secret", -> ".secret" | round3_spec.lua | killed |
| name_pub | changes: if n:sub(-4) == ".pub" then -> if false then | round3_spec.lua, survivors_spec.lua | killed |
| name_paths | changes: paths = want_secrets and M.PROJECT_SECRET_PAT -> paths = nil, | round3_spec.lua | killed |
| name_envsdir | changes: ".kube", ".azure", ".envs", ".secrets" } -> ".kube", ".azure" } | round3_spec.lua | killed |
| scan_line_level | changes: if ok and kind ~= "credentials in a URL" and  -> if ok and placeholder(line) then | round3_spec.lua | killed |
| scan_url_exempt | changes: if ok and kind ~= "credentials in a URL" and  -> if ok and placeholder(m) then | round3_spec.lua | killed |
| scan_longline | changes: gmatch("([^\n]*)\n") do -> gmatch("([^\n]*)\n") do | round3_spec.lua | killed |
| scan_unread | changes: res.unread.large = res.unread.large + 1 -> res.unread.large = res.unread.large | round3_spec.lua | killed |
| ui_unread | changes: if u and (u.large > 0 -> if false and (u.large > 0 | round3_spec.lua | killed |
| cj_mcp_env | changes: M.MCP_DROP = { "env", -> M.MCP_DROP = { "envx", | round3_spec.lua | killed |
| cj_primary | changes: "githubRepoPaths", "primaryApiKey", -> "githubRepoPaths", | round3_spec.lua | survived (equivalent: the key-name rule removes the same key) |
| cj_email | changes: if low:find("email", 1, true) or low:find("na -> if false then | round3_spec.lua | killed |
| cj_strings | changes: if #scan.text(v) > 0 or strip_userinfo(v) ~=  -> if false then | round3_spec.lua | killed |
| cj_keys | changes: if not is_list and secret_key(k) then -> if false then | round3_spec.lua | killed |
| cj_project_mcp | removes: entry.mcpServers = scrub_mcp(entry.mcpServers) | round3_spec.lua | killed |
| orph_temp | changes: if it[2] == "temp" then -> if false then | round3_spec.lua | killed |
| orph_reg | changes: items[#items + 1] = { f, "temp" } -> local _ = f | round3_spec.lua | killed |
| orph_net | changes: items[#items + 1] = { h.net_dir, "temp" } -> local _ = h | round3_spec.lua | killed |
| orph_name | changes: (name:match("%.claude%.json$") or name:match( -> true | round3_spec.lua | killed |
| run_tmpdir | changes: vim.uv.fs_mkdtemp("/tmp/xyno-run-XXXXXX") -> vim.uv.fs_mkdtemp((vim.uv.os_getenv | round3_spec.lua | killed |
| run_sbok | changes: env.XYNO_TEST_SANDBOX_OK = "1" -> env.XYNO_TEST_SANDBOX_OK = "" | round3_spec.lua | killed |
| run_timeout | changes: ):wait(FILE_TIMEOUT_MS) -> ):wait(900000) | round3_spec.lua | killed |
| need_fail | changes: if vim.env.XYNO_TEST_SANDBOX_OK == "1" then -> if false then | round3_spec.lua | killed |
| git_modules | removes: add_config(mc) | survivors_spec.lua | killed |
| san_token | changes: password = true, token = true, -> password = true, | survivors_spec.lua | killed |
| san_password | changes: password = true, token = true, -> token = true, | survivors_spec.lua | killed |
| san_cont_top | changes: drop_cont = line:sub(-1) == "\\" -> drop_cont = false | survivors_spec.lua | killed |
| san_header_case | changes: section = header:lower() -> section = header | survivors_spec.lua | killed |
| scan_urlfilter | changes: if not pw or #pw < 8 or pw:find("[%$%{%}<>%%] -> if not pw then | round3_spec.lua | killed |
| secret_keys | removes: "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", | survivors_spec.lua | killed |
| mask_varrun | changes: M.MASKED_IF_DIR = { "/var/run" } -> M.MASKED_IF_DIR = {} | survivors_spec.lua | killed |
| runkeep | changes: M.RUN_KEEP = { "/run/current-system", "/run/b -> M.RUN_KEEP = {} | survivors_spec.lua | killed |
| sockenv_nvim | changes: , "NVIM", "NVIM_LISTEN_ADDRESS" } -> } | survivors_spec.lua | killed |
| relay_sighup | changes: { "sigterm", "sigint", "sighup" } -> { "sigterm", "sigint" } | survivors_spec.lua | killed |
| relay_bind | changes: server:bind("127.0.0.1", port) -> server:bind("0.0.0.0", port) | survivors_spec.lua | killed |
| release_guard | removes: if h.released then | survivors_spec.lua | killed |
| v_unknown | changes: if type(exc) ~= "table" or not M.EXCEPTION_KI -> if type(exc) ~= "table" then | survivors_spec.lua | killed |
| v_empty | changes: if type(v) ~= "string" or v == "" then -> if false then | survivors_spec.lua | killed |
| v_envname | changes: if not v:match("^[%a_][%w_]*$") then -> if false then | survivors_spec.lua | killed |
| capdrop | removes: "--cap-drop", "ALL", | survivors_spec.lua, sandbox_spec.lua | killed |
| die_with_parent | changes: "--die-with-parent", -> "--new-session" | leak_spec.lua | killed |
| tmp_tmpfs | changes: add("base", "empty /tmp: the host's /tmp is i -> add("base", "empty /tmp: the host's | survivors_spec.lua | killed |

54 mutations: 53 killed, 1 equivalent survivor.

Equivalent mutants (not credited as kills): `cj_primary` (`primaryApiKey` is also removed by the key-name rule). With unprivileged bubblewrap the capability set is empty even without `--cap-drop ALL`; the flag itself is pinned by the layout spec, the capability set by a behavioural spec.

Limits that remain and are documented: secrets in unknown formats or under unlisted names; hard links to secrets that are not on the credential list; sockets beyond the search budget; secret names (not content) inside shown trees; files the content scan does not read.

### Second hardening round

An independent re-verification found these; each has a spec that fails when the fix is removed (mutation table in the commit messages and below).

- **Process leaks**: the in-sandbox relay exits on SIGTERM/SIGINT/SIGHUP, when its parent changes and when the proxy socket is gone; `--die-with-parent` is pinned by a timeout-based spec that kills the launcher and requires bwrap, agent and relay to disappear; release closes the proxy and removes the socket directory. `tests/run.lua` fails the run (and kills the process) when a bwrap/relay of a spec file survives it. (`tests/leak_spec.lua`)
- **`~/.claude`**: in the allowlist view only the login (read-only), this project's transcripts and `policy.claude_share` names exist; `~/.claude.json` is a copy with the current project's record only. (`tests/claude_spec.lua`)
- **Secrets without a telling name**: sanitized read-only copies of git configs (URL tokens, credential helpers, auth headers), a larger default name list, a bounded content scan for known token formats with approve-to-unhide, hard links to hidden files, and symlinks named like secrets hide their target instead of failing with "Can't mount on symlink destination". New option `policy.content_scan`. (`tests/tokens_spec.lua`)
- **Other homes**: `/home` and the account's real home (when it is not `$HOME`) are empty tmpfs; toolchains, `$PATH`, the agent and the relay's nvim are bound back narrowly. (`tests/homes_spec.lua`)
- **Writable approvals**: shared system directories as a whole and parents of masked directories are refused, `policy.writable` too; specs kill the surviving `inside(p, f)` mutant. (`tests/writable_spec.lua`)
- **Spec gaps**: one spec per preview section (`tests/sections_spec.lua`).
- **Hermetic suite**: private fake `$HOME` outside `/tmp` with fake credentials, own scratch, cleanup; plan specs still run and sandbox specs skip where bubblewrap or user namespaces are unavailable; the `/tmp` placeholder spec no longer compares a snapshot of the shared `/tmp`; the last `RESULT` line of a spec file is the one counted (a failure message that quoted a nested run's line used to be read instead). (`tests/hermetic_spec.lua`)

Behaviour changes: with the default allowlist view the agent no longer sees your global `~/.claude` settings, `CLAUDE.md`, plugins or other projects' transcripts (share chosen names with `policy.claude_share`); a token refresh inside the sandbox is not persisted.

Hardening after an independent red team. Each finding was reproduced by running it and now has a spec that fails when the fix is removed.

- **Environment**: bwrap starts with `env -i` and only the allowed variables; stripped secrets no longer exist in `/proc/1/environ` or any other process of the sandbox. `$NVIM` and `$NVIM_LISTEN_ADDRESS` are stripped. (`tests/env_spec.lua`)
- **Sockets**: `/run`, `/var/tmp` (and a real `/var/run`) are empty tmpfs; sockets named by `$SSH_AUTH_SOCK`, `$XDG_RUNTIME_DIR`, `$DBUS_SESSION_BUS_ADDRESS`, ... and sockets inside the project are hidden; the relay's own nvim RPC socket is stopped. New `policy.keep_run`. (`tests/sockets_spec.lua`)
- **Project secrets**: `.env`, `.env.*`, keys, `.npmrc`, `.netrc`, `credentials.*`, `secrets.*` ... hidden with empty read-only overlays; `policy.project_secrets`, `secret_files`, `secret_allow`; shown in the preview, approvable through the exception flow. (`tests/secrets_spec.lua`)
- **Symlinks**: links out of the project are listed in the preview with the readability of their target; `policy.symlinks = "refuse"` blocks the launch. (`tests/secrets_spec.lua`)
- **`$HOME` allowlist**: new option `home`, default `"allowlist"`; `"denylist"` restores the old view; `policy.home_allow`. A fake agent that needs `cargo`/`rustc`, `git` and the installed agent CLI run inside it. (`tests/home_spec.lua`)
- **Preview == argv**: the preview and the command line are rendered from `plan.ops`; the preview shows the base mounts, masked sockets, home view, env settings and, in full mode, the exact mount order. (`tests/preview_spec.lua`)
- **Exceptions**: approvals that cannot take effect (writable `<project>/.git`, unhide of a path nothing hides, env that is not stripped) are refused, not logged as approved; writable `/etc`, `/proc`, `/run/user`, shell startup files and symlinks that resolve there, `unhide /etc/shadow`, and `LD_PRELOAD`/`PATH`/`LD_LIBRARY_PATH` env exceptions are refused (`expert_exceptions = true` for the last). (`tests/exceptions_spec.lua`)
- **run()**: a missing agent is detected before anything is mounted or opened, with the sandbox on as well; `jobstart` failures close the new split and release the sandbox. (`tests/ui_spec.lua`)
- **Stray placeholders**: shared directories (`/tmp`, `/var/tmp`, `/run`, `/`, parents of `$HOME`) get no placeholders and are not mounted writable; placeholders of a dead Neovim are swept at the next launch; `tests/run.lua` fails when a spec leaves one in `/tmp`. (`tests/strays_spec.lua`)
- `wrap()` accepts `opts.env` (variables set on top of Neovim's environment) because bwrap no longer inherits the caller's.

Breaking: the command line now starts with `env -i NAME=value ... bwrap`; callers that looked for `bwrap` at index 1 must look for it after `env -i`. The default `$HOME` view is the allowlist.
