# Changelog

## Unreleased

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
