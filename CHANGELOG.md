# Changelog

## Unreleased

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
