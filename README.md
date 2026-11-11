# xyno-sandbox.nvim

A Neovim plugin that runs a command-line coding agent inside a bubblewrap sandbox and refuses to start it without one. Linux only.

## Why

Command-line coding agents that run without permission prompts have all of your privileges. I did not want that from inside my editor, so I wrap them: the filesystem is read-only except the project and a scratch directory, credentials are hidden, secret environment variables are stripped, and anything that would later run outside the sandbox (git hooks, editor task files, direnv, cargo config, the agent's own settings) is locked read-only. Where no sandbox can be created, the agent does not start. That fail-closed default is the point of the plugin.

The policy knows the config, cache and state directories of one agent CLI, but `wrap()` takes any command; for other agents those paths are simply absent.

## Requirements

- Neovim 0.12+
- Linux with [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) on `PATH` and unprivileged user namespaces enabled
- no other plugin

## Install (lazy.nvim)

```lua
{
  "xynorash/xyno-sandbox.nvim",
  cmd = { "XynoSandboxStatus", "XynoSandboxPolicy", "XynoSandboxApprovals", "XynoSandboxRun" },
  opts = {},
  -- no dependencies on other plugins
  keys = {
    { "<leader>as", "<Cmd>XynoSandboxStatus<CR>", desc = "Sandbox status" },
    { "<leader>ap", "<Cmd>XynoSandboxPolicy<CR>", desc = "Sandbox policy" },
  },
}
```

A lualine component that shows the state (`sandbox: on`, `sandbox: checking`, `sandbox: OFF`, `sandbox: refused`, plus `x2` for two running sandboxes):

```lua
lualine_x = {
  { require("xyno_sandbox").statusline, color = function() return require("xyno_sandbox").statusline_hl() end },
}
```
`statusline()` never blocks and never errors, so it also works in a plain `statusline` option.

## Options

`setup(opts)` with the defaults:

```lua
require("xyno_sandbox").setup({
  sandbox = true,            -- false: deliberate opt-out, run unsandboxed even where bwrap works
  allow_unsandboxed = false, -- true: run unsandboxed when NO working backend exists (never disables a working sandbox)
  keymaps = false,           -- false, or { status = "<lhs>", policy = "<lhs>" }; no global keymap is set by default
  commands = true,           -- register the :XynoSandbox* commands
  preview = "once",          -- policy preview before a launch: "always" | "once" (per project) | "never"
  strip_skip_permissions = false, -- true: remove --dangerously-skip-permissions from the command
  agent_cmd = nil,           -- command shown by :XynoSandboxPolicy before anything was launched
  policy = {                 -- ADDITIVE policy lists (nothing can be removed from the built-in policy)
    readonly = {},           -- more read-only locks: project-relative, absolute or ~/ (locked when present)
    writable = {},           -- more writable paths: absolute or ~/ (never "/" or $HOME)
    hidden = {},             -- more hidden paths: absolute or ~/ (dir: empty tmpfs, file: empty file)
    guard_dirs = {},         -- project-relative dirs masked read-only when absent
    guard_files = {},        -- project-relative files bound to an empty read-only file when absent
    scrub = { contains = {}, prefix = {}, exact = {} }, -- more environment variable names to strip
    scan_depth = 8,          -- how deep nested .git and workspace members are looked for (1 to 32)
  },
})
```

`setup()` validates its options: an unknown key, a wrong type, a relative `writable`/`hidden` path, a `..`, a path that would expose `/` or `$HOME`, or a bad variable name raises an error and changes nothing.

Only the booleans `false` and `true` count for `sandbox` and `allow_unsandboxed`. `0`, `1`, `"false"` and `"true"` do not. Either may also be a function returning the boolean, evaluated at every call.

| Situation | Result |
| --- | --- |
| Linux, `bwrap` present and user namespaces work (checked by a real probe) | sandboxed (only `sandbox = false` turns it off) |
| No backend (Windows, macOS, Linux without `bwrap`) | refused: `wrap()` returns `nil, reason` |
| `bwrap` present but it cannot create a namespace (kernel setting, AppArmor, container) | refused, with the reason and a fix hint |
| No working backend and `allow_unsandboxed = true` | runs unsandboxed |
| `sandbox = false` anywhere | runs unsandboxed |

Every explicitly unsandboxed run through `:XynoSandboxRun` or `run()` warns.

### The permission-bypass flag

Agents that run without permission prompts (`--dangerously-skip-permissions`) rely on the sandbox as the only barrier. The preview says so on its own line: `Agent permission prompts: OFF (--dangerously-skip-permissions)`. With `strip_skip_permissions = true` the flag is removed from the command before it runs and the line reads `ON`. The agent then has to ask before acting, which a non-interactive `--print` run cannot do; what a given agent does then is not something this plugin checks. Without that setting the command is run as given.

## Policy preview

Before a launch the plugin shows the policy it is about to apply, built from the same plan that becomes the `bwrap` command line (`:XynoSandboxPolicy` shows it any time):

- writable paths (project, scratch, the agent and cargo caches)
- read-only paths and the locked git directories
- absent files and directories that are guarded so the agent cannot create them
- hidden credential paths (replaced with empty ones)
- the NAMES of the stripped environment variables (never values; the command's arguments, which hold the prompt, are not shown either)
- network state (open)
- the permission-bypass line above

`preview = "always"` shows it before every launch, `"once"` before the first launch of each project, `"never"` not at all. It is an interactive float (`<CR>` or `y` launches, `q` or `n` cancels), so it needs a UI: a headless Neovim never waits for it. `run()` then returns `nil` and starts the job after the confirm (`opts.on_start(job)` gets the id).

### Exceptions

Press `e` in the preview to consider one exception: show one hidden credential path, let one environment variable through, or make one more existing path writable. Each is decided separately: approve for this launch only, approve for this project (remembered), or refuse. Nothing is approved silently:

- every decision (`approved`, `refused`, `revoked`) is appended to `stdpath("state")/xyno-sandbox/exceptions.log`, one JSON object per line with `ts` (UTC), `project`, `kind` (`env`, `unhide`, `writable`), `path` or `name`, `decision` and `scope`. Values of variables are never logged.
- a refused exception leaves the plan exactly as it was (a spec compares the plans).
- an exception that cannot be applied (`/`, `$HOME`, `..`, a path that does not exist, the plugin's own state directory) is logged as refused with the reason.
- remembered approvals are listed and revoked with `:XynoSandboxApprovals`; the state files are `0600` and sit outside every writable path of the sandbox, so the agent cannot edit its own approvals.

## Commands

- `:XynoSandboxStatus` shows how an agent would run here: sandboxed, unsandboxed (and why), or refused (and why, with a fix hint). `:XynoSandboxStatus!` re-runs the readiness probe.
- `:XynoSandboxPolicy [dir]` shows the policy preview for the project (`dir`, default the git root of the current buffer). `!` lists every entry instead of the first 25 of each section. `e` considers an exception.
- `:XynoSandboxApprovals` lists the remembered approvals of every project (`x` revokes the one under the cursor); `:XynoSandboxApprovals revoke {id}` revokes by id; `:XynoSandboxApprovals log` opens the decision log.
- `:XynoSandboxRun {cmd} [args...]` runs the command in a terminal split, wrapped. Arguments are split on whitespace (use `\ ` for a space). The project is Neovim's current directory. If no sandbox is available it prints a one-line error and starts nothing, and a job that cannot start leaves no empty split behind.

## Readiness

`bwrap` on `PATH` is not a sandbox: unprivileged user namespaces are off on some kernels, restricted by AppArmor, or blocked by a container. `status()` runs the real isolation flags with `true` as the command (`bwrap --unshare-user --disable-userns ... true`) asynchronously with a 5 s timeout and caches the verdict (10 minutes for a success, 30 seconds for a failure). Until it finished `status()` answers `{ mode = "bwrap", ready = "pending" }` without blocking; `wrap()` waits for it once. A failed probe is no backend: the agent is refused, and the reason names the cause (`kernel.unprivileged_userns_clone`, `user.max_user_namespaces`, `kernel.apparmor_restrict_unprivileged_userns`, a container's seccomp profile, a masked `/proc`, a timeout) with the command that fixes it.

## Lua API

```lua
local sandbox = require("xyno_sandbox")

sandbox.status()  -- { mode = "bwrap", ready = "ok"|"pending" }
                  -- | { mode = "unsandboxed", via = "sandbox=false"|"allow_unsandboxed", reason, hint? }
                  -- | { mode = "refused", reason, hint? }        (never blocks)
sandbox.check(cb, force?)  -- run the readiness probe, then cb(status())
sandbox.plan(cmd, project, tmp_dir, { exceptions = {...} })
                  -- the structured plan (writable, readonly, git_locked, masks, guard_files, hidden,
                  -- env_strip, env_kept, network, agent, exceptions, notes), or nil, reason when refused
sandbox.argv(plan)  -- the bwrap command line of a plan (pure)
sandbox.wrap(cmd, project, tmp_dir, { plan = plan })
                  -- string[]? wrapped command, or nil, reason when refused; third value: a handle.
                  -- When explicitly unsandboxed the same `cmd` table comes back.
                  -- `project` and `tmp_dir` are the only writable places of the agent.
                  -- Run the result from Neovim's cwd (it becomes the agent's cwd if inside the project).
                  -- Call handle.release() when the process ended: it deletes the private copy of the
                  -- agent config and the empty placeholders the guards left in the project.
sandbox.confirm(cmd, project, tmp_dir, function(ok, plan_or_reason) end)  -- the launch-time preview
sandbox.run(cmd, { project = ..., tmp_dir = ..., on_start = fn, on_exit = fn })  -- what :XynoSandboxRun does
sandbox.approve(project, kind, value, scope?)  -- log and apply an exception ("once" | "project")
sandbox.refuse(project, kind, value)           -- log a refusal; changes nothing
sandbox.approvals(project?)                    -- remembered approvals
sandbox.revoke(project, id)
sandbox.statusline(), sandbox.statusline_hl()  -- lualine component and its highlight group
sandbox.cleanup()                              -- release every live sandbox (runs at VimLeavePre)
sandbox.scrub_names(env?, file_login?)         -- names of the environment variables that are stripped
sandbox.readonly_paths(project)                -- paths re-bound read-only, and absent dirs masked
```

`xyno_sandbox.plan` is the pure builder behind `plan()`: `build({ project, tmp_dir, cwd, env, home, uid, config, probes, aux, exceptions, cmd })` takes the filesystem as a `probes` table (a table-backed fake in the specs) and returns the plan; `argv(plan)` renders it. Nothing in it touches the disk, so the preview and the launcher cannot drift apart: they print and run the same plan.

### Wrapping an agent command

```lua
local cmd = { "my-agent", "--some-flag", "..." } -- any agent command
local wrapped, err, handle = require("xyno_sandbox").wrap(cmd, project_root, scratch_dir)
if not wrapped then
  error("sandbox: " .. tostring(err), 0) -- fail closed
end
vim.system(wrapped, { cwd = project_root }, function() vim.schedule(handle.release) end)
```

### Mapping from xynovim's option variables

| xynovim | xyno-sandbox |
| --- | --- |
| `vim.g.xynovim_99_sandbox = false` | `setup({ sandbox = false })` |
| `vim.g.xynovim_99_allow_unsandboxed = true` | `setup({ allow_unsandboxed = true })` |
| `require("config.agent_sandbox")` | `require("xyno_sandbox")` |

xynovim passes functions that read those variables, so changing them at run time takes effect immediately.

## How it works

`wrap()` prefixes the command with `bwrap`: a read-only bind of `/`, a private `/dev`, `/proc` and `/tmp`, new user, pid, ipc, uts and cgroup namespaces, nested user namespaces disabled, all capabilities dropped, no controlling terminal (no TIOCSTI injection). The project, the scratch directory, and a short list of agent and cargo cache paths are writable. On top of those binds, git directories (also behind `.git` files and in nested checkouts and submodules down to 8 levels), `.cargo` and `.envrc` of workspace members down to 8 levels, `.cargo`, `.envrc`, `.vscode`, the agent's project directory and the agent's settings, hooks, skills and memory are read-only. What is absent and would run unsandboxed when planted (`.git`, `.cargo`, `.vscode`, `.claude`, `.envrc`, `.mise.toml`, `.nvim.lua`, `.exrc`, `.nvimrc`, `.mcp.json`) is covered by an empty read-only directory or file for the run, and the launcher removes those empty placeholders when the run ends (`handle.release()`). A denylist of credential directories (`~/.ssh`, `~/.aws`, browser profiles, keyrings, shell histories, `/run/user/<uid>`, container sockets and more) is replaced by empty directories or files. Environment variables whose names look like secrets or cloud credentials are removed with `--unsetenv`. The agent's user-level config file in `$HOME` is replaced by a private copy.

## Residual risks

It is a denylist on a read-only view of the whole filesystem, with the network open (the model needs it). It is not a security boundary against a determined attacker.

- the agent's credential file under its config directory in `$HOME` must stay readable and writable (token refresh), so an agent can read that token.
- everything unlisted under `$HOME` is readable.
- loopback services and abstract sockets are reachable.
- cargo's `registry/src` and `git` are writable, so your own cargo may later build planted code.
- a nested `.git` deeper than 8 levels is not locked (`policy.scan_depth` raises it to 32), and a `.git` the agent creates itself in a new directory is not locked either (the `known limits` spec is an expected failure for that). `target`, `node_modules`, `.venv` and `.cache` are not scanned.
- the directory walk stops after 20000 directories; the preview then says so.
- files the project lacks and that are not in the guard list (`rust-toolchain.toml`, `bacon.toml`, a workspace member's `.envrc`) can be created inside the project. Add them with `policy.guard_files`.
- the placeholders of the guards are removed when the run ends; after a crash of Neovim an empty read-only `.envrc` or an empty `.vscode` directory can stay behind (remove them by hand). The masks inside the agent's config directory are shared by all projects and stay.
- the network is open: the preview shows it, nothing restricts it.
- an approved exception (`unhide`, `writable`, `env`) widens the policy for that launch or, when remembered, for that project until revoked; the log tells what and when, it does not make the exception safe.

## Platform status

- Linux: the specs in this repository run on Linux (`nvim -l tests/run.lua`); that is the only platform where the sandbox works and the only one I claim.
- Windows and macOS: there is no bubblewrap, so `wrap()` refuses and nothing starts. In the original xynovim CI the sandbox spec is skipped on both by design, and the refusal was exercised by a separate spec there. `tests/failclosed_spec.lua` ports that refusal check without an OS gate, but this repository's CI only runs on Linux, so on Windows and macOS it is not run here.
- Windows guards from the source stay in place (the module loads without a user id).
- Sandbox specs that need a working user namespace skip with a message on machines that restrict them.
- Known limits that are tested as the correct behaviour are `xfail` specs: reported as `XFAIL` with their reason, counted separately, and a failure (`XPASS`) as soon as one starts passing.

## Tests

See [tests/README.md](tests/README.md) for the harness (`skip`, `pending`, `xfail`).

```sh
nvim -l tests/run.lua                       # every tests/*_spec.lua, one headless nvim each
LAZY_PATH=/path/to/lazy.nvim nvim --headless -u tests/e2e/smoke.lua   # lazy.nvim smoke test
```

## Extracted from xynovim

This plugin is the sandbox wrapper of my Neovim config, [xynovim](https://github.com/xynorash/xynovim), published on its own.  The glue for the agent plugin I use stays there.

It is my own independent project and is not affiliated with the vendors of the agents it can wrap.

## License

MIT, see [LICENSE](LICENSE).
