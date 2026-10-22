# xyno-sandbox.nvim

A Neovim plugin that runs a command-line coding agent inside a bubblewrap sandbox and refuses to start it without one. Linux only.

## Why

Agents like `claude --dangerously-skip-permissions` run with all of your privileges. I did not want that from inside my editor, so I wrap them: the filesystem is read-only except the project and a scratch directory, credentials are hidden, secret environment variables are stripped, and anything that would later run outside the sandbox (git hooks, editor task files, direnv, cargo config, the agent's own settings) is locked read-only. Where no sandbox can be created, the agent does not start. That fail-closed default is the point of the plugin.

The policy is written for Claude Code (it knows `~/.claude`), but `wrap()` takes any command, so it works for other agents too. The Claude-specific paths are simply absent for them.

## Requirements

- Neovim 0.12+
- Linux with [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) on `PATH` and unprivileged user namespaces enabled
- no other plugin

## Install (lazy.nvim)

```lua
{
  "xynorash/xyno-sandbox.nvim",
  cmd = { "XynoSandboxStatus", "XynoSandboxRun" },
  opts = {},
  -- no dependencies on other plugins
  keys = {
    { "<leader>as", "<Cmd>XynoSandboxStatus<CR>", desc = "Sandbox status" },
  },
}
```

## Options

`setup(opts)` with the defaults:

```lua
require("xyno_sandbox").setup({
  sandbox = true,            -- false: deliberate opt-out, run unsandboxed even where bwrap works
  allow_unsandboxed = false, -- true: run unsandboxed when NO backend exists (never disables a working sandbox)
  keymaps = false,           -- false, or { status = "<lhs>" }; no global keymap is set by default
  commands = true,           -- register :XynoSandboxStatus and :XynoSandboxRun
})
```

Only the booleans `false` and `true` count. `0`, `1`, `"false"` and `"true"` do not opt out.

| Situation | Result |
| --- | --- |
| Linux with `bwrap` | sandboxed (only `sandbox = false` turns it off) |
| No backend (Windows, macOS, Linux without `bwrap`) | refused: `wrap()` returns `nil, reason` |
| No backend and `allow_unsandboxed = true` | runs unsandboxed |
| `sandbox = false` anywhere | runs unsandboxed |

Every explicitly unsandboxed run through `:XynoSandboxRun` or `run()` warns.

## Commands

- `:XynoSandboxStatus` shows how an agent would run here: sandboxed, unsandboxed (and why), or refused (and why).
- `:XynoSandboxRun {cmd} [args...]` runs the command in a terminal split, wrapped. Arguments are split on whitespace (use `\ ` for a space). The project is Neovim's current directory. If no sandbox is available it prints a one-line error and starts nothing.

## Lua API

```lua
local sandbox = require("xyno_sandbox")

sandbox.status()  -- { mode = "bwrap" } | { mode = "unsandboxed", via = "sandbox=false"|"allow_unsandboxed", reason }
                  -- | { mode = "refused", reason }
sandbox.wrap(cmd, project, tmp_dir)
                  -- string[]? wrapped command, or nil, reason when refused.
                  -- When explicitly unsandboxed the same `cmd` table comes back.
                  -- `project` and `tmp_dir` are the only writable places of the agent.
                  -- Run the result from Neovim's cwd (it becomes the agent's cwd if inside the project).
sandbox.run(cmd, { project = ..., tmp_dir = ... })  -- what :XynoSandboxRun does; returns the job id
sandbox.scrub_names(env?, file_login?)  -- names of the environment variables that are stripped
sandbox.readonly_paths(project)         -- paths re-bound read-only, and absent dirs masked with an empty read-only dir
```

### Wrapping an agent command

```lua
local cmd = { "claude", "--dangerously-skip-permissions", "-p", "..." }
local wrapped, err = require("xyno_sandbox").wrap(cmd, project_root, scratch_dir)
if not wrapped then
  error("sandbox: " .. tostring(err), 0) -- fail closed
end
vim.system(wrapped, { cwd = project_root })
```

### Example: the 99 plugin

This is how my own config plugs it into [99](https://github.com/ThePrimeagen/99): the provider builds its command, then the wrapper wraps it, and a refusal aborts the request before anything starts. That glue stays in [xynovim](https://github.com/xynorash/xynovim), it is not part of this plugin.

```lua
function Guarded._build_command(self, query, context)
  local cmd = Claude._build_command(self, query, context)
  local project = vim.fs.root(0, ".git") or vim.uv.cwd()
  local wrapped, err = require("xyno_sandbox").wrap(cmd, project, tmp_dir)
  if not wrapped then
    error("99 sandbox: " .. tostring(err), 0)
  end
  return wrapped
end

function Guarded.make_request(self, query, context, observer)
  if require("xyno_sandbox").status().mode == "refused" then
    -- notify, fail the observer, and do not start
  end
  -- ...
end
```

### Mapping from xynovim's option variables

| xynovim | xyno-sandbox |
| --- | --- |
| `vim.g.xynovim_99_sandbox = false` | `setup({ sandbox = false })` |
| `vim.g.xynovim_99_allow_unsandboxed = true` | `setup({ allow_unsandboxed = true })` |
| `require("config.agent_sandbox")` | `require("xyno_sandbox")` |

The values are read at every `status()` and `wrap()` call, so changing `require("xyno_sandbox").config.sandbox` at run time takes effect immediately.

## How it works

`wrap()` prefixes the command with `bwrap`: a read-only bind of `/`, a private `/dev`, `/proc` and `/tmp`, new user, pid, ipc, uts and cgroup namespaces, nested user namespaces disabled, all capabilities dropped, no controlling terminal (no TIOCSTI injection). The project, the scratch directory, and a short list of agent and cargo cache paths are writable. On top of those binds, git directories (also behind `.git` files and in submodules down to two levels), `.cargo`, `.envrc`, `.vscode`, `.claude` and the agent's settings, hooks, skills and memory are read-only, or masked with an empty read-only directory when absent. A denylist of credential directories (`~/.ssh`, `~/.aws`, browser profiles, keyrings, shell histories, `/run/user/<uid>`, container sockets and more) is replaced by empty directories or files. Environment variables whose names look like secrets or cloud credentials are removed with `--unsetenv`. `~/.claude.json` is replaced by a private copy.

## Residual risks

It is a denylist on a read-only view of the whole filesystem, with the network open (the model needs it). It is not a security boundary against a determined attacker.

- `~/.claude/.credentials.json` must stay readable and writable (OAuth refresh), so an agent can read that token.
- everything unlisted under `$HOME` is readable.
- loopback services and abstract sockets are reachable.
- cargo's `registry/src` and `git` are writable, so your own cargo may later build planted code.
- a nested `.git` deeper than 2 levels is not locked.
- files the project lacks (`.envrc`, `.vscode/tasks.json`, `rust-toolchain.toml`, `bacon.toml`) can be created inside the project.
- masks leave empty directories behind (for example an empty `.cargo`, or `~/.claude/projects/<name>/memory`).

## Platform status

- Linux: the specs in this repository run on Linux (`nvim -l tests/run.lua`); that is the only platform where the sandbox works and the only one I claim.
- Windows and macOS: there is no bubblewrap, so `wrap()` refuses and nothing starts. In the original xynovim CI the sandbox spec is skipped on both by design, and the refusal was exercised by a separate spec there. Beyond that, this repository has not been run on Windows or macOS.
- Windows guards from the source stay in place (the module loads without a user id).
- Sandbox specs that need a working user namespace skip with a message on machines that restrict them.

## Tests

```sh
nvim -l tests/run.lua                       # every tests/*_spec.lua, one headless nvim each
LAZY_PATH=/path/to/lazy.nvim nvim --headless -u tests/e2e/smoke.lua   # lazy.nvim smoke test
```

## Extracted from xynovim

This plugin is the sandbox wrapper of my Neovim config, [xynovim](https://github.com/xynorash/xynovim), published on its own. The 99 integration stays there.

It is my own independent project and is not affiliated with the vendors of the agents it can wrap.

## License

MIT, see [LICENSE](LICENSE).
