# Tests

```sh
nvim -l tests/run.lua                  # every tests/*_spec.lua, one headless nvim each
nvim -l tests/run.lua tests/x_spec.lua # one spec file
```

One line per test, then `RESULT passed=N failed=N skipped=N xfailed=N`. The exit code is 0 only without failures.

| Result | Meaning |
| --- | --- |
| `ok` | passed |
| `FAIL` | failed (also: an `xfail` that passed, shown as `XPASS`) |
| `SKIP` | could not run here, with the reason (for example no working bubblewrap) |
| `XFAIL` | a known, documented limit that is expected to fail, with its reason |

## Specs

- `plan_spec.lua`: the pure plan builder, against a fake filesystem (no disk, no bwrap).
- `sandbox_spec.lua`: the wrapped command and real behaviour inside bwrap, against a fake `$HOME`.
- `guards_spec.lua`: guards for absent files, deeper nesting, placeholder and temp-file cleanup, in a real sandbox.
- `probe_spec.lua`: readiness probe, fail-closed status, hints, statusline (fake `bwrap` scripts).
- `exceptions_spec.lua`: approve, refuse, remember, revoke, the log contents.
- `ui_spec.lua`: preview text, launch confirm modes, the float, commands, `run()`.
- `options_spec.lua`: option validation and the policy lists.
- `setup_spec.lua`, `failclosed_spec.lua`: setup, commands, refusal without a backend.
- `harness_spec.lua`: the harness itself.

Specs that need a working user namespace call `H.need_sandbox()` and `SKIP` with the reason where none exists.

## Known limits: `xfail`, not `skip`

A behaviour that is wrong today and documented as a limit is written as a test of the CORRECT behaviour and registered with a reason:

```lua
xfail("a .git created by the agent in a new directory is read-only", "only what exists at launch is locked", function()
  -- the assertion of the correct behaviour
end)
```

- while it fails: `XFAIL <name> (known limit: <reason> | <first line of the error>)`, counted as `xfailed`, not a failure;
- when it starts passing: `FAIL <name>` with `XPASS`, so the limit cannot silently disappear from the docs and the specs: turn it into a normal `it` and update the README;
- a `skip()` inside it (no sandbox here) stays a skip.

The old `known_bug()` helper turned a failing assertion into a skip with a "KNOWN BUG" prefix; skips are for "cannot run here", so it was removed (`harness_spec.lua` checks it stays gone). `pending(name, reason)` registers a test that is not written yet.

## Smoke test

```sh
LAZY_PATH=/path/to/lazy.nvim nvim --headless -u tests/e2e/smoke.lua
```
