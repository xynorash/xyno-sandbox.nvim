# Tests

```sh
nvim -l tests/run.lua                  # every tests/*_spec.lua, one headless nvim each
nvim -l tests/run.lua tests/x_spec.lua # one spec file
```

`tests/run.lua` builds a private root (fake `$HOME` with fake credentials, outside `/tmp`) for the whole run, fails when a spec file leaves a `bwrap` or relay process behind, and removes the root. Set `XYNO_TEST_BASE` to choose where it is created. Without a usable `$HOME` (`HOME=/nonexistent`) it falls back to `$XDG_CACHE_HOME`, then to `<checkout>/.test-root` (removed again); with nowhere writable outside `/tmp` it prints `SKIP all specs (...)` and exits 0.

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
- `leak_spec.lua`: relay, bwrap and proxy lifetime; the runner's process-leak check.
- `hermetic_spec.lua`: the private fake `$HOME`, cleanup, a machine without bubblewrap.
- `round3_spec.lua`, `round4_spec.lua`, `survivors_spec.lua`, `survivors2_spec.lua`: one `describe` per finding of the third and fourth hardening rounds (hard links to credentials and to files that run outside the sandbox, token boundaries of the content scan, what a kill -9 leaves behind, the runner without a usable `$HOME`, the secret-name matcher and large-project timings) and the specs that kill the mutants listed in the CHANGELOG.
- `claude_spec.lua`, `homes_spec.lua`, `tokens_spec.lua`, `writable_spec.lua`, `sections_spec.lua`: `~/.claude`, other homes, secrets without a telling name, writable approvals, one check per preview section.

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
