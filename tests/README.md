# Tests

```sh
nvim -l tests/run.lua                  # every tests/*_spec.lua, one headless nvim each
nvim -l tests/run.lua tests/x_spec.lua # one spec file
```

`tests/run.lua` builds a private root (fake `$HOME` with fake credentials, outside `/tmp`) for the whole run, fails when a spec file leaves a `bwrap` or relay process behind, and removes the root. Set `XYNO_TEST_BASE` to choose where it is created. A runner that is killed with SIGKILL cannot clean up; its root and scratch directory carry an `.owner` file (pid and start time) and the NEXT run removes every such directory whose runner is gone (`tests/reaper.lua`; directories without an owner file only when over a day old; `XYNO_TEST_REAP_BASES` replaces the searched places, the reaper's own specs use it). Without a usable `$HOME` (`HOME=/nonexistent`) it falls back to `$XDG_CACHE_HOME`, then to `<checkout>/.test-root` (removed again); with nowhere writable outside `/tmp` it prints `SKIP all specs (...)` and exits 0.

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
- `round5_spec.lua`: the third verification (login file through a hard link and in the denylist view, credential files the hidden list missed, editor directories and subdirectories of the project, the scan on very long lines, token formats and boundaries, the probe, the survivors of the independent mutation run, the reaper of a killed run's leftovers).
- `round6_spec.lua`: the sixth round (absolute bwrap path, names planted in subdirectories and the end-of-run quarantine, mise/rust-toolchain locks, the editable-files report, the scan by content, a credential inside a locked directory, the survivors of the fifth round's mutation run, the `~/.claude.json` copy, docs against code).
- `round7_spec.lua`: the seventh round (the end-of-run sweep inside `target/` / `node_modules/` / virtualenvs, the walk bounds that are reported, a renamed directory, `.npmrc` / `.yarnrc.yml` / `.githooks` / `.mvn` / `.pnpmfile.cjs` / `.dir-locals.el` / `.lvimrc`, and the survivors of the independent mutation run: a hidden directory inside a read-only one, `dir_sig`, the `~/.claude.json` guards, file modes, token lengths).
- `round8_spec.lua`, `round8_net_spec.lua`, `round8_scan_spec.lua`: the eighth round (a runner that is killed takes its spec child with it, protected names compared by content: moved and tampered, changed deep in the tree, the quarantine under read-only parents, nested skipped directories, the names added in round 8, the exact subdirectory mount budget, the address check at every boundary, the proxy's pumps and connection count, the URL finder of the content scan).
- `round9_spec.lua`: the ninth round (user info of git:// and ftp:// URLs, the validators of guard_dirs / guard_files / secret_allow / scan_depth, base64 private key headers, the minimum length of each token format, the reaper and the runner's cleanup of trees with read-only directories). Git write mode's bypasses (rebuilt `.git`, `commondir`, rebase state, submodule git directories) are in `git_write_spec.lua`.
- `gaps_spec.lua`: the ninth round's second pass (the changed lines shown for an edited `.nvmrc` / `.gitattributes` / `init.gradle`, `buildSrc` / `build-logic` sources, `node_modules/.bin`, the quarantine depth and the forced-removal budget). The git write allowlist (absent `config.worktree`, new and existing top-level names) is in `git_write_spec.lua`.
- `tables_spec.lua` (with `tables_expected.lua`, a written-out copy of every policy table): every entry of every hidden / read-only / masked / refused list is effective in a real run.
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
