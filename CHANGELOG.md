# Changelog

## Unreleased

### Fifth hardening round

The third verification (a hard-link and login-file probe, a scanner timing probe, an independent mutation run of 213 mutants) found the following; each was reproduced and has a spec in `tests/round5_spec.lua` that failed before the fix (run against the previous commit: 25 of the new specs failed) and passes now.

- **F1 login file through a hard link** (host file changed): `ln ~/.claude/.credentials.json proj/hl_claude` made the read-only bound login writable through the project name. The login is now part of the `plan.CODE_RUNS_OUTSIDE` list that is compared by inode with the project's multi-link files (the name is hidden), and a writable approval for it is refused.
- **F2 login file in `home = "denylist"`**: it was directly writable there. It is locked read-only in `plan.HOME_READONLY` now, so a token refresh is not saved in either view (documented).
- **F3 credential files the hidden list missed** (denylist view): `~/.config/sops` (age keys), `~/.gem/credentials`, `~/.config/pypoetry/auth.toml`, `~/.pip/pip.conf`, `~/.config/pip/pip.conf`, `~/.npm/_logs` are in `plan.HIDDEN`.
- **F4 subdirectories**: `.cargo`, `.envrc`, `.mise.toml`, `.nvim.lua`, `.nvimrc`, `.exrc`, `.claude`, `.mcp.json`, `.vscode`, `.zed`, `.idea`, `.helix`, `.husky`, `.devcontainer`, `.pre-commit-config.yaml`, `.lldbinit`, `.gdbinit` that exist in any subdirectory the walk found are read-only (`plan.MEMBER_READONLY`, was `.cargo` and `.envrc`). A file the agent CREATES in a subdirectory is still not prevented (a mount per directory and name would be thousands); the plan and the preview say so, and `release()` compares those names (`plan.WATCH_NAMES`, plus a new nested `.git`) in up to 400 subdirectories with the state at launch and warns about every new one (`handle.planted`). It neither prevents nor removes them. README and help text no longer claim more.
- **F5 editor and hook directories of the project root**: `.zed`, `.idea`, `.helix`, `.husky`, `.devcontainer`, `.pre-commit-config.yaml`, `.lldbinit`, `.gdbinit` are read-only when present and masked / bound to an empty read-only file while absent (placeholders removed when the run ends), like `.vscode`; they cannot be renamed away either.
- **F6 quadratic scan**: the URL pattern was retried from every letter, so 64 KB of letters took 16 s and the 400 ms budget (only checked between files) did not help. The scheme is now looked for from each `://` (a 256 KB line takes about 30 ms for every shape tried: letters, hex, base64, dashes, `-----BEGIN ` repeated, `sk-a`, `a://`, minified code) and the budget is checked between lines inside a file; a run out of time reports `truncated`.
- **F7 boundaries and formats**: a token with a distinctive prefix is found glued to the end of a word (`tokenghp_...`, `1ghp_...`, `idAKIA...`; an upper-case word before an AWS key id still stops it); GitHub, GitLab, npm and Hugging Face tokens use a minimum length (the 41-character case); private key headers are found in any case and with tabs or several spaces; new formats: Hugging Face, DigitalOcean, Shopify, Slack app tokens, Stripe test keys, legacy `sk-` OpenAI keys. Still not found (documented): URL-encoded, HTML-entity and hex headers, base64 wrapped inside the header or encoded twice, UTF-16.
- **F8** (documented): the `~/.claude.json` copy keeps `oauthAccount.accountUuid`, a top-level `env`, `awsAuthRefresh`, `hooks` and `cachedGrowthBookFeatures`.
- **Plan speed**: a path-only secret (`.docker/config.json`) was tested by building and lower-casing the full path of every file; it is now tested only for files whose base name can end such a path. A project with 100000 files in `target/` and 100000 in an unskipped directory plans in 0.25 s instead of 0.73 s.
- **Runner**: a runner killed with SIGKILL left its private root and scratch directory (the verifier found `/tmp/xyno-run-*` and `~/.cache/xyno-sandbox-test-*`). Both carry an `.owner` file (pid and start time) and the next run removes those of dead runners (`tests/reaper.lua`; ownerless ones only when over a day old; symlinks never followed). `HOME=/nonexistent` is green now (two spec hermeticity bugs: a spec that counted every notification, including Neovim's own "cannot write nvim.log", and a spec that assumed `<checkout>/.test-root` was not in use by the outer run).
- **Survivors of the independent mutation run** that were real gaps now have specs: the readiness probe is pinned to the real isolation flags and the read-only root (`probe_argv`), `M.plan()` with a refused status, `ENV` among the dangerous variables, no "tree is large" note for a small tree, the hard-link record of a credential alias, the `guard_files` dedupe, `policy.readonly` may name `~` (writable and hidden may not), the agent found through `$PATH` (own home and another user's home, and a symlink out of its directory), `store.save` with an unencodable state, the 203.0.113.0/24 range and the octet limits of `net.is_public_ip`. The others of the 53 were equivalent or cosmetic (error branches, off-by-one on an unpinned boundary); one more, deleting `allow_other(found, ...)` for a bare agent name, is equivalent because its `$PATH` directory is shown whole anyway.

Mutation check of the fifth round (each edit applied to a copy of the repository in the scratchpad, `tests/round5_spec.lua` run in it, the result recorded): 88 mutants. 86 killed, 1 equivalent (`exe_slash_other`), 1 withdrawn (`reaper_follow_links`: the edit removed a second `type == "directory"` check that the directory listing already guarantees, so the redundant condition was deleted from the code). `glpat_min` (GitLab minimum length) survived its first run and led to a stronger token spec. In a first draft the deadline mutants (`no_deadline_pass`, `timed_not_truncated`) were only killed by an unrelated, timing-dependent spec; the spec for a time budget that runs out INSIDE a file was rewritten so that it kills them itself. Mutants that would make the runner delete directories were run with `XYNO_TEST_REAP_BASES` pointing at a private directory, never against the real `/tmp` or `~/.cache`. The full suite passes with the real `$HOME` and with `HOME=/nonexistent`.

| mutants | edit | result |
|---|---|---|
| `login_not_code_hardlink`, `login_not_readonly` | login file removed from `CODE_RUNS_OUTSIDE` / from `HOME_READONLY` | killed |
| `hidden_.config_sops`, `hidden_.gem_credentials`, `hidden_.config_pypoetry_auth.toml`, `hidden_.pip_pip.conf`, `hidden_.config_pip_pip.conf`, `hidden_.npm__logs` | one entry removed from `HIDDEN` each | killed (6) |
| `member_no_claude`, `member_no_husky` | a name removed from `MEMBER_READONLY` | killed |
| `watch_dirs_empty`, `watch_cap_off`, `watch_note_gone`, `watch_note_always`, `watch_no_git` | the watched directories not filled / cap off / note off or always / `.git` not watched | killed (5) |
| `planted_all`, `planted_none`, `planted_not_recorded`, `planted_level`, `planted_before_empty`, `watched_lstat` | `release()` reports everything / nothing / not recorded / wrong level / empty launch state / never sees a name | killed (6) |
| `root_ro_no_zed` .. `root_ro_no_gdbinit` (8) | one name removed from `PROJECT_READONLY` | killed (8) |
| `mask_no_zed`, `mask_no_devcontainer`, `guard_no_lldbinit`, `guard_no_precommit` | an absent name no longer masked / guarded | killed (4) |
| `url_quadratic` | URL search retried from every letter again | killed (spec file hangs, killed by the runner after 240 s) |
| `url_at_skip`, `no_deadline_check`, `no_deadline_pass`, `timed_not_truncated` | next `://` skipped / deadline not checked / not passed / not reported | killed (4) |
| `gh_exact`, `glpat_min`, `prefixed_off`, `nonupper_any`, `nonupper_never` | exact length again / wrong minimum / prefix rule off / AWS rule too wide or never | killed (5, `glpat_min` after the spec was strengthened) |
| `key_case`, `key_no_lower`, `key_tab` | header only upper case / not lower-cased / spaces only | killed (3) |
| `pat_hf`, `pat_do`, `pat_shp`, `pat_xapp`, `pat_stripe_test`, `pat_openai_legacy`, `do_len` | a new format removed / wrong length | killed (7) |
| `plast_walk_off`, `plast_tree_off`, `plast_walk_nolower`, `plast_key_wrong` | path-only secrets not found (walk, shown tree), name not lower-cased, wrong key | killed (4) |
| `probe_no_flags`, `probe_rw_root`, `probe_no_net` | the probe without the isolation flags / `--bind /` / `--share-net` | killed (3) |
| `plan_refused_ignored`, `env_ENV_off`, `tree_large_always`, `hardlink_record_gone`, `gseen_off`, `readonly_forbid_whole`, `save_encode_ignored` | the survivors of the independent run | killed (7) |
| `net_doc_range`, `net_octet`, `net_octet2` | 203.0.113.0/24 not refused, octet limit 256 / 255 | killed (3) |
| `exe_slash_own`, `exe_real_own` | bare agent name not looked up in `$PATH` / the real file of a symlink not shown (own home) | killed (2) |
| `exe_slash_other` | `allow_other(found, ...)` deleted | equivalent: the `$PATH` directory is shown whole anyway |
| `runner_no_reap`, `runner_no_owner_root`, `runner_no_owner_tmp` | the runner does not reap / does not mark its directories | killed (3) |
| `reaper_alive_always`, `reaper_start_ignored`, `reaper_no_trim`, `reaper_garbage_alive`, `reaper_default_no_tmp`, `reaper_legacy_always`, `reaper_legacy_never`, `reaper_probe_age`, `reaper_stranger`, `reaper_override_ignored`, `reaper_owner_field` | each condition of the reaper flipped (those that would delete were run with `XYNO_TEST_REAP_BASES` pointing at a private directory) | killed (11) |

### Fourth hardening round

The second verification of the third round found the following, each confirmed by running it. Every fix has a spec that failed before it (checked against the previous commit) and passes now; the mutation table is below.

- **Writable approvals for code that runs outside the sandbox**: `~/.config/direnv`, `~/.config/mise`, `~/.claude/{settings.json,hooks,commands,agents}`, `~/.local/share/nvim`, `~/.zshenv`, `~/.profile`, `~/.inputrc`, `~/.config/git`, `~/.cargo/config.toml`, `~/.rustup`, `~/.config/fish`, `~/.tmux.conf` and more were approved. The forbidden list is now generated from `plan.CODE_RUNS_OUTSIDE` (eight documented categories), the refusal names the category, a parent of a listed path is refused as before, and there is no override (`expert_exceptions` still only concerns environment variables). (`tests/round4_spec.lua`)
- **Hard link write-through**: `ln ~/.bashrc proj/dot_bashrc` made the project name writable and every write reached the real file (reproduced in a real sandbox before the fix). Project names whose inode matches any file of the code-runs list, or a locked file of the project (`.git/config`, `.git/hooks`, `.envrc`, ...), are hidden (empty, read-only); files are compared before directories under a 1500-file budget with a note when it runs out. Every other multi-link project file is reported as a note and in `plan.multilinks`.
- **Content scan boundaries**: `key=-----BEGIN RSA PRIVATE KEY-----MIIE...` on one line was missed (the header needed a non-word character after the dashes); a token after a JSON `\n`/`\t` escape was missed. Fixed, plus a private key header inside base64 (three alignments). A matrix spec covers 23 wrappers (quotes, `=`, `:`, JSON, YAML, URLs, CRLF) for eight token formats.
- **kill -9 leftovers**: the empty file that hidden files are bound to stayed in Neovim's temporary directory (`/tmp/nvim.<user>/<id>`) and was shared by all launches. Every launch now has its own, removed by `release()`; it and Neovim's emptied directory are recorded and removed by the next launch. A relay inside the sandbox cannot do this (its socket directory is read-only there), so a Neovim that is never started again leaves them.
- **Performance**: matching every file name against the ~250 secret globs compiled each glob again per file: a directory with 100000 files (not `target/`) took 18 s to plan. A compiled matcher (exact set, bucketed prefix/suffix) brings it to 0.4 s; the content scan also stops at 6000 directories and on its time budget while entering directories, and reads file systems that report no entry types. A plan for 100000 files in `target/` builds in about 0.2 s (0.4 s with 40000 directories, where the socket search stops at its budget and says so).
- **Runner**: `HOME=/nonexistent` died with E739 in `make_root`; it now falls back (`$XDG_CACHE_HOME`, `<checkout>/.test-root`, removed afterwards) and skips cleanly with a reason where nothing is writable.
- **Bug found by the new specs**: `validate_exception` raised an error for a non-table, non-string argument (a number) instead of refusing it.
- **Surviving mutants of the third round**: specs for `run_keep` argv, a socket under `/tmp`, `home_allow` outside `$HOME`/through symlinks, `NO_PROXY`, hard-link aliases, `..` in approvals, submodule configs, every sanitizer branch, the URL placeholder filter, key file name suffixes, `/var/run`, kept `/run` entries, `$NVIM`, relay signals and bind address, a double `release()`, and the front door of approvals. (`tests/survivors2_spec.lua`)

Mutation check of the fourth round (each edit applied to a copy of the repository outside /tmp, the named spec file run, the copy deleted): 102 mutants, 102 killed, 0 survived. One earlier candidate (dropping `name ~= p` in the hard-link loop) was equivalent, so that redundant condition was removed from the code.

| mutation | edit | file | result |
|---|---|---|---|
| run_keep_all_rw | add("sockets", k.why, "--ro-bind", k.path, k.path) -> add("sockets", k.why, "--bind", k.path, k.path) | plan.lua | killed by survivors2_spec.lua |
| in_masked_tmp_always_false | local in_masked = function(p) if inside(p, "/tmp") then -> local in_masked = function(p) if false then | plan.lua | killed by survivors2_spec.lua |
| home_allow_inside_check | if not (p and p ~= home and inside(p, home) and exists(p)) t -> if not (p and p ~= home and exists(p)) then | plan.lua | killed by survivors2_spec.lua |
| home_allow_not_home_itself | if not (p and p ~= home and inside(p, home) and exists(p)) t -> if not (p and inside(p, home) and exists(p)) then | plan.lua | killed by survivors2_spec.lua |
| home_allow_symlink | if lstat_type(p) == "link" then -- bwrap cannot mount on a s -> if false then -- bwrap cannot mount on a symlink | plan.lua | killed by survivors2_spec.lua |
| home_allow_symlink_target_unchecked | if real and real ~= p then return allow(real, why) end retur -> if real and real ~= p then aseen[real] = true plan | plan.lua | killed by survivors2_spec.lua |
| no_proxy_empty | add("setenv", "no direct connections", "--setenv", "NO_PROXY -> add("setenv", "no direct connections", "--setenv", | plan.lua | killed by survivors2_spec.lua |
| no_proxy_lower_empty | add("setenv", "no direct connections", "--setenv", "no_proxy -> local _ = 1 | plan.lua | killed by survivors2_spec.lua |
| hardlink_alias | hide(m.path, "hard link of the hidden " .. h.path) -> local _ = m | plan.lua | killed by survivors2_spec.lua |
| hardlink_cred_alias | hide(name, "hard link of the credential " .. p) -> local _ = name | plan.lua | killed by round3_spec.lua |
| validate_dotdot | if seg == ".." then return nil elseif -> if seg == ".." then -- dropped elseif | plan.lua | killed by survivors2_spec.lua |
| git_modules | add_config(mc) -> local _ = mc | plan.lua | killed by survivors2_spec.lua |
| git_modules_only_first | for _, mc in ipairs(probes.glob(g .. "/modules/*/config")) d -> for _, mc in ipairs(vim.list_slice(probes.glob(g . | plan.lua | killed by survivors2_spec.lua |
| san_token | password = true, token = true, -> password = true, | sanitize.lua | killed by survivors2_spec.lua |
| san_password | password = true, token = true, -> token = true, | sanitize.lua | killed by survivors2_spec.lua |
| san_askpass | askpass = true, -> (removed) | sanitize.lua | killed by survivors2_spec.lua |
| san_extraheader | extraheader = true, -> (removed) | sanitize.lua | killed by survivors2_spec.lua |
| san_cont_top | if drop_cont then drop_cont = line:sub(-1) == "\\" -> if drop_cont then drop_cont = false | sanitize.lua | killed by survivors2_spec.lua |
| san_cont_in | changes[#changes + 1] = section .. "." .. k .. " hidden" dro -> changes[#changes + 1] = section .. "." .. k .. " h | sanitize.lua | killed by survivors2_spec.lua |
| san_header_case | section = header:lower() -> section = header | sanitize.lua | killed by survivors2_spec.lua |
| san_key_case | local k = key:lower() -> local k = key | sanitize.lua | killed by survivors2_spec.lua |
| san_helper_any_section | (section:match("^credential") and k == "helper") -> (k == "helper") | sanitize.lua | killed by survivors2_spec.lua |
| san_helper_dropped_never | (section:match("^credential") and k == "helper") or -> false or | sanitize.lua | killed by survivors2_spec.lua |
| san_bare_key | or line:match("^%s*([%w_-]+)%s*$") -> (removed) | sanitize.lua | killed by survivors2_spec.lua |
| san_userinfo | if new ~= line then -> if false then | sanitize.lua | killed by survivors2_spec.lua |
| scan_urlcreds_placeholder | for _, ph in ipairs({ "password", "passw0rd", "changeme", "s -> for _, ph in ipairs({}) do | scan.lua | killed by survivors2_spec.lua |
| scan_urlcreds_ph_redacted | , "********", "redacted" }) do -> , "********" }) do | scan.lua | killed by survivors2_spec.lua |
| scan_urlcreds_ph_secret | "changeme", "secret", "example" -> "changeme", "example" | scan.lua | killed by survivors2_spec.lua |
| scan_urlcreds_len | #pw < 8 -> #pw < 4 | scan.lua | killed by survivors2_spec.lua |
| scan_urlcreds_chars | pw:find("[%$%{%}<>%%]") -> pw:find("[%$%{%}<>]") | scan.lua | killed by survivors2_spec.lua |
| secret_idrsa | "sa.json", "serviceaccount.json", "*serviceaccount*.json", " -> "sa.json", "serviceaccount.json", "*serviceaccount | plan.lua | killed by survivors2_spec.lua |
| secret_idrsa_ed | "id_ecdsa*", "id_ed25519*", -> "id_ecdsa*", | plan.lua | killed by survivors2_spec.lua |
| secret_idrsa_dsa | "id_rsa*", "id_dsa*", -> "id_rsa*", | plan.lua | killed by survivors2_spec.lua |
| mask_varrun | M.MASKED_IF_DIR = { "/var/run" } -> M.MASKED_IF_DIR = {} | plan.lua | killed by survivors2_spec.lua |
| mask_varrun_always | if lstat_type(p) == "directory" then plan.masked[#plan.maske -> if lstat_type(p) ~= nil then plan.masked[#plan.mas | plan.lua | killed by survivors2_spec.lua |
| runkeep_none | M.RUN_KEEP = { "/run/current-system", "/run/booted-system",  -> M.RUN_KEEP = {} | plan.lua | killed by survivors2_spec.lua |
| runkeep_opengl | "/run/booted-system", "/run/opengl-driver" } -> "/run/booted-system" } | plan.lua | killed by survivors2_spec.lua |
| sockenv_nvim | , "NVIM", "NVIM_LISTEN_ADDRESS" } -> , "NVIM" } | plan.lua | killed by survivors2_spec.lua |
| sockenv_nvim_both | , "NVIM", "NVIM_LISTEN_ADDRESS" } -> } | plan.lua | killed by survivors2_spec.lua |
| relay_sighup | { "sigterm", "sigint", "sighup" } -> { "sigterm", "sigint" } | relay.lua | killed by survivors2_spec.lua |
| relay_sigint | { "sigterm", "sigint", "sighup" } -> { "sigterm", "sighup" } | relay.lua | killed by survivors2_spec.lua |
| relay_bind_all | server:bind("127.0.0.1", port) -> server:bind("0.0.0.0", port) | relay.lua | killed by survivors2_spec.lua |
| release_guard | if h.released then return end h.released = true -> h.released = true | init.lua | killed by survivors2_spec.lua |
| v_unknown_kind | if type(exc) ~= "table" or not M.EXCEPTION_KINDS[exc.kind] t -> if type(exc) ~= "table" then | plan.lua | killed by survivors2_spec.lua |
| v_unknown_kind_table | if type(exc) ~= "table" or not M.EXCEPTION_KINDS[exc.kind] t -> if not M.EXCEPTION_KINDS[exc.kind] then | plan.lua | killed by survivors2_spec.lua |
| v_empty | if type(v) ~= "string" or v == "" then -> if false then | plan.lua | killed by survivors2_spec.lua |
| v_empty_only | if type(v) ~= "string" or v == "" then -> if type(v) ~= "string" then | plan.lua | killed by survivors2_spec.lua |
| v_nonstring | if type(v) ~= "string" or v == "" then -> if v == "" then | plan.lua | killed by survivors2_spec.lua |
| v_envname | if not v:match("^[%a_][%w_]*$") then -> if false then | plan.lua | killed by survivors2_spec.lua |
| v_envname_anchor | if not v:match("^[%a_][%w_]*$") then -> if not v:match("^[%a_][%w_]*") then | plan.lua | killed by survivors2_spec.lua |
| code_drop_direnv | "/.config/direnv", -> (removed) | plan.lua | killed by round4_spec.lua |
| code_drop_rustup | "/.cargo/env", "/.rustup", -> "/.cargo/env", | plan.lua | killed by round4_spec.lua |
| code_drop_claude_hooks | "/.claude/settings.json", "/.claude/settings.local.json", "/ -> "/.claude/settings.json", "/.claude/settings.local | plan.lua | killed by round4_spec.lua |
| code_drop_zshenv | "/.zshrc", "/.zshenv", "/.zprofile" -> "/.zshrc", "/.zprofile" | plan.lua | killed by round4_spec.lua |
| code_ancestor_half | if inside(p, f) or inside(f, p) then return f .. " would run -> if inside(p, f) then return f .. " would run | plan.lua | killed by round4_spec.lua |
| code_child_half | if inside(p, f) or inside(f, p) then return f .. " would run -> if inside(f, p) then return f .. " would run | plan.lua | killed by round4_spec.lua |
| code_flatten | M.WRITABLE_FORBIDDEN_HOME[#M.WRITABLE_FORBIDDEN_HOME + 1] =  -> local _ = rel | plan.lua | killed by round4_spec.lua |
| code_category_msg | (" .. (code_runs_category(rel) or "code") .. ")" -> " | plan.lua | killed by round4_spec.lua |
| hl_code_loop | for _, rel in ipairs(M.WRITABLE_FORBIDDEN_HOME) do visit(bas -> for _, rel in ipairs({}) do visit(base .. rel, 0) | plan.lua | killed by round4_spec.lua |
| hl_never_hide | if not M.shadow(plan, name) then -> if false then | plan.lua | killed by round4_spec.lua |
| hl_git_paths | for _, sub in ipairs({ "/config", "/hooks", "/info", "/confi -> for _, sub in ipairs({}) do | plan.lua | killed by round4_spec.lua |
| hl_git_hooks | { "/config", "/hooks", "/info", "/config.worktree" } -> { "/config", "/info", "/config.worktree" } | plan.lua | killed by round4_spec.lua |
| hl_project_readonly | if inside(r.path, project) then if r.why == "git" then -> if false then if r.why == "git" then | plan.lua | killed by round4_spec.lua |
| hl_unknown_note | if #unknown > 0 then -> if false then | plan.lua | killed by round4_spec.lua |
| hl_budget | if code.stat >= M.HARDLINK_CODE_MAX then -> if false then | plan.lua | killed by round4_spec.lua |
| hl_budget_note | if code.stopped then plan.notes -> if false then plan.notes | plan.lua | killed by round4_spec.lua |
| hl_dirs_depth | elseif t == "directory" and d < 4 then code.queue -> elseif t == "directory" and d < 0 then code.queue | plan.lua | killed by round4_spec.lua |
| hl_queue | while qi <= #code.queue and not code.stopped do -> while false do | plan.lua | killed by round4_spec.lua |
| sc_loose | (pat[5] or boundary(line, i, j)) and -> boundary(line, i, j) and | scan.lua | killed by round4_spec.lua |
| sc_json_escape | local esc = i > 2 and s:sub(i - 2, i - 2) == "\\" and before -> local esc = false | scan.lua | killed by round4_spec.lua |
| sc_json_escape_n_only | before:match("[nrt]") -> before:match("[n]") | scan.lua | killed by round4_spec.lua |
| sc_b64_off | for _, form in ipairs(b64_forms(hdr)) do -> for _, form in ipairs({}) do | scan.lua | killed by round4_spec.lua |
| sc_b64_align | for k = 0, 2 do local enc -> for k = 0, 1 do local enc | scan.lua | killed by round4_spec.lua |
| sc_b64_cert | "-----BEGIN PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY" -> "-----BEGIN CERTIFICATE", "-----BEGIN RSA PRIVATE | scan.lua | killed by round4_spec.lua |
| sc_maxdirs | if qi > M.MAX_DIRS + 1 then -> if false then | scan.lua | killed by round4_spec.lua |
| sc_unknown_type | if ty == nil or ty == "unknown" then -> if false then | scan.lua | killed by round4_spec.lua |
| sc_dir_time | if (uv.hrtime() - t0) / 1e6 > M.MAX_MS then res.truncated, r -> local h = uv.fs_scandir(dir) | scan.lua | killed by round4_spec.lua |
| sc_private_key_pub | "%-%-%-%-%-BEGIN [%u ]*PRIVATE KEY[%u ]*%-%-%-%-%-" -> "%-%-%-%-%-BEGIN [%u ]*KEY[%u ]*%-%-%-%-%-" | scan.lua | killed by round4_spec.lua |
| d_empty_recorded | vim.fn.writefile({}, plan.empty_file) temp[#temp + 1] = plan -> vim.fn.writefile({}, plan.empty_file) | init.lua | killed by round4_spec.lua |
| d_reap_empty_name | or (name:match("%.empty$") and st.size == 0)) -> ) | init.lua | killed by round4_spec.lua |
| d_reap_empty_size | name:match("%.empty$") and st.size == 0 -> name:match("%.empty$") | init.lua | killed by round4_spec.lua |
| d_dir_recorded | items[#items + 1] = { d, "dir" } -> local _ = d | init.lua | killed by round4_spec.lua |
| d_per_launch | return { empty = vim.fn.tempname() .. ".empty", -> _G.__xe = _G.__xe or (vim.fn.tempname() .. ".empty | init.lua | killed by round4_spec.lua |
| d_net_recorded | items[#items + 1] = { h.net_dir, "temp" } -> local _ = h | init.lua | killed by round4_spec.lua |
| f_pcall | local ok = pcall(vim.fn.mkdir, d, "p") if not ok then return -> vim.fn.mkdir(d, "p") | run.lua | killed by round4_spec.lua |
| f_skip | if not root then -- nothing -> if false then -- nothing | run.lua | killed by round4_spec.lua |
| f_skip_exit | io.stdout:write("RESULT passed=0 failed=0 skipped=1 xfailed= -> io.stdout:write("RESULT passed=0 failed=0 skipped= | run.lua | killed by round4_spec.lua |
| f_fallback_repo | repo .. "/.test-root", }) do -> }) do | run.lua | killed by round4_spec.lua |
| f_made_dirs | vim.uv.fs_rmdir(d) -- only when empty -> local _ = d | run.lua | killed by round4_spec.lua |
| x_exc_nontable | vim.inspect(type(exc) == "table" and exc.kind or nil) -> vim.inspect(exc and exc.kind) | plan.lua | killed by survivors2_spec.lua |
| hl_shadow_dropped2 | if not M.shadow(plan, name) then -> if true then | plan.lua | killed by round4_spec.lua |
| docs_readme_override | there is no override -> there is an override | README.md | killed by docs_spec.lua |
| m_exact | if exact[n] then return true end -> if false then return true end | plan.lua | killed by round4_spec.lua |
| m_except | if n:sub(-4) == ".pub" or ex_set[n] then -> if n:sub(-4) == ".pub" then | plan.lua | killed by round4_spec.lua |
| m_pub | if n:sub(-4) == ".pub" or ex_set[n] then -> if ex_set[n] then | plan.lua | killed by round4_spec.lua |
| m_prefix | if n:sub(1, #pre) == pre then -> if n:sub(1, #pre) == pre and #n > #pre then | plan.lua | killed by round4_spec.lua |
| m_prefix_bucket | local list = prefix[n:sub(1, 1)] -> local list = prefix[n:sub(2, 2)] | plan.lua | killed by round4_spec.lua |
| m_suffix | if #n >= #suf and n:sub(-#suf) == suf then -> if #n > #suf and n:sub(-#suf) == suf then | plan.lua | killed by round4_spec.lua |
| m_suffix_bucket | list = suffix[n:sub(-1)] -> list = suffix[n:sub(1, 1)] | plan.lua | killed by round4_spec.lua |
| m_mixed | for _, pat in ipairs(mixed) do if n:match(pat) then -> for _, pat in ipairs({}) do if n:match(pat) then | plan.lua | killed by round4_spec.lua |
| m_cache_invalidate | if not c or c.n ~= #globs or c.except ~= except or c.en ~= # -> if not c then | plan.lua | killed by round4_spec.lua |
| m_star_only | elseif stars == 1 and l:sub(-1) == "*" and #l > 1 then -> elseif stars == 1 and l:sub(-1) == "*" then | plan.lua | killed by round4_spec.lua |

Remaining limits (also in the README): the code-runs list is a list of known places, not proof; hard links to files outside both lists, or in directories the scan skips, stay writable (the plan warns when it sees a multi-link file); a key in base64 is found only as a private key header, every other encoded secret is not; the guard that registers Neovim's emptied temporary directory is only for `nvim.<user>/<id>` and has no spec of its own; timings are from one machine.

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
