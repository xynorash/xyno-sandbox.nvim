-- Tenth round: the survivors of the independent mutation run (see CHANGELOG). The git write allowlist is pinned entry by
-- entry (a literal list here, not the plan table) and by real git commands in a real sandbox; the new-name audit below
-- modules/, the submodule recursion, the report formats and the diff_lines bounds are pinned exactly.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local guard = require("xyno_sandbox.guard")
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local harness = require("xynotest.harness")
local uv = vim.uv

before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
end)

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text or "x\n")
  f:close()
end

describe("git write allowlist: every name git itself writes stays writable", function()
  local ALLOWED = {
    "HEAD", "ORIG_HEAD", "FETCH_HEAD", "COMMIT_EDITMSG", "TAG_EDITMSG", "SQUASH_MSG", "AUTO_MERGE",
    "CHERRY_PICK_HEAD", "REVERT_HEAD", "packed-refs", "shallow", "index", "objects", "refs", "logs",
    "description", "lfs", "rr-cache", "gc.log", "gc.pid", "lost-found",
    "MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "BISECT_LOG", "BISECT_START", "NOTES_MERGE_REF", "NOTES_MERGE_WORKTREE",
    "sharedindex.0123abcd", "index.lock", "HEAD.lock", "packed-refs.lock",
  }
  it("each of these names is allowed (one literal list, so a flipped entry fails by name)", function()
    for _, n in ipairs(ALLOWED) do
      H.ok(plan.git_write_allowed(n), n .. " must stay writable")
    end
  end)
  it("each prefix is pinned on its own", function()
    for _, n in ipairs({ "MERGE_X", "BISECT_X", "NOTES_MERGE_X", "sharedindex.X" }) do
      H.ok(plan.git_write_allowed(n), n)
    end
    -- just short of a prefix is not allowed
    for _, n in ipairs({ "MERGE", "BISECT", "NOTES_MERGE", "sharedindex", "xMERGE_X", "NOTES_X" }) do
      H.not_ok(plan.git_write_allowed(n), n)
    end
  end)
  it("everything that runs or redirects stays out", function()
    for _, n in ipairs({
      "hooks", "config", "info", "config.worktree", "commondir", "gitdir", "modules", "worktrees", "remotes",
      "branches", "rebase-merge", "rebase-apply", "sequencer", "alternates", "evil", "locks", "x.lock.d", "HEAD2",
    }) do
      H.not_ok(plan.git_write_allowed(n), n)
    end
  end)
end)

describe("git write mode: the history commands git users run all work (each file of the allowlist is needed)", function()
  local function inside(script, project)
    H.need_sandbox()
    if vim.fn.executable("git") ~= 1 then
      harness.skip("git not installed")
    end
    sb.config.network = "open"
    sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, { git_write = true })
    local wrapped, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
    H.ok(wrapped, err)
    local r = vim.system(wrapped, { text = true, cwd = project }):wait(120000)
    h.release()
    return "\n" .. (r.stdout or "") .. (r.stderr or ""), r
  end
  local saved = vim.deepcopy(sb.config)
  after_each(function()
    sb.config = vim.deepcopy(saved)
  end)
  local G = "git -c user.name=agent -c user.email=a@example.invalid "

  it("checkout -b (HEAD), reset --hard (ORIG_HEAD), pack-refs (packed-refs), tag -a, merge --squash, cherry-pick", function()
    local project = H.fixture("basic", { git = true })
    H.git(project, "commit", "-q", "--allow-empty", "-m", "second")
    local script = table.concat({
      "cd " .. project,
      G .. "checkout -q -b topic 2>&1; echo checkout=$?",
      "echo more >> README.md; " .. G .. "add README.md; " .. G .. "commit -q -m third 2>&1; echo commit=$?",
      G .. "reset -q --hard HEAD~1 2>&1; echo reset=$?",
      G .. "pack-refs --all 2>&1; echo packrefs=$?",
      G .. "tag -a v1 -m v1 2>&1; echo tag=$?",
      G .. "checkout -q main 2>&1; echo back=$?",
      G .. "merge --squash topic 2>&1 >/dev/null; echo squash=$?",
      G .. "merge --no-ff -q topic -m m 2>&1; echo merge=$?",
      G .. "rev-parse ORIG_HEAD >/dev/null 2>&1; echo origHead=$?",
    }, "\n")
    local out = inside(script, project)
    for _, k in ipairs({ "checkout", "commit", "reset", "packrefs", "tag", "back", "squash", "merge" }) do
      H.match(out, "\n" .. k .. "=0", true, k .. " must work in git write mode:\n" .. out)
    end
    local branch = H.git(project, "branch", "--list", "topic")
    H.match(branch, "topic", true)
    H.match(H.git(project, "tag", "--list"), "v1", true)
  end)

  it("fetch (FETCH_HEAD), gc and update-ref work", function()
    local project = H.fixture("basic", { git = true })
    local script = table.concat({
      "cd " .. project,
      G .. "fetch -q . main 2>&1; echo fetch=$?",
      G .. "gc -q 2>&1; echo gc=$?",
      G .. "update-ref refs/heads/x HEAD 2>&1; echo updateref=$?",
    }, "\n")
    local out = inside(script, project)
    for _, k in ipairs({ "fetch", "gc", "updateref" }) do
      H.match(out, "\n" .. k .. "=0", true, k .. ":\n" .. out)
    end
  end)
end)

describe("git_top / git_audit: a new name below modules/ and the top level", function()
  local function gitdir()
    local d = H.tmpdir() .. "/g/.git"
    vim.fn.mkdir(d .. "/objects", "p")
    vim.fn.mkdir(d .. "/modules/sub", "p")
    write(d .. "/HEAD", "ref: refs/heads/main\n")
    return d
  end
  it("a submodule git directory made by hand is reported, one that was there at launch is not", function()
    local d = gitdir()
    local before = guard.git_top({ d })
    H.eq({}, guard.git_audit(before, { d }))
    vim.fn.mkdir(d .. "/modules/evil", "p")
    H.eq({ d .. "/modules/evil" }, guard.git_audit(before, { d }))
  end)
  it("a new allowed top-level name is fine, a new other one is reported, an old other one is not", function()
    local d = gitdir()
    write(d .. "/oldthing", "1")
    local before = guard.git_top({ d })
    write(d .. "/ORIG_HEAD", "1")
    write(d .. "/newthing", "1")
    H.eq({ d .. "/newthing" }, guard.git_audit(before, { d }))
  end)
  it("a name that was in modules/ at launch counts as old (the recorded set is under <dir>/modules)", function()
    local d = gitdir()
    local before = guard.git_top({ d })
    H.eq({ sub = true }, before[d .. "/modules"])
    H.eq(true, before[d].HEAD)
    H.eq(true, before[d].modules)
  end)
  it("audit with no recorded launch state treats every non-allowed name as new", function()
    local d = gitdir()
    write(d .. "/zzz", "1")
    local out = guard.git_audit(nil, { d })
    table.sort(out)
    H.eq({ d .. "/modules", d .. "/modules/sub", d .. "/zzz" }, out)
  end)
end)

describe("git write plan: submodule git directories are audited, bounded by GIT_MODULES_DEPTH (pure plan)", function()
  local function fakeprobes(entries)
    local function kids(dir)
      local out, prefix = {}, dir .. "/"
      for p, t in pairs(entries) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), t }
        end
      end
      table.sort(out, function(x, y)
        return x[1] < y[1]
      end)
      return out
    end
    return {
      stat_type = function(p)
        return entries[p]
      end,
      exists = function(p)
        return entries[p] ~= nil
      end,
      list = kids,
      glob = function(pat)
        local out = {}
        local dir = pat:gsub("/%*$", "")
        for _, e in ipairs(kids(dir)) do
          out[#out + 1] = dir .. "/" .. e[1]
        end
        return out
      end,
      read_line = function()
        return nil
      end,
      realpath = function(p)
        return entries[p] and p or nil
      end,
    }
  end
  local function build(entries)
    return plan.build({
      project = "/h/proj",
      tmp_dir = "/h/scratch",
      cwd = "/h/proj",
      home = "/h",
      uid = 1000,
      probes = fakeprobes(entries),
      env = { PATH = "/bin", HOME = "/h" },
      cmd = { "agent" },
      aux = { empty = "/aux/empty", claude_json = "/aux/claude.json", git_dir = "/aux/git" },
      config = { network = "open", home = "denylist", policy = { git_write = true } },
    })
  end
  local function chain(levels)
    local e = { ["/h"] = "directory", ["/h/proj"] = "directory", ["/h/scratch"] = "directory", ["/h/proj/.git"] = "directory" }
    local cur = "/h/proj/.git"
    local dirs = { cur }
    for i = 1, levels do
      e[cur .. "/modules"] = "directory"
      cur = cur .. "/modules/m" .. i
      e[cur] = "directory"
      dirs[#dirs + 1] = cur
    end
    return e, dirs
  end

  it("the project git dir and every submodule dir to GIT_MODULES_DEPTH are audited, deeper ones are not", function()
    H.eq(4, plan.GIT_MODULES_DEPTH)
    local e, dirs = chain(5)
    e["/h/proj/.git/modules/afile"] = "file"
    local p = build(e)
    local got = {}
    for _, x in ipairs(p.git_audit) do
      got[x] = true
    end
    for i = 1, 4 do
      H.eq(true, got[dirs[i]], "level " .. i)
    end
    H.eq(nil, got[dirs[5]], "level 5 is past the bound")
    H.eq(nil, got[dirs[6]], "level 6 is past the bound")
    H.eq(nil, got["/h/proj/.git/modules/afile"], "a plain file below modules/ is not a git directory")
    H.eq(4, #p.git_audit)
  end)
  it("a project git dir without modules/ is audited alone", function()
    local e = chain(0)
    H.eq({ "/h/proj/.git" }, build(e).git_audit)
  end)
end)

describe("diff_lines bounds", function()
  it("shows the changed line, nothing after it", function()
    H.eq({ "- a2", "+ b2" }, guard._diff_lines("a1\na2\na3\n", "a1\nb2\na3\n", 6))
  end)
  it("a created text shows exactly its lines (no extra empty trailing line shown)", function()
    H.eq({ "+ one", "+ two" }, guard._diff_lines("", "one\ntwo\n", 6))
  end)
  it("starts at the right line of a later hunk", function()
    local a = "1\n2\n3\n4\n5\n6\n"
    local b = "1\n2\n3\n4\nfive\n6\n"
    H.eq({ "- 5", "+ five" }, guard._diff_lines(a, b, 6))
  end)
  it("is cut at max lines, exactly", function()
    local t = {}
    for i = 1, 20 do
      t[i] = "l" .. i
    end
    local out = guard._diff_lines("", table.concat(t, "\n") .. "\n", 5)
    H.eq(5, #out)
    H.eq("+ l5", out[5])
    H.eq(6, #guard._diff_lines("", table.concat(t, "\n") .. "\n", 6))
  end)
  it("cuts a line at 72 characters plus an ellipsis; 72 exactly is untouched", function()
    local l72, l73 = ("z"):rep(72), ("z"):rep(73)
    H.eq({ "+ " .. l72 }, guard._diff_lines("", l72 .. "\n", 6))
    H.eq({ "+ " .. l72 .. "..." }, guard._diff_lines("", l73 .. "\n", 6))
  end)
  it("nil when a text was not kept", function()
    H.eq(nil, guard._diff_lines(nil, "x", 6))
    H.eq(nil, guard._diff_lines("x", nil, 6))
  end)
end)

describe("REVIEW_NAMES covers both Gradle init script spellings", function()
  it("init.gradle and init.gradle.kts", function()
    local set = {}
    for _, n in ipairs(plan.REVIEW_NAMES) do
      set[n] = true
    end
    H.ok(set["init.gradle"])
    H.ok(set["init.gradle.kts"])
  end)
  it("an edited init.gradle.kts is reported", function()
    local p = H.tmpdir() .. "/proj"
    write(p .. "/init.gradle.kts", "a\n")
    local before = guard.snapshot(p)
    write(p .. "/init.gradle.kts", "b\n")
    local res = guard.compare(before, guard.snapshot(p))
    H.eq(1, #res.review)
  end)
end)

describe("node_modules/.bin of a dependency is not recorded, wherever the project lives", function()
  it("a dependency below a path that itself has no node_modules in it", function()
    local p = H.tmpdir() .. "/proj"
    write(p .. "/node_modules/dep/node_modules/.bin/x", "1\n")
    write(p .. "/node_modules/@scope/dep/node_modules/.bin/z", "1\n")
    write(p .. "/node_modules/.bin/top", "1\n")
    local snap = guard.snapshot(p)
    H.ok(snap.bin[p .. "/node_modules/.bin/top"], "the project's own is recorded")
    H.eq(nil, snap.bin[p .. "/node_modules/dep/node_modules/.bin/x"])
    H.eq(nil, snap.bin[p .. "/node_modules/@scope/dep/node_modules/.bin/z"])
  end)
end)

describe("end-of-run report formats, exactly", function()
  local function review(n)
    local r = {}
    for i = 1, n do
      r[i] = { change = "changed", path = "/p/f" .. i, plus = i, minus = 0 }
    end
    return r
  end
  local function res(extra)
    return vim.tbl_extend("force", { review = {}, trees = {}, bin = {}, modified = {} }, extra)
  end
  local PRE = "files that run on your machine later were edited (review before you build or run them): "

  it("review: 8 entries are listed whole, the 9th switches to '; ... N in all'", function()
    local lines = guard.report(res({ review = review(8) }))
    local parts = {}
    for i = 1, 8 do
      parts[i] = ("changed /p/f%d +%d -0"):format(i, i)
    end
    H.eq(PRE .. table.concat(parts, "; "), lines[1])
    local l9 = guard.report(res({ review = review(9) }))[1]
    H.eq(PRE .. table.concat(parts, "; ") .. "; ... 9 in all", l9)
  end)
  it("review: shows the diff lines in brackets", function()
    local lines = guard.report(res({ review = { { change = "created", path = "/p/.nvmrc", plus = 1, minus = 0, lines = { "+ 20" } } } }))
    H.eq(PRE .. "created /p/.nvmrc +1 -0 [+ 20]", lines[1])
  end)

  local TPRE = "build sources that a tool compiles and RUNS on your machine at the next build were edited (read the diff before you build): "
  local function tree(i, names)
    return { change = "changed", path = "/p/buildSrc" .. i, plus = 2, minus = 1, names = names or {} }
  end
  it("trees: loud, 4 names per tree, 8 trees then '... N in all'", function()
    local lines, loud = guard.report(res({ trees = { tree(1, { "a", "b", "c", "d", "e" }) } }))
    H.eq(TPRE .. "changed /p/buildSrc1 +2 -1 (a, b, c, d)", lines[1])
    H.ok(loud[1])
    local ts = {}
    for i = 1, 9 do
      ts[i] = tree(i)
    end
    local l9 = guard.report(res({ trees = ts }))[1]
    H.match(l9, "changed /p/buildSrc8 +2 -1; ... 9 in all", true)
    H.no_match(l9, "buildSrc9", true)
    local l8 = guard.report(res({ trees = vim.list_slice(ts, 1, 8) }))[1]
    H.no_match(l8, "in all", true)
    H.match(l8, "buildSrc8 +2 -1", true)
  end)
  it("trees: a tree without counts shows none", function()
    local lines = guard.report(res({ trees = { { change = "removed", path = "/p/buildSrc", names = {} } } }))
    H.eq(TPRE .. "removed /p/buildSrc", lines[1])
  end)

  local BPRE = "node_modules/.bin changed (what `npm run` / `npx` starts on your machine; an install does this too, a plain file or a link out of node_modules is not what an install makes): "
  local function b(change, name, id)
    return { change = change, path = "/p/node_modules/.bin/" .. name, id = id }
  end
  it("bin: link targets and '(file)' are shown, the 6-entry cap ends in ', ...'", function()
    local lines = guard.report(res({ bin = { b("added", "l", "link:../x/y.js"), b("added", "f", "sha:abc"), b("added", "o", "other") } }))
    H.eq(BPRE .. "added 3: l -> ../x/y.js, f (file), o", lines[1])
    local many = {}
    for i = 1, 7 do
      many[i] = b("removed", "r" .. i, "x")
    end
    H.eq(BPRE .. "removed 7: r1, r2, r3, r4, r5, r6, ...", guard.report(res({ bin = many }))[1])
    H.eq(BPRE .. "removed 6: r1, r2, r3, r4, r5, r6", guard.report(res({ bin = vim.list_slice(many, 1, 6) }))[1])
  end)
  it("bin: added, changed and removed come in that order", function()
    local lines = guard.report(res({ bin = { b("removed", "c", "x"), b("changed", "b", "sha:1"), b("added", "a", "sha:2") } }))
    H.eq(BPRE .. "added 1: a (file); changed 1: b (file); removed 1: c", lines[1])
  end)
  it("bin: loud boundaries (a link to ../../ or an absolute path is loud; ../ and a relative inside is not; removal never)", function()
    local function loud_of(change, id)
      local _, loud = guard.report(res({ bin = { b(change, "x", id) } }))
      return loud[1] == true
    end
    H.ok(loud_of("added", "link:/usr/bin/curl"))
    H.ok(loud_of("added", "link:../../evil.sh"))
    H.ok(loud_of("changed", "sha:1"))
    H.not_ok(loud_of("added", "link:../pkg/cli.js"))
    H.not_ok(loud_of("added", "link:pkg/cli.js"))
    H.not_ok(loud_of("added", "link:.../x"))
    H.not_ok(loud_of("removed", "sha:1"))
    H.not_ok(loud_of("removed", "link:/usr/bin/curl"))
  end)
end)

describe("git write mode: host-side git battery after an agent that tried to plant (real sandbox)", function()
  local saved = vim.deepcopy(sb.config)
  after_each(function()
    sb.config = vim.deepcopy(saved)
  end)
  it("status, log, diff, fsck, gc, commit, fetch, checkout, submodule status and maintenance run nothing of the agent's", function()
    H.need_sandbox()
    if vim.fn.executable("git") ~= 1 then
      harness.skip("git not installed")
    end
    local project = H.fixture("basic", { git = true })
    local canary = H.tmpdir() .. "/FSRAN3"
    local c = "touch " .. canary
    local script = table.concat({
      "cd " .. project,
      "printf '[core]\\n\\tfsmonitor = " .. c .. "\\n\\thooksPath = /x\\n[filter \"f\"]\\n\\tsmudge = " .. c .. "\\n[alias]\\n\\tst = !" .. c .. "\\n[core]\\n\\tsshCommand = " .. c .. "\\n[credential]\\n\\thelper = !" .. c .. "\\n[gpg]\\n\\tprogram = " .. c .. "\\n' > .git/config.worktree",
      "printf '[core]\\n\\tfsmonitor = " .. c .. "\\n' > .git/config.worktree.x",
      "mkdir -p .git/worktrees/w .git/modules/m/hooks .git/hooks2",
      "printf '#!/bin/sh\\n" .. c .. "\\n' > .git/modules/m/hooks/post-checkout; chmod +x .git/modules/m/hooks/post-checkout",
      "printf '#!/bin/sh\\n" .. c .. "\\n' > .git/post-commit; chmod +x .git/post-commit",
      "printf '[core]\\n\\tfsmonitor = " .. c .. "\\n' > .git/modules/m/config",
      "echo '* filter=f' > .gitattributes",
      "echo '* filter=f' > .git/info/attributes",
      "echo /nonexistent > .git/objects/info/alternates",
      "echo 'gitdir: /x' > .git/gitdir; echo ../../x > .git/worktrees/w/commondir",
      "true",
    }, "\n")
    sb.config.network = "open"
    sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, { git_write = true })
    local wrapped, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
    H.ok(wrapped, err)
    vim.system(wrapped, { text = true, cwd = project }):wait(120000)
    local seen = H.capture_notify(function()
      h.release() -- the end-of-run sweep and git audit of the real flow
    end)
    H.ok(#seen > 0, "the sweep reported the planted names")
    local function git(...)
      return vim.system({ "git", "-C", project, "-c", "user.name=t", "-c", "user.email=t@t", ... }, { text = true }):wait(60000)
    end
    for _, args in ipairs({
      { "status" }, { "log", "--oneline" }, { "diff" }, { "fsck" }, { "gc", "-q" },
      { "commit", "-q", "--allow-empty", "-m", "host" }, { "fetch", "-q", "." }, { "checkout", "-q", "-b", "hostb" },
      { "submodule", "status" }, { "maintenance", "run", "--auto" }, { "stash", "list" },
    }) do
      git(unpack(args))
      H.eq(0, vim.fn.filereadable(canary), "git " .. args[1] .. " ran a planted command")
    end
  end)
end)
