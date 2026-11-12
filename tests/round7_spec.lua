-- Seventh round: the end-of-run sweep (skipped directories, walk bounds, renamed directories), auto-exec
-- config names of package managers and editors, and the survivors of the independent mutation run.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local guard = require("xyno_sandbox.guard")
local sanitize = require("xyno_sandbox.sanitize")
local store = require("xyno_sandbox.store")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text or "x\n")
  f:close()
end

local function inside(project, script)
  H.need_sandbox()
  sb.config.network = "open"
  local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
  H.ok(cmd, err)
  local r = vim.system(cmd, { cwd = project, text = true }):wait(60000)
  h.release()
  return (r.stdout or "") .. (r.stderr or ""), h
end

local function rel_list(project, paths)
  local out = {}
  for _, p in ipairs(paths) do
    out[#out + 1] = p:sub(#project + 2)
  end
  return out
end

-- ------------------------------------------------------------------ sweep: skipped directories
describe("the end-of-run sweep enters target/, node_modules/ and virtualenvs", function()
  for _, skip in ipairs({ "target", "node_modules", ".venv", "venv", "__pycache__" }) do
    it("a name planted below " .. skip .. "/ is found", function()
      local project = H.tmpdir()
      write(project .. "/src/main.rs")
      local before = guard.snapshot(project)
      write(project .. "/" .. skip .. "/debug/.cargo/config.toml", "[target.x]\nrunner='evil'\n")
      write(project .. "/" .. skip .. "/pkg/.envrc", "evil\n")
      vim.fn.mkdir(project .. "/" .. skip .. "/pkg/inner/.git/hooks", "p")
      write(project .. "/" .. skip .. "/pkg/inner/.git/hooks/pre-commit", "#!/bin/sh\n")
      local res = guard.compare(before, guard.snapshot(project))
      local got = rel_list(project, res.planted)
      H.eq({ skip .. "/debug/.cargo", skip .. "/pkg/.envrc", skip .. "/pkg/inner/.git" }, got)
      H.eq({}, res.incomplete)
    end)
  end

  it("a nested skipped directory (target inside node_modules) is walked too", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/node_modules/a/target/b", "p")
    local before = guard.snapshot(project)
    write(project .. "/node_modules/a/target/b/.envrc")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ "node_modules/a/target/b/.envrc" }, rel_list(project, res.planted))
  end)

  it("a name that existed in target/ at launch is not reported", function()
    local project = H.tmpdir()
    write(project .. "/target/debug/.cargo/config.toml")
    local before = guard.snapshot(project)
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({}, res.planted)
  end)

  it("the walk inside them has its own budget: the main budget is not used up by a big target/", function()
    local project = H.tmpdir()
    for i = 1, 30 do
      vim.fn.mkdir(project .. "/target/d" .. i, "p")
    end
    write(project .. "/sub/ok.txt")
    local old = guard.MAX_DIRS
    guard.MAX_DIRS = 5
    local snap = guard.snapshot(project)
    guard.MAX_DIRS = old
    H.eq(false, snap.truncated, "target/ is not counted against the main budget")
    H.ok(snap.skip_dirs > 0)
  end)
end)

describe("the walk bounds are reported, not silent", function()
  local function with(field, value, fn)
    local old = guard[field]
    guard[field] = value
    local ok, err = pcall(fn)
    guard[field] = old
    assert(ok, err)
  end

  it("a tree that grew past MAX_DIRS during the run: incomplete (the project is marked)", function()
    local project = H.tmpdir()
    write(project .. "/a/x")
    with("MAX_DIRS", 10, function()
      local before = guard.snapshot(project)
      H.eq(false, before.truncated)
      for i = 1, 30 do
        vim.fn.mkdir(project .. "/f" .. i, "p")
      end
      write(project .. "/zz/d1/d2/.envrc")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq(1, #res.incomplete, vim.inspect(res))
      H.match(res.incomplete[1], "directories", true)
      H.eq({}, res.partial)
    end)
  end)

  it("a tree already too big at launch: only 'partial'", function()
    local project = H.tmpdir()
    for i = 1, 30 do
      vim.fn.mkdir(project .. "/f" .. i, "p")
    end
    with("MAX_DIRS", 10, function()
      local before = guard.snapshot(project)
      H.eq(true, before.truncated)
      local res = guard.compare(before, guard.snapshot(project))
      H.eq({}, res.incomplete)
      H.eq(1, #res.partial)
    end)
  end)

  it("the time bound is reported the same way", function()
    local project = H.tmpdir()
    write(project .. "/a/x")
    with("MAX_MS", -1, function()
      local snap = guard.snapshot(project)
      H.eq(true, snap.truncated)
      H.match(snap.why, "ms", true)
    end)
    with("MAX_MS", 1e9, function()
      local before = guard.snapshot(project)
      with("MAX_MS", -1, function()
        local res = guard.compare(before, guard.snapshot(project))
        H.eq(1, #res.incomplete)
        H.match(res.incomplete[1], "ms", true)
      end)
    end)
  end)

  it(
    "a growing target/ past the second budget is INFO, not incomplete (an ordinary first build must not refuse the next launch)",
    function()
      local project = H.tmpdir()
      vim.fn.mkdir(project .. "/target/a", "p")
      with("SKIP_MAX_DIRS", 5, function()
        local before = guard.snapshot(project)
        H.eq(false, before.skip_truncated)
        for i = 1, 20 do
          vim.fn.mkdir(project .. "/target/z" .. i, "p")
        end
        local res = guard.compare(before, guard.snapshot(project))
        H.eq({}, res.incomplete, "the project is not marked dirty by the count growing")
        H.eq(1, #res.info)
        H.match(res.info[1], "target", true)
        H.eq({}, res.planted)
      end)
    end
  )

  it("a protected NAME planted inside the walked part of target/ still counts, bound or not", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/target/a", "p")
    with("SKIP_MAX_DIRS", 50, function()
      local before = guard.snapshot(project)
      write(project .. "/target/a/.envrc")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq({ project .. "/target/a/.envrc" }, res.planted)
    end)
  end)

  it("a directory below MAX_DEPTH is not entered, and that is reported when it appears during the run", function()
    local project = H.tmpdir()
    with("MAX_DEPTH", 3, function()
      local before = guard.snapshot(project)
      H.eq(false, before.depth_cut)
      write(project .. "/a/b/c/d/e/.envrc")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq({}, res.planted)
      H.eq(1, #res.incomplete)
      H.match(res.incomplete[1], "deeper than 3", true)
    end)
  end)

  it("MAX_DEPTH is exact: the directories at that depth are listed, the ones below are not entered", function()
    local project = H.tmpdir()
    with("MAX_DEPTH", 3, function()
      vim.fn.mkdir(project .. "/a/b/c", "p")
      local before = guard.snapshot(project)
      write(project .. "/a/b/c/.envrc")
      write(project .. "/a/b/c/d/.envrc")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq({ project .. "/a/b/c/.envrc" }, res.planted, "depth 3 is listed, depth 4 is not")
      H.eq(1, #res.incomplete)
    end)
  end)

  it("an .envrc 20 levels deep is found with the default depth", function()
    local project = H.tmpdir()
    local before = guard.snapshot(project)
    local deep = project .. "/" .. ("d/"):rep(20)
    write(deep .. ".envrc")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(1, #res.planted)
    H.eq({}, res.incomplete)
  end)

  it("21000 directories then a planted file: the real sweep marks the project", function()
    H.need_sandbox()
    local project = H.tmpdir()
    write(project .. "/a/x")
    local old = guard.MAX_DIRS
    guard.MAX_DIRS = 40
    local out = inside(project, "for i in $(seq 1 80); do mkdir f$i; done; mkdir -p z/y/w; : > z/y/w/.envrc; echo done")
    guard.MAX_DIRS = old
    H.match(out, "done", true)
    local rec = sb.dirty(project)
    H.ok(rec, "the project must be marked")
    H.ok(#rec.incomplete > 0, vim.inspect(rec))
    local c, why = sb.wrap({ "true" }, project, H.tmpdir())
    H.eq(nil, c)
    H.match(why, "could not be completed", true)
    H.match(why, "XynoSandboxReview", true)
    sb.clear_dirty(project)
  end)

  it("a planted name under target/ through the real sweep: moved to the quarantine, project marked", function()
    H.need_sandbox()
    local project = H.tmpdir()
    write(project .. "/src/x.rs")
    inside(
      project,
      "mkdir -p target/debug/deps/q && printf 'x' > target/debug/deps/q/.envrc && mkdir -p node_modules/p/.cargo && : > node_modules/p/.cargo/config.toml; echo done"
    )
    H.eq(nil, uv.fs_lstat(project .. "/target/debug/deps/q/.envrc"), "removed from the project")
    H.eq(nil, uv.fs_lstat(project .. "/node_modules/p/.cargo"))
    local rec = sb.dirty(project)
    H.ok(rec)
    H.eq(2, #rec.planted, vim.inspect(rec.planted))
    sb.clear_dirty(project)
  end)
end)

-- ------------------------------------------------------------------ rename of a directory
describe("a directory renamed during the run is not a set of new files", function()
  it("compare: the same inodes under a new path are 'moved', not planted", function()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\n")
    write(project .. "/sub/.envrc", "use flake\n")
    write(project .. "/sub/.vscode/tasks.json", "{}\n")
    local before = guard.snapshot(project)
    H.ok(uv.fs_rename(project .. "/sub", project .. "/sub_old"))
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({}, res.planted)
    H.eq({}, res.removed)
    H.eq({}, res.modified)
    H.eq(3, #res.moved)
    H.eq(project .. "/sub/.cargo", res.moved[1].from)
    H.eq(project .. "/sub_old/.cargo", res.moved[1].to)
  end)

  it("a copy of the same names is still planted", function()
    local project = H.tmpdir()
    write(project .. "/sub/.envrc", "use flake\n")
    local before = guard.snapshot(project)
    write(project .. "/sub2/.envrc", "evil\n")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/sub2/.envrc" }, res.planted)
    H.eq({}, res.moved)
  end)

  it("a name removed (not moved) is reported as removed", function()
    local project = H.tmpdir()
    write(project .. "/sub/.envrc", "use flake\n")
    local before = guard.snapshot(project)
    uv.fs_unlink(project .. "/sub/.envrc")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/sub/.envrc" }, res.removed)
    H.eq({}, res.moved)
  end)

  it("real run: mv sub sub_old keeps the user's files, no quarantine, no dirty mark", function()
    H.need_sandbox()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\njobs = 2\n")
    write(project .. "/sub/.envrc", "use flake\n")
    write(project .. "/sub/.vscode/tasks.json", "{}\n")
    write(project .. "/sub/src/lib.rs", "// x\n")
    local out = inside(project, "mv sub sub_old && echo moved")
    H.match(out, "moved", true, out)
    H.eq("[build]\njobs = 2\n", io.open(project .. "/sub_old/.cargo/config.toml"):read("a"))
    H.eq("use flake\n", io.open(project .. "/sub_old/.envrc"):read("a"))
    H.ok(uv.fs_lstat(project .. "/sub_old/.vscode/tasks.json"))
    H.eq(nil, sb.dirty(project), "a rename of the user's own directory must not mark the project")
    local names = vim.fn.readdir(project .. "/sub_old")
    table.sort(names)
    H.eq({ ".cargo", ".envrc", ".vscode", "src" }, names, "no placeholder is left behind")
  end)

  it("real run: a moved directory that also holds absent-name placeholders leaves nothing behind", function()
    H.need_sandbox()
    local project = H.tmpdir()
    write(project .. "/sub/src/lib.rs", "// x\n")
    inside(project, "mv sub sub_old")
    local names = vim.fn.readdir(project .. "/sub_old")
    table.sort(names)
    H.eq({ "src" }, names, "empty read-only placeholders of the masks are removed")
    H.eq(nil, sb.dirty(project))
  end)
end)

-- ------------------------------------------------------------------ more auto-exec names
describe("package-manager and editor config names that run a program are covered", function()
  local NEW_LOCKED = { ".githooks", ".mvn", ".pnpmfile.cjs", ".dir-locals.el", ".lvimrc" }
  local NEW_GUARDED = { ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", ".dir-locals.el", ".lvimrc" }
  local NEW_REVIEW =
    { "conftest.py", "bunfig.toml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml" }

  local function has(list, n)
    return vim.tbl_contains(list, n)
  end

  it("the tables name them (written out here: deleting an entry fails)", function()
    for _, n in ipairs(NEW_LOCKED) do
      H.ok(has(plan.PROJECT_READONLY, n), "PROJECT_READONLY " .. n)
      H.ok(has(plan.MEMBER_READONLY, n), "MEMBER_READONLY " .. n)
      H.ok(has(plan.WATCH_NAMES, n), "WATCH_NAMES " .. n)
    end
    for _, n in ipairs(NEW_GUARDED) do
      H.ok(has(plan.PROJECT_GUARD_FILES, n), "PROJECT_GUARD_FILES " .. n)
      H.ok(has(plan.WATCH_NAMES, n), "WATCH_NAMES " .. n)
    end
    for _, n in ipairs({ ".githooks", ".mvn" }) do
      H.ok(has(plan.PROJECT_MASK_IF_ABSENT, n), "PROJECT_MASK_IF_ABSENT " .. n)
    end
    for _, n in ipairs({ ".npmrc", ".yarnrc.yml", ".dir-locals.el", ".lvimrc" }) do
      H.ok(has(plan.SUBDIR_GUARD_FILES, n), "SUBDIR_GUARD_FILES " .. n)
    end
    for _, n in ipairs(NEW_REVIEW) do
      H.ok(has(plan.REVIEW_NAMES, n), "REVIEW_NAMES " .. n)
    end
    H.eq({ ".npmrc", ".yarnrc", ".yarnrc.yml" }, plan.WATCH_EXTRA)
  end)

  it("real run: none of them can be created at the project root", function()
    H.need_sandbox()
    local project = H.tmpdir()
    local lines = {}
    for _, n in ipairs(vim.list_extend(vim.deepcopy(NEW_GUARDED), { ".githooks/pre-commit", ".mvn/extensions.xml" })) do
      lines[#lines + 1] = ("mkdir -p \"$(dirname '%s')\" 2>/dev/null; ( : > '%s' ) 2>/dev/null && echo 'CREATED:%s'"):format(
        n,
        n,
        n
      )
    end
    lines[#lines + 1] = "echo done"
    local out = inside(project, table.concat(lines, "\n"))
    H.match(out, "done", true, out)
    H.no_match(out, "CREATED:", true, out)
    H.eq(nil, sb.dirty(project))
    H.eq({}, vim.fn.readdir(project), "the placeholders are gone again")
  end)

  it(
    "real run: a name created in a deep subdirectory is quarantined (npmrc, yarnrc.yml, .githooks, .dir-locals.el)",
    function()
      H.need_sandbox()
      local project = H.tmpdir()
      write(project .. "/a/b/c/d/e/f/x.txt")
      local old = plan.SUBDIR_MASK_MAX
      plan.SUBDIR_MASK_MAX = 0 -- (no mount budget: only the sweep is left)
      local out
      local ok, err = pcall(function()
        out = inside(
          project,
          "cd a/b/c/d/e/f && printf 'script-shell=./evil.sh\\n' > .npmrc && printf 'yarnPath: ./y.cjs\\n' > .yarnrc.yml"
            .. " && mkdir .githooks && printf '#!/bin/sh\\n' > .githooks/pre-commit && printf '(eval)' > .dir-locals.el && echo done"
        )
      end)
      plan.SUBDIR_MASK_MAX = old
      assert(ok, err)
      H.match(out, "done", true, out)
      local rec = sb.dirty(project)
      H.ok(rec, "marked")
      local names = {}
      for _, p in ipairs(rec.planted) do
        names[#names + 1] = vim.fs.basename(p)
      end
      table.sort(names)
      H.eq({ ".dir-locals.el", ".githooks", ".npmrc", ".yarnrc.yml" }, names)
      H.eq(nil, uv.fs_lstat(project .. "/a/b/c/d/e/f/.npmrc"))
      sb.clear_dirty(project)
    end
  )

  it("conftest.py and lefthook.yml changes are reported as editable files that run later", function()
    local project = H.tmpdir()
    write(project .. "/tests/conftest.py", "import x\n")
    local before = guard.snapshot(project)
    write(project .. "/tests/conftest.py", "import x\nimport os; os.system('id')\n")
    write(project .. "/lefthook.yml", "pre-commit:\n")
    write(project .. "/bunfig.toml", "[run]\n")
    local res = guard.compare(before, guard.snapshot(project))
    local by = {}
    for _, r in ipairs(res.review) do
      by[r.path:sub(#project + 2)] = r.change
    end
    H.eq({ ["bunfig.toml"] = "created", ["lefthook.yml"] = "created", ["tests/conftest.py"] = "changed" }, by)
  end)
end)

-- ------------------------------------------------------------------ survivors
describe("survivor: a hidden directory inside a read-only directory is hidden on top", function()
  local PROJECT, TMP, FHOME = "/h/proj", "/h/scratch", "/h"
  local function fakefs(entries)
    return {
      stat_type = function(x)
        return entries[x]
      end,
      lstat_type = function(x)
        return entries[x]
      end,
      exists = function(x)
        return entries[x] ~= nil
      end,
      list = function(dir)
        local out, prefix = {}, dir == "/" and "/" or (dir .. "/")
        for x, t in pairs(entries) do
          if x:sub(1, #prefix) == prefix and not x:sub(#prefix + 1):find("/", 1, true) then
            out[#out + 1] = { x:sub(#prefix + 1), t }
          end
        end
        table.sort(out, function(a, b)
          return a[1] < b[1]
        end)
        return out
      end,
      glob = function()
        return {}
      end,
      read_line = function()
        return nil
      end,
      realpath = function(x)
        return entries[x] and x or nil
      end,
      stat_info = function()
        return nil
      end,
    }
  end
  local function build(entries, readonly)
    return plan.build({
      project = PROJECT,
      tmp_dir = TMP,
      cwd = PROJECT,
      home = FHOME,
      uid = 1000,
      probes = fakefs(vim.tbl_extend("force", {
        [FHOME] = "directory",
        [FHOME .. "/.claude"] = "directory",
        [PROJECT] = "directory",
        [TMP] = "directory",
        [PROJECT .. "/.git"] = "directory",
      }, entries)),
      env = { PATH = "/usr/bin" },
      cmd = { "agent" },
      aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
      config = { network = "open", home = "denylist", policy = { readonly = readonly or {} } },
    })
  end

  it("plan: the directory gets a tmpfs after the read-only bind, a file gets the empty file", function()
    local p = build({
      [FHOME .. "/.config"] = "directory",
      [FHOME .. "/.config/gcloud"] = "directory",
      [FHOME .. "/.aws"] = "directory",
    }, { "~/.config" })
    local ops = plan.ops(p)
    local tmpfs_on_dir, dir_hidden_twice = 0, 0
    for _, op in ipairs(ops) do
      if
        op.section == "hidden"
        and op.args[1] == "--tmpfs"
        and op.args[2] == FHOME .. "/.config/gcloud"
        and op.why:find("inside the read-only", 1, true)
      then
        tmpfs_on_dir = tmpfs_on_dir + 1
      end
      if op.section == "hidden" and op.args[2] == FHOME .. "/.aws" then
        dir_hidden_twice = dir_hidden_twice + 1
      end
    end
    H.eq(1, tmpfs_on_dir, "a hidden DIRECTORY inside the read-only ~/.config")
    H.eq(1, dir_hidden_twice, "~/.aws is not inside a read-only path: hidden once, not again")
    H.match(
      table.concat(
        vim.tbl_map(function(o)
          return o.why
        end, ops),
        "\n"
      ),
      "(inside the read-only " .. FHOME .. "/.config)",
      true
    )
  end)

  it("plan: a hidden path that IS the read-only path is not hidden a second time", function()
    local p = build({ [FHOME .. "/.aws"] = "directory" }, { "~/.aws" })
    local n = 0
    for _, op in ipairs(plan.ops(p)) do
      if op.why and op.why:find("inside the read-only", 1, true) then
        n = n + 1
      end
    end
    H.eq(0, n)
  end)

  it("real run: ~/.config/gcloud/sf1 is unreadable under policy.readonly = {'~/.config'}", function()
    H.need_sandbox()
    sb.config.home = "denylist"
    sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, { readonly = { "~/.config" } })
    local home = uv.os_homedir()
    local project = home .. "/t-r7-hidden-dir"
    write(project .. "/x.txt")
    write(home .. "/.config/gcloud/sf1", "TOPSECRET-R7\n")
    write(home .. "/.config/other-r7/ok", "VISIBLE-R7\n")
    local out = inside(project, "cat ~/.config/gcloud/sf1 2>&1; cat ~/.config/other-r7/ok; echo done")
    vim.fn.delete(project, "rf")
    vim.fn.delete(home .. "/.config/gcloud/sf1")
    vim.fn.delete(home .. "/.config/other-r7", "rf")
    pcall(uv.fs_rmdir, home .. "/.config/gcloud")
    H.match(out, "done", true, out)
    H.match(out, "VISIBLE-R7", true, out)
    H.no_match(out, "TOPSECRET", true, out)
  end)
end)

describe("survivor: edits inside a protected directory are detected (dir_sig)", function()
  it("a file edited in place two levels down in .vscode is 'modified'", function()
    local project = H.tmpdir()
    write(project .. "/.vscode/sub/deeper/tasks.json", "{}\n")
    local before = guard.snapshot(project)
    write(project .. "/.vscode/sub/deeper/tasks.json", '{"tasks":[{"command":"evil"}]}\n')
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/.vscode" }, res.modified)
  end)

  it("a file edited directly in .vscode is 'modified'", function()
    local project = H.tmpdir()
    write(project .. "/.vscode/tasks.json", "{}\n")
    local before = guard.snapshot(project)
    write(project .. "/.vscode/tasks.json", '{"a":1}\n')
    H.eq({ project .. "/.vscode" }, guard.compare(before, guard.snapshot(project)).modified)
  end)

  it("a new file at the top of .cargo is 'modified' and an untouched .cargo is not", function()
    local project = H.tmpdir()
    write(project .. "/.cargo/a", "1")
    local before = guard.snapshot(project)
    H.eq({}, guard.compare(before, guard.snapshot(project)).modified)
    write(project .. "/.cargo/config.toml", "x")
    H.eq({ project .. "/.cargo" }, guard.compare(before, guard.snapshot(project)).modified)
  end)

  it("the listing keeps 400 entries: the 400th is compared, the 401st is not", function()
    local project = H.tmpdir()
    for i = 1, 401 do
      write(project .. ("/.vscode/f%03d"):format(i), "1")
    end
    local before = guard.snapshot(project)
    write(project .. "/.vscode/f401", "22")
    H.eq({}, guard.compare(before, guard.snapshot(project)).modified, "entry 401 is past the bound")
    write(project .. "/.vscode/f400", "22")
    H.eq({ project .. "/.vscode" }, guard.compare(before, guard.snapshot(project)).modified, "entry 400 is inside it")
  end)

  it("the listing is bounded in depth (6) and entries (400) and stops there", function()
    local project = H.tmpdir()
    write(project .. "/.vscode/a/b/c/d/e/f/g/h/deep.json", "1")
    local before = guard.snapshot(project)
    write(project .. "/.vscode/a/b/c/d/e/f/g/h/deep.json", "22")
    -- seven levels down is past the recursion limit: not seen (documented)
    H.eq({}, guard.compare(before, guard.snapshot(project)).modified)
  end)
end)

describe("survivor: the two guards on a non-object ~/.claude.json are each needed", function()
  it("sanitize.claude_json alone returns an empty object for every non-object", function()
    for _, v in ipairs({ 5, "str", true, vim.NIL, { 1, 2 } }) do
      local ok, out = pcall(sanitize.claude_json, v, { "/p" })
      H.ok(ok, "raised for " .. vim.inspect(v))
      H.eq("{}", vim.json.encode(out))
    end
  end)
  it("write_scrubbed_claude_json refuses a non-object on its own (nothing is written)", function()
    local d = H.tmpdir()
    for _, t in ipairs({ "5", '"s"', "true", "null", "[1]" }) do
      write(d .. "/in.json", t)
      H.eq(false, sb.write_scrubbed_claude_json(d .. "/in.json", d .. "/out.json", "/p"), t)
      H.eq(nil, uv.fs_lstat(d .. "/out.json"), "no copy for " .. t)
    end
  end)
end)

describe("survivor: modes of what the sweep writes", function()
  it("the quarantine directory is 0700, its files 0600, the dirty mark 0600", function()
    local project = H.tmpdir()
    write(project .. "/sub/.envrc", "evil\n")
    local q = guard.quarantine(project, { project .. "/sub/.envrc" })
    local function mode(p)
      return bit.band(uv.fs_stat(p).mode, tonumber("777", 8))
    end
    H.eq(tonumber("700", 8), mode(q.dir))
    H.eq(tonumber("600", 8), mode(q.dir .. "/sub/.envrc"))
    H.eq("evil\n", io.open(q.dir .. "/sub/.envrc"):read("a"))
    H.ok(guard.mark_dirty(project, { planted = { project .. "/sub/.envrc" }, quarantine = q.dir }))
    local mark = vim.fn.glob(store.dir() .. "/dirty/*.json")
    H.eq(tonumber("600", 8), mode(mark))
  end)

  it("quarantine reports a cut copy and treats a path that is already gone as removed", function()
    local project = H.tmpdir()
    write(project .. "/big/.envrc", ("x"):rep(guard.QUARANTINE_FILE_MAX + 1))
    local q = guard.quarantine(project, { project .. "/big/.envrc", project .. "/missing/.envrc" })
    H.eq(true, q.cut, "an oversized file is cut")
    H.eq(2, #q.moved)
    H.eq(true, q.moved[1].ok)
    H.eq(project .. "/big/.envrc", q.moved[1].path)
    -- (a path that is already gone is not a failure: round 8 replaced vim.fn.delete, which called it one)
    H.eq(true, q.moved[2].ok)
  end)

  it("copy depth and entry caps: a protected tree deeper than 8 levels or with over 300 entries is cut", function()
    local project = H.tmpdir()
    for i = 1, guard.QUARANTINE_ENTRIES_MAX + 20 do
      write(project .. "/sub/.cargo/f" .. i, "1")
    end
    local q = guard.quarantine(project, { project .. "/sub/.cargo" })
    H.eq(true, q.cut)
    local kept = #vim.fn.readdir(q.dir .. "/sub/.cargo")
    H.eq(guard.QUARANTINE_ENTRIES_MAX - 1, kept)
    local project2 = H.tmpdir()
    write(project2 .. "/s/.cargo/" .. ("d/"):rep(10) .. "f", "1")
    local q2 = guard.quarantine(project2, { project2 .. "/s/.cargo" })
    local deepest = q2.dir .. "/s/.cargo" .. ("/d"):rep(8)
    H.ok(uv.fs_lstat(deepest), "eight levels are copied")
    H.eq(nil, uv.fs_lstat(deepest .. "/d"), "the ninth is not")
  end)
end)

describe("survivor: token length predicates (Hugging Face 37, SendGrid exactly 69)", function()
  local scan = require("xyno_sandbox.scan")
  local function kinds(s)
    return (scan.text(s))
  end
  local function az(n)
    return ("aB3dE5fG7h"):rep(math.ceil(n / 10)):sub(1, n)
  end
  it("hf_ + 34 characters is a token, 33 is not", function()
    H.has(kinds("hf_" .. az(34)), "Hugging Face token")
    H.eq({}, kinds("hf_" .. az(33)))
  end)
  it("SendGrid: SG.<22>.<43> is a key; one character more or less is not", function()
    H.has(kinds("SG." .. az(22) .. "." .. az(43)), "SendGrid key")
    H.eq({}, kinds("SG." .. az(22) .. "." .. az(42)))
    H.eq({}, kinds("SG." .. az(22) .. "." .. az(44)))
  end)
end)

describe("round 7: README, help and changelog say what the code does", function()
  local readme = io.open(H.repo .. "/README.md"):read("*a")
  local help = io.open(H.repo .. "/doc/xyno-sandbox.txt"):read("*a")
  it("the documented bounds are the real ones", function()
    H.eq({ 4000, 700, 40 }, { guard.SKIP_MAX_DIRS, guard.SKIP_MAX_MS, guard.MAX_DEPTH })
    H.match(readme, "4000 directories and 0.7 s", true)
    H.match(readme, "40 levels", true)
    H.match(help, "4000 directories, 0.7 s", true)
  end)
  it("every new name is in the README, and the gaps are stated", function()
    for _, n in ipairs({
      ".githooks",
      ".mvn",
      ".pnpmfile.cjs",
      ".dir-locals.el",
      ".lvimrc",
      ".npmrc",
      ".yarnrc.yml",
      "conftest.py",
      ".gradle",
    }) do
      H.match(readme, "`" .. n, true, n)
    end
    H.match(readme, "NOT found", true)
    H.no_match(readme, "directories past the walk bounds are not compared (the plan/the report say so)", true)
  end)
end)
