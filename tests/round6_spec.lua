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

  it("the probe really spawns the absolute path (not the bare name)", function()
    local bin = stub_dir()
    vim.env.PATH = bin .. ":" .. old_path
    probe.reset()
    probe.net = false
    local seen
    local real = vim.system
    vim.system = function(argv, ...)
      seen = seen or argv
      return real(argv, ...)
    end
    local ok, e = pcall(probe.run_sync, true)
    vim.system = real
    H.ok(ok, e)
    H.eq(bin .. "/bwrap", seen[1])
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

-- ------------------------------------------------------------------ F5 + non-table JSON
describe("F5: the ~/.claude.json copy drops what the agent does not need", function()
  local sanitize = require("xyno_sandbox.sanitize")
  local DATA = {
    numStartups = 3, theme = "dark",
    oauthAccount = { accountUuid = "u-1", organizationUuid = "o-1", emailAddress = "me@x.example", displayName = "Me", organizationRole = "admin" },
    env = { AWS_PROFILE = "prod" }, awsAuthRefresh = "aws sso login --profile prod", awsCredentialExport = "aws-export",
    apiKeyHelper = "/usr/local/bin/get-key", hooks = { PreToolUse = { { command = "curl evil" } } },
    cachedGrowthBookFeatures = { f = true }, cachedStatsigGates = { g = true }, cachedDynamicConfigs = { c = 1 },
    projects = { ["/p"] = { hasTrustDialogAccepted = true } },
  }
  it("drops account ids, the env map, auth-refresh commands, hooks and the feature caches", function()
    local out = sanitize.claude_json(vim.deepcopy(DATA), { "/p" })
    for _, k in ipairs({ "env", "awsAuthRefresh", "awsCredentialExport", "apiKeyHelper", "hooks", "cachedGrowthBookFeatures",
      "cachedStatsigGates", "cachedDynamicConfigs" }) do
      H.eq(nil, out[k], k)
    end
    H.eq(nil, out.oauthAccount.accountUuid)
    H.eq(nil, out.oauthAccount.organizationUuid)
    H.eq(nil, out.oauthAccount.emailAddress)
    H.eq(nil, out.oauthAccount.displayName)
    H.eq("admin", out.oauthAccount.organizationRole, "what is not an identifier stays")
    H.eq(3, out.numStartups)
    H.eq(true, out.projects["/p"].hasTrustDialogAccepted)
  end)
end)

describe("a ~/.claude.json that is not a JSON object", function()
  local sanitize = require("xyno_sandbox.sanitize")
  it("sanitize.claude_json returns an empty object for anything that is not one", function()
    for _, v in ipairs({ "text", 12, true, vim.NIL, { 1, 2, 3 } }) do
      local ok, out = pcall(sanitize.claude_json, v, { "/p" })
      H.ok(ok, "raised for " .. vim.inspect(v) .. ": " .. tostring(out))
      H.eq("{}", vim.json.encode(out))
    end
  end)

  it("the launcher shares none of: null, a number, a string, a list; odd members do not crash it", function()
    local d = H.tmpdir()
    local function try(text)
      write(d .. "/in.json", text)
      return pcall(sb.write_scrubbed_claude_json, d .. "/in.json", d .. "/out.json", "/p")
    end
    for _, t in ipairs({ "null", "123", '"s"', "true", "[1,2]", "", "{" }) do
      local ok, shared = try(t)
      H.ok(ok, "raised for " .. t)
      H.eq(false, shared, "shared for " .. t)
    end
    for _, t in ipairs({ "{}", "[]", '{"projects":"x"}', '{"projects":[1]}', '{"mcpServers":"x"}', '{"oauthAccount":7}', '{"projects":{"/p":{"mcpServers":3}}}' }) do
      local ok, shared = try(t)
      H.ok(ok, "raised for " .. t)
      H.eq(true, shared, t)
    end
  end)
end)

-- ------------------------------------------------------------------ F4: survivors
describe("F4: net.is_public_ip boundaries (every special range, both edges)", function()
  local net = require("xyno_sandbox.net")
  local PRIVATE = {
    "0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "127.0.0.1", "127.255.255.255",
    "100.64.0.0", "100.127.255.255", "169.254.0.1", "169.254.255.255",
    "172.16.0.0", "172.16.5.5", "172.20.1.1", "172.31.0.0", "172.31.255.255",
    "192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255", "192.168.0.0", "192.168.255.255",
    "198.18.0.0", "198.18.255.255", "198.19.0.0", "198.19.255.255", "198.51.100.0", "198.51.100.255",
    "203.0.113.0", "203.0.113.255", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
    "::", "::1", "fe80::1", "febf::1", "fc00::1", "fdff::1", "ff02::1", "2001:db8::1", "2001:0db8:ffff::1",
    "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:172.31.1.1", "::ffff:192.168.1.1", "64:ff9b::a00:1", "64:ff9b::7f00:1",
    "2002:a00:1::1", "2002:c0a8:101::1",
  }
  local PUBLIC = {
    "1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "126.255.255.255", "128.0.0.1", "100.63.255.255", "100.128.0.0",
    "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0", "191.255.255.255", "192.0.1.1", "192.0.3.0",
    "192.1.0.1", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0", "198.51.99.255", "198.51.101.0",
    "203.0.112.255", "203.0.114.0", "223.255.255.255",
    "2606:4700::1", "2001:db9::1", "2001:4860:4860::8888", "fe00::1", "fec0::1", "::ffff:8.8.8.8", "64:ff9b::808:808",
    "2002:808:808::1",
  }
  it("refuses every private, loopback, link-local, shared, benchmark, documentation and multicast address", function()
    for _, ip in ipairs(PRIVATE) do
      H.eq(false, net.is_public_ip(ip), ip .. " must not be public")
    end
  end)
  it("accepts the addresses just outside each range", function()
    for _, ip in ipairs(PUBLIC) do
      H.eq(true, net.is_public_ip(ip), ip .. " must be public")
    end
  end)
  it("a name or garbage is not a public address", function()
    for _, ip in ipairs({ "example.com", "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "::g", "1::2::3" }) do
      H.eq(false, net.is_public_ip(ip), ip)
    end
  end)
end)

describe("F4: policy.readonly in a project that is $HOME", function()
  it("locks '~/x' and absolute paths but not a project-relative one", function()
    local p = plan.build({
      project = FHOME, tmp_dir = TMP, cwd = FHOME, home = FHOME, uid = 1000,
      probes = fakefs({
        [FHOME] = "directory", [FHOME .. "/.claude"] = "directory", [TMP] = "directory", [FHOME .. "/x"] = "directory",
        [FHOME .. "/rel"] = "directory", ["/srv/abs"] = "directory",
      }),
      env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
      config = { network = "open", policy = { readonly = { "~/x", "rel", "/srv/abs" } } },
    })
    local ro = {}
    for _, r in ipairs(p.readonly) do
      ro[r.path] = r.why
    end
    H.eq("policy.readonly", ro[FHOME .. "/x"])
    H.eq("policy.readonly", ro["/srv/abs"])
    H.eq(nil, ro[FHOME .. "/rel"], "'rel' would be $HOME/rel for a project that is $HOME: not applied")
  end)
  it("in an ordinary project all three forms apply", function()
    local p = plan.build({
      project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = FHOME, uid = 1000,
      probes = fakefs({
        [FHOME] = "directory", [FHOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory", [PROJECT .. "/.git"] = "directory",
        [FHOME .. "/x"] = "directory", [PROJECT .. "/rel"] = "directory", ["/srv/abs"] = "directory",
      }),
      env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
      config = { network = "open", policy = { readonly = { "~/x", "rel", "/srv/abs" } } },
    })
    local ro = {}
    for _, r in ipairs(p.readonly) do
      ro[r.path] = r.why
    end
    for _, x in ipairs({ FHOME .. "/x", PROJECT .. "/rel", "/srv/abs" }) do
      H.eq("policy.readonly", ro[x], x)
    end
  end)
end)

describe("F4: git_locked lists exactly the locked git directories", function()
  it("a nested repository, the root .git and a masked absent .git are each counted once; other read-only paths are not", function()
    local p = build({ [PROJECT .. "/sub"] = "directory", [PROJECT .. "/sub/.git"] = "directory", [PROJECT .. "/.envrc"] = "file" })
    table.sort(p.git_locked)
    H.eq({ PROJECT .. "/.git", PROJECT .. "/sub/.git" }, p.git_locked)
    local bare = plan.build({
      project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = FHOME, uid = 1000,
      probes = fakefs({ [FHOME] = "directory", [FHOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory" }),
      env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
      config = { network = "open" },
    })
    H.eq({ PROJECT .. "/.git" }, bare.git_locked, "an absent .git is guarded and listed")
    local text = table.concat(require("xyno_sandbox.ui").lines(p, { home = FHOME }), "\n")
    H.match(text, "git directories locked (2)", true)
  end)
end)

describe("F4: the in-sandbox relay", function()
  local RELAY = H.repo .. "/lua/xyno_sandbox/relay.lua"

  it("refuses to start without its three arguments (usage, exit 2)", function()
    local r = vim.system({ vim.v.progpath, "-u", "NONE", "-i", "NONE", "--headless", "-l", RELAY }, { text = true }):wait(10000)
    H.eq(2, r.code)
    H.match(r.stderr, "usage: relay.lua SOCK PORT READY", true)
    local r2 = vim.system({ vim.v.progpath, "-u", "NONE", "-i", "NONE", "--headless", "-l", RELAY, "/x", "notaport" }, { text = true }):wait(10000)
    H.eq(2, r2.code)
  end)

  it("closes both ends of a connection once both directions ended (no descriptor leak)", function()
    local dir = H.tmpdir()
    vim.fn.mkdir(dir .. "/net", "p")
    local sock = dir .. "/net/proxy.sock"
    local server = uv.new_pipe(false)
    assert(server:bind(sock))
    local served = 0
    server:listen(64, function()
      local c = uv.new_pipe(false)
      server:accept(c)
      c:read_start(function(err, chunk)
        if err or not chunk then
          if not c:is_closing() then
            c:close()
          end
          return
        end
        c:write("pong", function()
          c:shutdown(function()
            served = served + 1
          end)
        end)
      end)
    end)
    local port = 20000 + (uv.hrtime() % 20000)
    local ready = dir .. "/ready"
    local sh = vim.system({ "sh", "-c", ('"%s" -u NONE -i NONE --headless -l "%s" "%s" %d "%s" </dev/null >/dev/null 2>&1 & wait'):format(
      vim.v.progpath, RELAY, sock, port, ready), "xyno-r6-relay", dir:match("([^/]+)$") })
    H.ok(vim.wait(10000, function()
      return uv.fs_stat(ready) ~= nil
    end, 50), "the relay did not come up")
    local found = H.procs(sock)
    local pid
    for _, pr in ipairs(found) do
      if pr[2]:find("%-l ") and pr[2]:find("relay.lua", 1, true) and not pr[2]:find("^sh ") then
        pid = pr[1]
      end
    end
    H.ok(pid, "relay process among " .. vim.inspect(found))
    local function fds()
      local n = 0
      for _ in vim.fs.dir("/proc/" .. pid .. "/fd") do
        n = n + 1
      end
      return n
    end
    local function connect_once()
      local done = false
      local cl = uv.new_tcp()
      cl:connect("127.0.0.1", port, function(err)
        if err then
          done = true
          return
        end
        cl:write("ping")
        cl:read_start(function(e, chunk)
          if e or not chunk then
            if not cl:is_closing() then
              cl:close()
            end
            done = true
          end
        end)
      end)
      vim.wait(5000, function()
        return done
      end, 5)
      H.ok(done, "a connection through the relay finished")
    end
    connect_once()
    vim.wait(300, function() return false end)
    local before = fds()
    for _ = 1, 40 do
      connect_once()
    end
    vim.wait(800, function() return false end)
    local after = fds()
    uv.kill(pid, 15)
    sh:kill(9)
    server:close()
    H.wait_gone(sock, 4000)
    H.ok(served >= 40, "the fake proxy served the connections: " .. served)
    H.ok(after <= before + 4, ("the relay leaked descriptors: %d before, %d after 40 connections"):format(before, after))
  end)
end)

describe("F4: the readiness probe runs the isolation of the real launch", function()
  local EXPECTED = { "--die-with-parent", "--new-session", "--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc",
    "--unshare-uts", "--unshare-cgroup-try", "--cap-drop", "ALL" }

  it("plan.ISOLATION_FLAGS is exactly the expected list", function()
    H.eq(EXPECTED, plan.ISOLATION_FLAGS)
  end)

  it("the command the probe really spawns carries every flag, the read-only root and --unshare-net when filtered", function()
    local bin = H.tmpdir()
    local log = bin .. "/argv.log"
    write(bin .. "/bwrap", '#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "' .. log .. '"\nexit 0\n')
    uv.fs_chmod(bin .. "/bwrap", tonumber("755", 8))
    vim.env.PATH = bin .. ":" .. old_path
    for _, net_on in ipairs({ false, true }) do
      probe.reset()
      probe.net = net_on
      local e = probe.run_sync(true)
      H.ok(e.ok, vim.inspect(e))
      local got = vim.fn.readfile(log)
      local text = "\0" .. table.concat(got, "\0") .. "\0"
      for _, f in ipairs(EXPECTED) do
        H.ok(text:find("\0" .. f .. "\0", 1, true), "the probe did not pass " .. f)
      end
      H.ok(text:find("\0--ro-bind\0/\0/\0", 1, true), "read-only root")
      H.ok(text:find("\0true\0", 1, true), "runs `true`")
      H.eq(net_on, text:find("\0--unshare-net\0", 1, true) ~= nil)
    end
    probe.net = false
  end)
end)

describe("F4: M.plan() when the status is refused", function()
  it("returns nil and the reason, never a plan", function()
    vim.env.PATH = H.tmpdir() -- no bwrap here
    probe.reset()
    sb.config.sandbox, sb.config.allow_unsandboxed = true, false
    local p, reason = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    H.eq(nil, p)
    H.match(reason, "bwrap not found", true)
    sb.config.allow_unsandboxed = true
    local p2 = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    H.eq("unsandboxed", p2.mode, "the explicit opt-in gives an unsandboxed plan")
  end)
end)

describe("F4: ENV_DANGEROUS_EXACT", function()
  local DANGEROUS = { "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG_OUTPUT", "BASH_ENV", "ENV", "PYTHONPATH", "PYTHONSTARTUP",
    "PYTHONHOME", "NODE_OPTIONS", "NODE_PATH", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "GIT_SSH_COMMAND", "GIT_EXEC_PATH",
    "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "SHELLOPTS", "PS4", "PROMPT_COMMAND", "IFS",
    "HOME", "SHELL" }
  it("each of them is refused as an env exception, with the reason that names the danger", function()
    local ctx = { home = FHOME, probes = fakefs({}), scrub = nil }
    for _, name in ipairs(DANGEROUS) do
      H.ok(plan.ENV_DANGEROUS_EXACT[name], name .. " is missing from the table")
      for _, spelled in ipairs({ name, name:lower() }) do
        local ok, why = plan.validate_exception({ kind = "env", value = spelled }, ctx)
        H.eq(false, ok, spelled)
        H.match(why, "decides which code runs", true, spelled)
      end
    end
  end)
end)

-- ---------------------------------------------- survivors of the first mutation run
describe("round 6 survivors", function()
  it("no mount point is planned below a path the policy mounts read-only", function()
    local entries = {
      [PROJECT .. "/vendor"] = "directory", [PROJECT .. "/vendor/lib"] = "directory", [PROJECT .. "/src"] = "directory",
    }
    local fs = fakefs(vim.tbl_extend("force", {
      [FHOME] = "directory", [FHOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory", [PROJECT .. "/.git"] = "directory",
    }, entries))
    local p = plan.build({
      project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = FHOME, uid = 1000, probes = fs, env = { PATH = "/usr/bin" }, cmd = { "agent" },
      aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" }, config = { network = "open", policy = { readonly = { "vendor" } } },
    })
    local below, outside = 0, 0
    for _, list in ipairs({ p.masks, p.guard_files }) do
      for _, m in ipairs(list) do
        if m.path:find(PROJECT .. "/vendor/", 1, true) == 1 then
          below = below + 1
        elseif m.path:find(PROJECT .. "/src/", 1, true) == 1 then
          outside = outside + 1
        end
      end
    end
    H.eq(0, below, "a mount point below the read-only vendor/ cannot be created")
    H.ok(outside > 0, "an ordinary directory still gets its masks")
  end)

  it("a deleted Makefile is reported as deleted with the lines that went", function()
    local project = H.tmpdir()
    write(project .. "/Makefile", "a:\n\tx\n\ty\n")
    local before = guard.snapshot(project)
    uv.fs_unlink(project .. "/Makefile")
    local res = guard.compare(before, guard.snapshot(project))
    H.eq(1, #res.review)
    H.eq("deleted", res.review[1].change)
    H.eq({ 0, 3 }, { res.review[1].plus, res.review[1].minus })
    H.match(table.concat(guard.report(res), "\n"), "deleted " .. project .. "/Makefile +0 -3", true)
  end)

  it("a review mark that cannot be read still refuses the launch", function()
    local project = H.tmpdir()
    guard.mark_dirty(project, { planted = { project .. "/x/.envrc" }, quarantine = "/q" })
    local f = assert(io.open(store.dir() .. "/dirty/" .. vim.fn.glob(store.dir() .. "/dirty/*"):match("([^/]+)$"), "wb"))
    f:write("{ not json")
    f:close()
    local rec = guard.dirty(project)
    H.ok(rec and rec.unreadable, "an unreadable mark is still a mark")
    local c, why = sb.wrap({ "true" }, project, H.tmpdir())
    H.eq(nil, c)
    H.match(why, "XynoSandboxReview", true)
    guard.clear_dirty(project)
  end)

  it("every file in .github/workflows is listed in the preview as editable-and-runs-later", function()
    local p = build({ [PROJECT .. "/.github"] = "directory", [PROJECT .. "/.github/workflows"] = "directory",
      [PROJECT .. "/.github/workflows/ci.yml"] = "file", [PROJECT .. "/.github/workflows/sub"] = "directory" })
    H.eq({ PROJECT .. "/.github/workflows/ci.yml" }, p.runs_later)
  end)
end)
