-- Secrets that are not found by their name alone: tokens in .git/config remote URLs and in the
-- global git config, more default file names, a bounded content scan for known token formats, hard
-- links to hidden files, and names that are symlinks. Plan specs use fake probes; the behavioural
-- specs run real commands in a real sandbox on the suite's fake $HOME.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local scan = require("xyno_sandbox.scan")
local sanitize = require("xyno_sandbox.sanitize")
local ui = require("xyno_sandbox.ui")
local store = require("xyno_sandbox.store")
local harness = require("xynotest.harness")

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local TOKEN = "ghp_" .. string.rep("A1b2", 9)

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text)
  f:close()
end

-- --------------------------------------------------------------- git config

describe("sanitize.git_config", function()
  local SRC = table.concat({
    "[core]", "\trepositoryformatversion = 0",
    '[remote "origin"]', "\turl = https://user:" .. TOKEN .. "@github.com/x/y.git", "\tfetch = +refs/heads/*:refs/remotes/origin/*",
    '[remote "bare"]', "\turl = https://" .. TOKEN .. "@gitlab.com/x/z.git", "\tpushurl = ssh://git:hunter2pw@example.org/z.git",
    '[remote "scp"]', "\turl = git@github.com:x/y.git",
    "[credential]", "\thelper = store --file=/home/u/.secret-creds",
    '[credential "https://github.com"]', "\thelper = !f() { echo password=x; }; f", "\tusername = bob",
    "[http]", "\textraHeader = Authorization: Bearer abc123",
    '[http "https://git.example.com/"]', "\textraheader = Authorization: Basic Zm9vOmJhcg== \\", "\t  continued-secret",
    '[url "https://' .. TOKEN .. '@github.com/"]', "\tinsteadOf = gh:",
    "[user]", "\tname = Bob", "\temail = bob@example.org", "",
  }, "\n")

  it("removes URL credentials of http(s) remotes, the password of other schemes, and keeps the rest", function()
    local out, changes = sanitize.git_config(SRC)
    H.no_match(out, TOKEN, true)
    H.no_match(out, "hunter2pw", true)
    H.match(out, "url = https://github.com/x/y.git", true)
    H.match(out, "url = https://gitlab.com/x/z.git", true)
    H.match(out, "pushurl = ssh://git@example.org/z.git", true)
    H.match(out, "url = git@github.com:x/y.git", true, "an scp-style remote has no secret in it")
    H.match(out, "[url \"https://github.com/\"]", true, "the token in a [url] section header is gone too")
    H.match(out, "insteadOf = gh:", true)
    H.match(out, "name = Bob", true)
    H.match(out, "fetch = +refs/heads/*:refs/remotes/origin/*", true)
    H.ok(#changes > 0)
  end)

  it("drops credential helpers (store paths, shell helpers) and auth headers, with their continuation lines", function()
    local out = sanitize.git_config(SRC)
    H.no_match(out, ".secret-creds", true)
    H.no_match(out, "echo password", true)
    H.no_match(out, "Authorization", true)
    H.no_match(out, "continued-secret", true)
    H.no_match(out, "helper", true)
    H.match(out, "username = bob", true, "a user name is not a secret")
  end)

  it("never prints a secret in its list of changes, is idempotent, and leaves a clean config alone", function()
    local out, changes = sanitize.git_config(SRC)
    H.no_match(table.concat(changes, "\n"), TOKEN, true)
    H.eq(out, (sanitize.git_config(out)))
    local clean = "[core]\n\tbare = false\n[remote \"o\"]\n\turl = https://github.com/a/b.git\n"
    local same, none = sanitize.git_config(clean)
    H.eq(clean, same)
    H.eq({}, none)
  end)
end)

describe("a git config inside the sandbox", function()
  local function inside(script, project, tmp)
    H.need_sandbox()
    sb.config.network = "open"
    local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    return (r.stdout or "") .. (r.stderr or ""), h
  end

  it("shows the remote without its token; the host file is untouched; the copy is removed on release", function()
    if vim.fn.executable("git") ~= 1 then
      return harness.skip("git not installed")
    end
    local project = H.fixture("basic", { git = true })
    H.git(project, "remote", "add", "origin", "https://bob:" .. TOKEN .. "@github.com/x/y.git")
    H.git(project, "config", "credential.helper", "store --file=/home/u/.hidden-store")
    local out, h = inside("cat .git/config; git remote -v; git config --get credential.helper; echo end", project, H.tmpdir())
    local copy_dir = h.plan.needs.git_dir
    H.ok(vim.uv.fs_stat(copy_dir), "the sanitized copies exist while the sandbox runs")
    h.release()
    H.no_match(out, TOKEN, true, out)
    H.no_match(out, ".hidden-store", true, out)
    H.match(out, "github.com/x/y.git", true, out)
    H.match(out, "end", true, out)
    H.match(table.concat(vim.fn.readfile(project .. "/.git/config"), "\n"), TOKEN, true, "the real config is unchanged")
    H.eq(nil, vim.uv.fs_stat(copy_dir), "the copies are deleted on release")
  end)

  it("is read-only: the agent cannot change it, and git still works for local commands", function()
    if vim.fn.executable("git") ~= 1 then
      return harness.skip("git not installed")
    end
    local project = H.fixture("basic", { git = true })
    local out, h = inside("git config user.name hacked 2>&1; echo x > .git/config 2>&1; git log --oneline | head -2", project, H.tmpdir())
    h.release()
    H.match(out, "init", true, out)
    H.no_match(table.concat(vim.fn.readfile(project .. "/.git/config"), "\n"), "hacked", true)
  end)

  it("the plan lists the sanitized copies in the preview and in the argv, project and global config alike", function()
    local project = H.fixture("basic", { git = true })
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    H.ok(#p.git_configs >= 1)
    local text = table.concat(ui.lines(p), "\n")
    H.match(text, "Git configs shown without credentials", true)
    H.match(text, project .. "/.git/config", true)
    local argv = table.concat(sb.argv(p), "\0")
    H.match(argv, "\0--ro-bind\0" .. p.git_configs[1].copy .. "\0" .. project .. "/.git/config\0", true)
  end)

  it("the global ~/.gitconfig is shown without credentials as well (allowlist view)", function()
    local home = vim.uv.os_homedir()
    local had = vim.uv.fs_stat(home .. "/.gitconfig") ~= nil
    H.ok(not had, "the suite's fake home has no .gitconfig")
    write(home .. "/.gitconfig", '[url "https://' .. TOKEN .. '@github.com/"]\n\tinsteadOf = gh:\n[credential]\n\thelper = store\n[user]\n\tname = Zed\n')
    local project = H.tmpdir()
    local out, h = inside('cat "$HOME/.gitconfig"', project, H.tmpdir())
    h.release()
    vim.uv.fs_unlink(home .. "/.gitconfig")
    H.no_match(out, TOKEN, true, out)
    H.match(out, "name = Zed", true, out)
  end)
end)

-- --------------------------------------------------------------- names

describe("default secret names", function()
  it("hide the files that tools and frameworks keep credentials in", function()
    for _, n in ipairs({ ".dev.vars", "serviceAccountKey.json", "google-services.json", "GoogleService-Info.plist", "wp-config.php",
      "token.txt", "api_keys.txt", "application-prod.properties", "application-production.yml", ".pgpass", ".my.cnf", "master.key",
      "local.settings.json", "appsettings.Production.json", "firebase-adminsdk-abc12.json", "password.txt", "api-key.json" }) do
      H.ok(plan.is_secret_name(n, plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT), n .. " should be hidden by name")
    end
  end)

  it("leave source and ordinary config alone", function()
    for _, n in ipairs({ "tokenizer.rs", "api_key.rs", "token.go", "passwords.md", "application.properties", "application-dev.properties",
      "README.md", "Cargo.toml", "wp-config-sample.php.md", "settings.json", ".env.example", "package.json" }) do
      H.not_ok(plan.is_secret_name(n, plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT), n .. " must stay readable")
    end
  end)

  it("a real project: they are empty inside the sandbox, the host files keep their content", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.fixture("basic")
    local names = { ".dev.vars", "serviceAccountKey.json", "google-services.json", "wp-config.php", "token.txt", "api_keys.txt", "application-prod.properties" }
    for _, n in ipairs(names) do
      write(project .. "/" .. n, "NAME-SECRET-" .. n .. "\n")
    end
    write(project .. "/src/api_key.rs", "// NOT-A-SECRET\n")
    local cmd, err, h = sb.wrap({ "bash", "-c", "cat " .. table.concat(names, " ") .. " src/api_key.rs" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "NAME-SECRET-", true, out)
    H.match(out, "NOT-A-SECRET", true, out)
    H.match(vim.fn.readfile(project .. "/token.txt")[1], "NAME-SECRET-token.txt", true)
  end)
end)

-- --------------------------------------------------------------- content

describe("scan.text (known token formats)", function()
  local function kinds(s)
    return scan.text(s)
  end
  local function z(n, c)
    return string.rep(c or "Q", n)
  end

  it("finds each supported format", function()
    local cases = {
      ["AWS access key id"] = "aws_access_key_id = AKIA" .. z(16, "7"),
      ["AWS secret access key"] = 'aws_secret_access_key = "' .. z(40, "k") .. '"',
      ["GitHub token"] = "GITHUB=ghp_" .. z(36, "a"),
      ["GitHub fine-grained token"] = "t = github_pat_" .. z(22, "a") .. "_" .. z(59, "b"),
      ["GitLab token"] = "t: glpat-" .. z(20, "y"),
      ["Slack token"] = "SLACK=xoxb-1234567890-" .. z(24, "z"),
      ["Slack webhook"] = "https://hooks.slack.com/services/T0123/B0456/" .. z(24, "w"),
      ["Stripe live key"] = "sk_live_" .. z(30, "s"),
      ["Anthropic key"] = "ANTHROPIC_API_KEY=sk-ant-api03-" .. z(60, "p"),
      ["OpenAI key"] = "OPENAI=sk-proj-" .. z(60, "p"),
      ["Google API key"] = "key=AIza" .. z(35, "g"),
      ["npm token"] = "//registry.npmjs.org/:_authToken=npm_" .. z(36, "n"),
      ["private key"] = "-----BEGIN OPENSSH PRIVATE KEY-----",
      ["credentials in a URL"] = "DB=https://deploy:Zx9fKq27Lm@git.internal.net/r.git",
    }
    for kind, text in pairs(cases) do
      H.has(kinds(text), kind, kind .. ": " .. text)
    end
    H.has(kinds("-----BEGIN RSA PRIVATE KEY-----"), "private key")
    H.has(kinds("-----BEGIN PGP PRIVATE KEY BLOCK-----"), "private key")
  end)

  it("does not flag look-alikes, placeholders and ordinary hashes", function()
    for _, text in ipairs({
      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", -- the documented example
      "ghp_short", "token = ghp_" .. z(10, "a"), "sk-ant-short", "AKIA" .. z(8, "A"), "xoxb-1",
      "sha256: " .. z(64, "a"), "uuid 123e4567-e89b-12d3-a456-426614174000", "https://user:password@localhost/db",
      "https://deploy:${DEPLOY_TOKEN}@git.example.com/r.git", "https://x:<your-token>@host.example/", "-----BEGIN CERTIFICATE-----",
      "-----BEGIN PUBLIC KEY-----", "your_api_key_here = 'sk-ant-" .. z(40, "x") .. "'", "base64: " .. z(120, "A"),
      "aws_secret_access_key = " .. z(30, "k"), "see https://github.com/ghp_" .. z(36, "a") .. "/x" == nil and "" or "plain text",
    }) do
      H.eq({}, kinds(text), text)
    end
  end)

  it("a prefix inside a longer word is not a token", function()
    H.eq({}, kinds("xghp_" .. z(36, "a")))
    H.eq({}, kinds("ghp_" .. z(36, "a") .. "extra"))
  end)

  it("does not flood: 20000 lines of hashes, ids, base64 and code give no hit", function()
    local lines = {}
    local seed = 7
    for i = 1, 20000 do
      seed = (seed * 1103515245 + 12345) % 2147483648
      lines[#lines + 1] = ("%08x%08x%08x%08x  id-%d  %s"):format(seed, seed * 3 % 2^32, seed * 7 % 2^32, seed * 11 % 2^32, i, ("QUJD"):rep(i % 20 + 1))
    end
    H.eq({}, kinds(table.concat(lines, "\n")))
  end)
end)

describe("scan.project", function()
  local function project_with(files)
    local dir = H.tmpdir() .. "/p"
    for rel, text in pairs(files) do
      write(dir .. "/" .. rel, text)
    end
    return dir
  end
  local GH = "token = " .. TOKEN .. "\n"

  it("returns the files with a hit, by kind, without the secret", function()
    local dir = project_with({ ["deploy/ci.yml"] = GH, ["src/main.rs"] = "fn main() {}\n", ["notes.txt"] = "-----BEGIN RSA PRIVATE KEY-----\n" })
    local r = scan.project(dir)
    table.sort(r.hits, function(a, b) return a.path < b.path end)
    H.eq({ { path = dir .. "/deploy/ci.yml", kind = "GitHub token" }, { path = dir .. "/notes.txt", kind = "private key" } }, r.hits)
    H.not_ok(r.truncated)
    H.eq(3, r.files)
    H.no_match(vim.inspect(r), TOKEN, true)
  end)

  it("skips build and dependency directories, large files, binary files, binary extensions and symlinks", function()
    local dir = project_with({
      ["node_modules/x/k.js"] = GH, ["target/debug/k.txt"] = GH, [".git/config"] = GH,
      ["big.txt"] = GH .. string.rep("x", scan.MAX_FILE_BYTES + 10), ["bin.dat"] = "\0\0\0" .. GH,
      ["img.png"] = GH, ["ok/plain.txt"] = "nothing here\n",
    })
    vim.uv.fs_symlink(dir .. "/ok/plain.txt", dir .. "/link-to-file")
    write(H.tmpdir() .. "/outside.txt", GH)
    local r = scan.project(dir)
    H.eq({}, r.hits)
  end)

  it("is bounded: the file budget stops the walk and says so", function()
    local files = {}
    for i = 1, 30 do
      files[("d/f%02d.txt"):format(i)] = "x\n"
    end
    local dir = project_with(files)
    local old = scan.MAX_FILES
    scan.MAX_FILES = 10
    local r = scan.project(dir)
    scan.MAX_FILES = old
    H.ok(r.truncated)
    H.match(r.why, "files", true)
    H.eq(10, r.files)
  end)

  it("is bounded in time: an exhausted budget stops it", function()
    local dir = project_with({ ["a.txt"] = "x\n", ["b.txt"] = "y\n" })
    local old = scan.MAX_MS
    scan.MAX_MS = -1
    local r = scan.project(dir)
    scan.MAX_MS = old
    H.ok(r.truncated)
    H.match(r.why, "ms", true)
  end)

  it("a rescan of an unchanged project does not read the files again", function()
    local dir = project_with({ ["ci.yml"] = GH })
    local first = scan.project(dir)
    H.eq(1, #first.hits)
    local real_open = io.open
    local opened = 0
    io.open = function(...)
      opened = opened + 1
      return real_open(...)
    end
    local second = scan.project(dir)
    io.open = real_open
    H.eq(1, #second.hits)
    H.eq(0, opened)
  end)

  it("scans 4000 ordinary files well inside its time budget", function()
    local dir = H.tmpdir() .. "/many"
    vim.fn.mkdir(dir, "p")
    for d = 1, 40 do
      vim.fn.mkdir(dir .. "/d" .. d, "p")
      for i = 1, 100 do
        write(("%s/d%d/f%d.rs"):format(dir, d, i), "fn f() { println!(\"hello\"); }\n")
      end
    end
    local t0 = vim.uv.hrtime()
    local r = scan.project(dir)
    local ms = (vim.uv.hrtime() - t0) / 1e6
    H.ok(r.files >= 3900)
    H.ok(ms < scan.MAX_MS + 600, ("took %d ms"):format(ms))
  end)
end)

describe("hidden by content", function()
  local function content_plan(extra_cfg, exceptions)
    local project = H.tmpdir() .. "/proj"
    write(project .. "/Cargo.toml", "[package]\n")
    write(project .. "/deploy/ci.yml", "token = " .. TOKEN .. "\n")
    write(project .. "/src/lib.rs", "pub fn f() {}\n")
    local cfg = vim.tbl_extend("force", { network = "open" }, extra_cfg or {})
    return plan.build({
      project = project, tmp_dir = H.tmpdir(), cwd = project, home = vim.uv.os_homedir(), uid = 1000, env = { PATH = "/usr/bin" },
      cmd = { "agent" }, aux = { empty = "/aux/e" }, config = cfg, exceptions = exceptions or {},
    }), project
  end

  it("a file whose content has a token is hidden by default and listed in the preview with its kind", function()
    local p, project = content_plan()
    local hidden
    for _, h in ipairs(p.hidden) do
      if h.path == project .. "/deploy/ci.yml" then hidden = h end
    end
    H.ok(hidden, "deploy/ci.yml is hidden")
    H.eq("file", hidden.kind)
    H.match(hidden.why, "GitHub token", true)
    H.match(hidden.why, "^project content")
    local text = table.concat(ui.lines(p), "\n")
    H.match(text, "deploy/ci.yml", true)
    H.match(text, "looks like a GitHub token", true)
    H.match(text, "Content scan: ", true)
    H.no_match(text, TOKEN, true)
    H.no_match(table.concat(plan.argv(p), "\0"), TOKEN, true)
  end)

  it("the preview says what the scan cannot catch", function()
    local p = content_plan()
    H.match(table.concat(ui.lines(p), "\n"), "does not find passwords", true)
  end)

  it("approve-to-unhide: an unhide exception shows the file again, secret_allow too", function()
    local p0, project = content_plan()
    local e = { kind = "unhide", value = project .. "/deploy/ci.yml", scope = "once" }
    local ok = plan.validate_exception(e, { home = vim.uv.os_homedir(), probes = plan.real_probes(), baseline = p0 })
    H.ok(ok, "the baseline hides it, so the exception is valid")
    local p1 = content_plan(nil, { e })
    for _, h in ipairs(p1.hidden) do
      H.not_ok(h.path == project .. "/deploy/ci.yml", "shown after approval")
    end
    local p2 = plan.build({
      project = project, tmp_dir = H.tmpdir(), cwd = project, home = vim.uv.os_homedir(), uid = 1000, env = { PATH = "/usr/bin" },
      cmd = { "agent" }, aux = { empty = "/aux/e" }, config = { network = "open", policy = { secret_allow = { "deploy/ci.yml" } } },
    })
    for _, h in ipairs(p2.hidden) do
      H.not_ok(h.path == project .. "/deploy/ci.yml")
    end
  end)

  it("policy.content_scan = false turns it off (names still apply)", function()
    local p = content_plan({ policy = { content_scan = false } })
    for _, h in ipairs(p.hidden) do
      H.not_ok(h.path:match("ci%.yml$"))
    end
    H.eq(false, p.scan.enabled)
    H.throws(function() sb.setup({ policy = { content_scan = "no" } }) end, "content_scan")
  end)

  it("a shared directory or $HOME as the project is not scanned", function()
    local scanned = 0
    local probes = plan.real_probes()
    probes.scan_project = function() scanned = scanned + 1 return { hits = {}, multi = {}, files = 0 } end
    for _, project in ipairs({ "/tmp", vim.uv.os_homedir() }) do
      plan.build({ project = project, tmp_dir = H.tmpdir(), home = vim.uv.os_homedir(), uid = 1000, env = {}, cmd = { "a" },
        aux = { empty = "/e" }, config = { network = "open" }, probes = probes })
    end
    H.eq(0, scanned)
  end)

  it("a truncated scan is stated in the plan", function()
    local project = H.tmpdir() .. "/trunc"
    for i = 1, 20 do write(("%s/f%d.txt"):format(project, i), "x\n") end
    local old = scan.MAX_FILES
    scan.MAX_FILES = 5
    local p = plan.build({ project = project, tmp_dir = H.tmpdir(), home = vim.uv.os_homedir(), uid = 1000, env = {}, cmd = { "a" },
      aux = { empty = "/e" }, config = { network = "open" } })
    scan.MAX_FILES = old
    H.eq(true, p.scan.truncated)
    H.match(table.concat(p.notes, "\n"), "project scan stopped", true)
    H.match(table.concat(ui.lines(p), "\n"), "STOPPED", true)
  end)

  it("in a real sandbox the file reads empty and the host file is untouched", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.fixture("basic")
    write(project .. "/deploy/ci.yml", "token = " .. TOKEN .. "\n")
    write(project .. "/deploy/other.yml", "harmless = 1\n")
    local cmd, err, h = sb.wrap({ "bash", "-c", "cat deploy/ci.yml; cat deploy/other.yml; echo end" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, TOKEN, true, out)
    H.match(out, "harmless = 1", true, out)
    H.match(vim.fn.readfile(project .. "/deploy/ci.yml")[1], TOKEN, true)
  end)
end)

-- --------------------------------------------------------------- hard links

describe("hard links to hidden files", function()
  it("another name inside the project is hidden as well, and listed", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.fixture("basic")
    write(project .. "/.env", "HARDLINK-SECRET=1\n")
    H.eq(0, vim.uv.fs_link(project .. "/.env", project .. "/src/notes.txt") and 0 or 1)
    local p = sb.plan({ "bash", "-c", "cat .env src/notes.txt; echo end" }, project, H.tmpdir())
    local hl = p.hardlinks[1]
    H.ok(hl, "the hidden file is listed with its links")
    H.eq(project .. "/.env", hl.path)
    H.eq(2, hl.links)
    H.eq(1, hl.masked)
    H.eq(0, hl.unaccounted)
    local paths = vim.tbl_map(function(h) return h.path end, p.hidden)
    H.has(paths, project .. "/.env")
    H.has(paths, project .. "/src/notes.txt")
    local text = table.concat(ui.lines(p), "\n")
    H.match(text, "Hidden files that have other hard links", true)
    local cmd, err, h = sb.wrap(p.agent.cmd, project, p.tmp_dir, { plan = p })
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "HARDLINK-SECRET", true, out)
    H.match(out, "end", true, out)
  end)

  it("a name outside the project cannot be hidden: the plan warns, naming the file and the count", function()
    local project = H.fixture("basic")
    write(project .. "/.env", "SECRET=1\n")
    local outside = H.tmpdir() .. "/outside-link"
    H.ok(vim.uv.fs_link(project .. "/.env", outside))
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    H.eq(1, p.hardlinks[1].unaccounted)
    H.eq(0, p.hardlinks[1].masked)
    local notes = table.concat(p.notes, "\n")
    H.match(notes, project .. "/.env has 1 more hard link outside the project", true)
    H.match(table.concat(ui.lines(p), "\n"), "1 elsewhere NOT hidden", true)
  end)

  it("a hidden file with a single link produces no entry and no warning", function()
    local project = H.fixture("basic")
    write(project .. "/.env", "SECRET=1\n")
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    H.eq({}, p.hardlinks)
    H.no_match(table.concat(p.notes, "\n"), "hard link", true)
  end)

  it("a credentials file of $HOME with another link inside the project hides that name too (denylist view)", function()
    local home = vim.uv.os_homedir()
    local project = home .. "/hardlink-project" -- same file system as $HOME: hard links cannot cross it
    write(project .. "/Cargo.toml", "[package]\n")
    write(home .. "/.netrc", "machine x password y\n")
    H.ok(vim.uv.fs_link(home .. "/.netrc", project .. "/netrc-copy.txt"), "hard link")
    sb.config.home = "denylist"
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    vim.uv.fs_unlink(home .. "/.netrc")
    vim.fn.delete(project, "rf")
    local paths = vim.tbl_map(function(h) return h.path end, p.hidden)
    H.has(paths, home .. "/.netrc")
    H.has(paths, project .. "/netrc-copy.txt")
    H.eq(0, p.hardlinks[1].unaccounted)
  end)
end)

-- --------------------------------------------------------------- symlinks named like secrets

describe("a symlink named like a secret", function()
  it("inside the project: the target is hidden, nothing fails, the link reads empty", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.fixture("basic")
    write(project .. "/config/real.env", "SYMLINK-SECRET=1\n")
    vim.uv.fs_symlink("config/real.env", project .. "/.env")
    local cmd, err, h = sb.wrap({ "bash", "-c", "cat .env config/real.env; echo end" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "mount on symlink", true, out)
    H.no_match(out, "SYMLINK-SECRET", true, out)
    H.match(out, "end", true, out)
    H.eq(0, r.code, out)
  end)

  it("pointing outside: the visible target is hidden by path, never bound over the link itself", function()
    local entries = {
      ["/p"] = "directory", ["/p/.npmrc"] = "file", ["/etc/outside-secret"] = "file", ["/h"] = "directory", ["/h/.claude"] = "directory",
    }
    local probes = {
      stat_type = function(x) return entries[x] end,
      lstat_type = function(x) return x == "/p/.npmrc" and "link" or entries[x] end,
      exists = function(x) return entries[x] ~= nil end,
      list = function(d) if d == "/p" then return { { ".npmrc", "link" } } end return {} end,
      glob = function() return {} end, read_line = function() return nil end,
      realpath = function(x) return x == "/p/.npmrc" and "/etc/outside-secret" or (entries[x] and x or nil) end,
    }
    local p = plan.build({ project = "/p", tmp_dir = "/h/s", home = "/h", uid = 1, env = { PATH = "/usr/bin" }, cmd = { "a" },
      aux = { empty = "/e" }, config = { network = "open" }, probes = probes })
    local paths = vim.tbl_map(function(h) return h.path end, p.hidden)
    H.has(paths, "/etc/outside-secret")
    H.not_ok(vim.tbl_contains(paths, "/p/.npmrc"), "the link itself is never a mount destination")
  end)

  it("a dangling secret-named link is skipped quietly", function()
    local project = H.fixture("basic")
    vim.uv.fs_symlink("does/not/exist", project .. "/.env")
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    for _, h in ipairs(p.hidden) do
      H.not_ok(h.path == project .. "/.env")
    end
  end)

  it("a credentials file of $HOME that is a symlink (dotfile manager): its target is hidden, bwrap starts (denylist view)", function()
    H.need_sandbox()
    local home = vim.uv.os_homedir()
    write(home .. "/dotfiles/npmrc", "//registry:_authToken=DOTFILE-SECRET\n")
    vim.uv.fs_symlink(home .. "/dotfiles/npmrc", home .. "/.npmrc")
    sb.config.network = "open"
    sb.config.home = "denylist"
    local project = H.tmpdir()
    local cmd, err, h = sb.wrap({ "bash", "-c", 'cat "$HOME/.npmrc" "$HOME/dotfiles/npmrc"; echo end' }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    vim.uv.fs_unlink(home .. "/.npmrc")
    vim.fn.delete(home .. "/dotfiles", "rf")
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "DOTFILE-SECRET", true, out)
    H.no_match(out, "mount on symlink", true, out)
    H.match(out, "end", true, out)
  end)
end)
