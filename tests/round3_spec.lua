-- Third hardening round: what independent verification found missing. Each describe pins one finding;
-- plan specs use a fake filesystem, behavioural specs run real commands in a real sandbox on the
-- suite's private $HOME. The mutation table in CHANGELOG.md names the source edit that makes each
-- of these fail.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local scan = require("xyno_sandbox.scan")
local sanitize = require("xyno_sandbox.sanitize")
local store = require("xyno_sandbox.store")
local ui = require("xyno_sandbox.ui")
local harness = require("xynotest.harness")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
local env_restore = {}
local function setenv(name, value)
  env_restore[#env_restore + 1] = { name, uv.os_getenv(name) }
  uv.os_setenv(name, value)
end
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
  for i = #env_restore, 1, -1 do
    local e = env_restore[i]
    if e[2] == nil then
      uv.os_unsetenv(e[1])
    else
      uv.os_setenv(e[1], e[2])
    end
  end
  env_restore = {}
end)

local function write(path, text, mode)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text)
  f:close()
  if mode then
    uv.fs_chmod(path, mode)
  end
end

local GH = "ghp_" .. string.rep("Zq7x", 9)

-- ---------------------------------------------------------------- fake filesystem

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

--- entries: path -> type; info: path -> { nlink, dev, ino }; links: path -> real target
local function fakefs(entries, info, real)
  local p = {
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
    glob = function(pat)
      local out = {}
      local lp = "^" .. pat:gsub("[%-%.%+%[%]%(%)%$%^%%]", "%%%0"):gsub("%*", "[^/]*") .. "$"
      for x in pairs(entries) do
        if x:match(lp) then
          out[#out + 1] = x
        end
      end
      table.sort(out)
      return out
    end,
    read_line = function() return nil end,
    realpath = function(x) return (real or {})[x] or (entries[x] and x) or nil end,
    stat_info = function(x) return (info or {})[x] end,
  }
  return p
end

local function build(extra, over, info, scan_result)
  local entries = vim.tbl_extend("force", {
    [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  local probes = fakefs(entries, info)
  if scan_result then
    probes.scan_project = function() return scan_result end
  end
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = probes,
    env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
    config = { network = "open" },
  }, over or {}))
end

local function hidden(p)
  local out = {}
  for _, h in ipairs(p.hidden) do
    out[h.path] = h
  end
  return out
end

-- ------------------------------------------------- 1. hard links to $HOME credentials

describe("a project file that is a hard link of a credential in $HOME", function()
  local extra = { [HOME .. "/.ssh"] = "directory", [HOME .. "/.ssh/id_rsa"] = "file", [PROJECT .. "/innocent.txt"] = "file" }
  local info = { [HOME .. "/.ssh/id_rsa"] = { nlink = 2, dev = 7, ino = 4242 } }
  local scanned = { hits = {}, files = 1, multi = { { path = PROJECT .. "/innocent.txt", dev = 7, ino = 4242, nlink = 2 } } }

  for _, mode in ipairs({ "allowlist", "denylist" }) do
    it("is hidden in the " .. mode .. " view, and the preview says why", function()
      local p = build(extra, { config = { network = "open", home = mode } }, info, scanned)
      local h = hidden(p)[PROJECT .. "/innocent.txt"]
      H.ok(h, "the hard link of ~/.ssh/id_rsa stays readable")
      H.match(h.why, "hard link of the credential " .. HOME .. "/.ssh/id_rsa", true)
      local text = table.concat(ui.lines(p, { home = HOME }), "\n")
      H.match(text, "innocent.txt", true)
    end)
  end

  it("is left alone when the inode differs (a different file with the same link count)", function()
    local other = { hits = {}, files = 1, multi = { { path = PROJECT .. "/innocent.txt", dev = 7, ino = 1, nlink = 2 } } }
    local p = build(extra, nil, info, other)
    H.eq(nil, hidden(p)[PROJECT .. "/innocent.txt"])
  end)

  it("really is unreadable in a sandbox (allowlist and denylist), and the host file is unchanged", function()
    H.need_sandbox()
    for _, mode in ipairs({ "allowlist", "denylist" }) do
      sb.config.home = mode
      sb.config.network = "open"
      local home = uv.os_homedir()
      local project = H.tmpdir()
      -- the credential must be one the policy hides: ~/.ssh of the suite's private $HOME
      local real = home .. "/.ssh/id_rsa"
      write(real, "CANARY_SSH_" .. mode .. "\n", tonumber("600", 8))
      uv.fs_link(real, project .. "/hardlink_innocent.txt")
      local cmd, err, h = sb.wrap({ "cat", "hardlink_innocent.txt" }, project, H.tmpdir())
      H.ok(cmd, err)
      local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
      h.release()
      vim.fn.delete(home .. "/.ssh", "rf")
      H.no_match((r.stdout or "") .. (r.stderr or ""), "CANARY_SSH", true)
    end
  end)
end)

-- ------------------------------------------------ 2. secrets inside shown toolchain trees

describe("secrets inside the toolchain trees shown from $HOME", function()
  local function tree_entries()
    local e = {}
    for _, d in ipairs({ "dotfiles/bin", "dotfiles/.ssh", ".npm-global/bin", "go/bin", ".config/tool/bin", ".config/tool/secrets" }) do
      local acc = HOME
      for seg in d:gmatch("[^/]+") do
        acc = acc .. "/" .. seg
        e[acc] = "directory"
      end
    end
    e[HOME .. "/dotfiles/.ssh/id_rsa"] = "file"
    e[HOME .. "/dotfiles/bin/tool"] = "file"
    e[HOME .. "/.npm-global/.npmrc"] = "file"
    e[HOME .. "/go/credentials"] = "file"
    e[HOME .. "/.config/tool/secrets/key"] = "file"
    e[HOME .. "/.config/tool/bin/tool2"] = "file"
    return e
  end
  local PATHS = table.concat({ HOME .. "/dotfiles/bin", HOME .. "/.npm-global/bin", HOME .. "/go/bin", HOME .. "/.config/tool/bin", "/usr/bin" }, ":")

  it("are hidden by name: .ssh directories, .npmrc, credentials, secrets/ directories", function()
    local p = build(tree_entries(), { env = { PATH = PATHS }, config = { network = "open", home = "allowlist" } })
    local h = hidden(p)
    for _, want in ipairs({ "/dotfiles/.ssh", "/.npm-global/.npmrc", "/go/credentials", "/.config/tool/secrets" }) do
      H.ok(h[HOME .. want], want .. " is shown inside the allowed tree")
      H.match(h[HOME .. want].why, "secret in the shown tree", true)
    end
    H.eq(nil, h[HOME .. "/dotfiles/bin/tool"], "the tool itself stays")
    H.eq(nil, h[HOME .. "/.config/tool/bin/tool2"], "the tool itself stays")
  end)

  it("can be switched off with policy.tree_secrets = false", function()
    local p = build(tree_entries(), { env = { PATH = PATHS }, config = { network = "open", home = "allowlist", policy = { tree_secrets = false } } })
    H.eq(nil, hidden(p)[HOME .. "/go/credentials"])
  end)

  it("does not enter package caches (registry, node_modules)", function()
    local e = tree_entries()
    e[HOME .. "/go/bin/node_modules"] = "directory"
    e[HOME .. "/.npm-global/node_modules"] = "directory"
    e[HOME .. "/.npm-global/node_modules/.npmrc"] = "file"
    local p = build(e, { env = { PATH = PATHS }, config = { network = "open", home = "allowlist" } })
    H.eq(nil, hidden(p)[HOME .. "/.npm-global/node_modules/.npmrc"])
  end)

  it("really are unreadable in a sandbox while the tools stay runnable", function()
    H.need_sandbox()
    sb.config.network = "open"
    local home = uv.os_homedir()
    local base = home .. "/r3tree"
    vim.fn.delete(base, "rf")
    write(base .. "/dotfiles/.ssh/id_rsa", "CANARY_DOT\n")
    write(base .. "/dotfiles/bin/hello", "#!/bin/sh\necho TOOL-RUNS\n", tonumber("755", 8))
    write(base .. "/npm/.npmrc", "CANARY_NPMRC\n")
    write(base .. "/npm/bin/x", "#!/bin/sh\n", tonumber("755", 8))
    write(base .. "/tool/secrets/key", "CANARY_KEY\n")
    write(base .. "/tool/bin/x", "#!/bin/sh\n", tonumber("755", 8))
    setenv("PATH", table.concat({ base .. "/dotfiles/bin", base .. "/npm/bin", base .. "/tool/bin" }, ":") .. ":" .. uv.os_getenv("PATH"))
    local project = H.tmpdir()
    local script = ("hello; cat %s/dotfiles/.ssh/id_rsa %s/npm/.npmrc %s/tool/secrets/key 2>&1; ls %s/dotfiles/.ssh | wc -l"):format(base, base, base, base)
    local cmd, err, h = sb.wrap({ "sh", "-c", script }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    vim.fn.delete(base, "rf")
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "TOOL-RUNS", true, out)
    for _, c in ipairs({ "CANARY_DOT", "CANARY_NPMRC", "CANARY_KEY" }) do
      H.no_match(out, c, true, out)
    end
  end)
end)

-- ------------------------------------------------------------ 3. environment: by value

describe("the environment scrub looks at values and at more name shapes", function()
  local function stripped(env)
    local out = {}
    for _, n in ipairs(plan.scrub_names(env, true)) do
      out[n] = true
    end
    return out
  end

  it("strips a token under any name: the value is recognised", function()
    local env = { FOO = GH, NOTES = "see " .. GH .. " for access", PATH = "/usr/bin" }
    local s = stripped(env)
    H.ok(s.FOO and s.NOTES, "a GitHub token in a variable nobody listed")
    H.not_ok(s.PATH)
  end)

  it("strips credentials in a URL under any name, empty user included (redis://:pw@host)", function()
    local s = stripped({ CACHE = "redis://:hunter2hunter2@cache.internal:6379/0", DB = "postgres://app:Qp8vN2mXz4Lw@db/x" })
    H.ok(s.CACHE and s.DB)
  end)

  it("strips the name shapes that were missed: *_KEY, *_DSN, *_SESSION, JWT, COOKIE, BEARER, AUTH", function()
    local names = { "OPENROUTER_KEY", "GROQ_KEY", "NUGET_KEY", "SENTRY_DSN", "BW_SESSION", "CI_JOB_JWT", "JWT", "COOKIE", "BEARER",
      "AUTH", "SESSION", "RAILS_MASTER_KEY", "SERPAPI", "SOME_COOKIE_JAR", "X_BEARER_TOKEN_2" }
    local env = {}
    for _, n in ipairs(names) do
      env[n] = "plain-value"
    end
    local s = stripped(env)
    for _, n in ipairs(names) do
      H.ok(s[n], n .. " reaches the sandbox")
    end
  end)

  it("keeps ordinary variables, including session-looking ones that are not secrets", function()
    local env = { LANG = "C.UTF-8", TERM = "xterm", XDG_SESSION_TYPE = "wayland", XDG_SESSION_ID = "3", EDITOR = "nvim", SHELL = "/bin/bash",
      COLORTERM = "truecolor", PATH = "/usr/bin:/bin", DESKTOP_SESSION = "plasma" }
    H.eq({}, vim.tbl_keys(stripped(env)))
  end)

  it("a placeholder value (the format spelled out) is not a secret", function()
    H.eq({}, vim.tbl_keys(stripped({ HINT = "ghp_" .. string.rep("x", 36) .. " is the format" })))
  end)

  it("the value never exists in a real sandbox: env, /proc/1/environ", function()
    H.need_sandbox()
    sb.config.network = "open"
    setenv("FOO_CANARY", GH)
    setenv("OPENROUTER_KEY", "CANARY_OPENROUTER")
    local project = H.tmpdir()
    local cmd, err, h = sb.wrap({ "sh", "-c", "env; tr '\\0' '\\n' < /proc/1/environ" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "PATH=", true, out)
    H.no_match(out, GH, true)
    H.no_match(out, "CANARY_OPENROUTER", true)
    H.no_match(out, "FOO_CANARY", true)
  end)
end)

-- --------------------------------------------------------------- 4. sockets everywhere

describe("project sockets in directories the walk skips, and deep down", function()
  local deep = PROJECT
  for i = 1, 12 do
    deep = deep .. "/d" .. i
  end
  local extra = {
    [PROJECT .. "/target"] = "directory", [PROJECT .. "/target/debug"] = "directory", [PROJECT .. "/target/debug/a.sock"] = "socket",
    [PROJECT .. "/node_modules"] = "directory", [PROJECT .. "/node_modules/p"] = "directory", [PROJECT .. "/node_modules/p/b.sock"] = "socket",
    [PROJECT .. "/.cache"] = "directory", [PROJECT .. "/.cache/c.sock"] = "socket",
    [PROJECT .. "/top.sock"] = "socket", [PROJECT .. "/.git/fsmonitor--daemon.ipc"] = "socket",
  }
  do
    local acc = PROJECT
    for i = 1, 12 do
      acc = acc .. "/d" .. i
      extra[acc] = "directory"
    end
    extra[deep .. "/deep.sock"] = "socket"
  end

  it("are all hidden (target/, node_modules/, .cache/, .git/, below depth 8)", function()
    local p = build(extra)
    local h = hidden(p)
    for _, s in ipairs({ "/target/debug/a.sock", "/node_modules/p/b.sock", "/.cache/c.sock", "/top.sock", "/.git/fsmonitor--daemon.ipc" }) do
      H.ok(h[PROJECT .. s], s .. " is connectable in the sandbox")
      H.eq("project socket", h[PROJECT .. s].why)
    end
    H.ok(h[deep .. "/deep.sock"], "a socket 12 levels down")
  end)

  it("a search that runs out of budget says so in the plan", function()
    local old = plan.SOCK_MAX_DIRS
    plan.SOCK_MAX_DIRS = 2
    local p = build(extra)
    plan.SOCK_MAX_DIRS = old
    local found = false
    for _, n in ipairs(p.notes) do
      found = found or n:find("socket search stopped", 1, true) ~= nil
    end
    H.ok(found, vim.inspect(p.notes))
  end)

  it("really are not connectable in a sandbox", function()
    H.need_sandbox()
    if vim.fn.executable("python3") ~= 1 then
      return harness.skip("no python3 to connect with")
    end
    sb.config.network = "open"
    local project = H.tmpdir()
    local paths = { project .. "/target/debug/a.sock", project .. "/node_modules/p/b.sock", project .. "/.cache/c.sock",
      project .. "/d1/d2/d3/d4/d5/d6/d7/d8/d9/d10/deep.sock" }
    local pipes = {}
    for _, p in ipairs(paths) do
      vim.fn.mkdir(vim.fs.dirname(p), "p")
      local pipe = uv.new_pipe(false)
      local ok, e = pipe:bind(p)
      H.ok(ok, tostring(e) .. " " .. p)
      pipe:listen(4, function() end)
      pipes[#pipes + 1] = pipe
    end
    local py = "import socket,sys\nfor p in sys.argv[1:]:\n s=socket.socket(socket.AF_UNIX)\n s.settimeout(1)\n try:\n  s.connect(p); print('CONNECTED',p)\n except OSError as e:\n  print('refused',p)\n"
    local cmd, err, h = sb.wrap(vim.list_extend({ "python3", "-I", "-c", py }, paths), project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    for _, pipe in ipairs(pipes) do
      pipe:close()
    end
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "refused", true, out)
    H.no_match(out, "CONNECTED", true, out)
  end)
end)

-- ------------------------------------------------------------ 5. more secret names

describe("project secret names that were missed", function()
  local names = { ".vault-token", ".env~", "auth.json", "rclone.conf", ".terraformrc", ".secret", ".npmrc.bak", "id_rsa.bak",
    "id_ed25519_sk", "wallet.dat", "creds.json", "oauth_token", "sa.json", "serviceaccount.json", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", ".npmrc", "token.txt", "api_keys.txt", ".dev.vars", "serviceAccountKey.json", "google-services.json", "wp-config.php",
    "application-prod.properties" }
  it("are secret by base name", function()
    local globs = plan.PROJECT_SECRET_GLOBS
    for _, n in ipairs(names) do
      H.ok(plan.is_secret_name(n, globs, plan.PROJECT_SECRET_EXCEPT), n .. " is not recognised as a secret name")
    end
  end)

  it("public keys, templates and source files that merely mention keys stay readable", function()
    local globs = plan.PROJECT_SECRET_GLOBS
    for _, n in ipairs({ "id_rsa.pub", "id_ed25519.pub", ".env.example", "tokenizer.rs", "api_key.rs", "README.md", "secretary.md" }) do
      H.not_ok(plan.is_secret_name(n, globs, plan.PROJECT_SECRET_EXCEPT), n .. " is hidden")
    end
  end)

  it("are hidden by path where the base name says nothing (.docker/config.json ...) and as directories (.envs/)", function()
    local e = {}
    for _, f in ipairs({ ".docker/config.json", ".config/gh/hosts.yml", ".composer/auth.json", ".m2/settings.xml", ".gradle/gradle.properties", ".envs/prod" }) do
      local acc = PROJECT
      local dir = vim.fs.dirname(f)
      for seg in dir:gmatch("[^/]+") do
        acc = acc .. "/" .. seg
        e[acc] = "directory"
      end
      e[PROJECT .. "/" .. f] = "file"
    end
    e[PROJECT .. "/src"] = "directory"
    e[PROJECT .. "/src/config.json"] = "file"
    local p = build(e)
    local h = hidden(p)
    for _, f in ipairs({ ".docker/config.json", ".config/gh/hosts.yml", ".composer/auth.json", ".m2/settings.xml", ".gradle/gradle.properties" }) do
      H.ok(h[PROJECT .. "/" .. f], f .. " is readable")
    end
    H.ok(h[PROJECT .. "/.envs"], "the .envs directory")
    H.eq(nil, h[PROJECT .. "/src/config.json"], "a config.json elsewhere is not a secret")
  end)

  it("really are unreadable in a sandbox", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.tmpdir()
    local files = { ".vault-token", ".docker/config.json", ".env~", ".envs/prod", "id_rsa.bak", "wallet.dat", "sa.json", "auth.json" }
    for _, f in ipairs(files) do
      write(project .. "/" .. f, "CANARY_NAME\n")
    end
    write(project .. "/id_rsa.pub", "PUBLIC-OK\n")
    local cmd, err, h = sb.wrap({ "sh", "-c", "cat id_rsa.pub; cat .vault-token .docker/config.json .env~ .envs/prod id_rsa.bak wallet.dat sa.json auth.json 2>&1" },
      project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "PUBLIC-OK", true, out)
    H.no_match(out, "CANARY_NAME", true, out)
  end)
end)

-- ---------------------------------------------------------------- 6. content scan

describe("the content scan judges the match, not the line", function()
  it("finds a real token on a line that says example / fake / dummy", function()
    for _, line in ipairs({
      "TOKEN=" .. GH .. " # example",
      "git clone https://example.com/x # fake? no: " .. GH,
      "dummy_setup(); token = '" .. GH .. "'",
      "https://user:Tr0ub4dor9xQ@example.com/repo.git",
    }) do
      H.ok(#scan.text(line) > 0, "not found: " .. line:gsub(GH, "<token>"))
    end
  end)

  it("skips a match that spells out that it is not real", function()
    for _, line in ipairs({
      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
      "token = ghp_" .. string.rep("x", 36),
      "gh_example = ghp_" .. string.rep("A1b2", 9) .. "_EXAMPLE_",
    }) do
      H.eq({}, scan.text(line), line)
    end
  end)

  it("reads long lines too (a minified file)", function()
    H.eq({ "GitHub token" }, scan.text(string.rep("x = 1;", 1500) .. " t='" .. GH .. "';"))
  end)

  it("a password in a URL: short, templated and obviously fake ones are not hits; redis://:pw@ is", function()
    H.eq({}, scan.text("https://u:short@h.example/x"))
    H.eq({}, scan.text("https://u:${PASSWORD}word@h.example/x"))
    H.eq({}, scan.text("https://u:<password-here>@h.example/x"))
    H.eq({}, scan.text("https://user:changeme123@h.example/x"))
    H.eq({}, scan.text("https://u:100%25percent@h.example/x"))
    H.eq({ "credentials in a URL" }, scan.text("REDIS=redis://:Zx9pLmQ2vT8w@cache:6379"))
  end)

  it("counts what it could not read, and the preview says so", function()
    local dir = H.tmpdir()
    write(dir .. "/big.txt", string.rep("a", scan.MAX_FILE_BYTES + 10))
    write(dir .. "/bin.dat", "ab\0cd" .. GH)
    write(dir .. "/a.zip", GH)
    write(dir .. "/ok.txt", "nothing\n")
    local res = scan.project(dir)
    H.eq(1, res.unread.large)
    H.eq(1, res.unread.binary)
    H.eq(1, res.unread.extension)
    H.eq(0, #res.hits)
    local p = plan.build({
      project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, env = { PATH = "/bin" }, cmd = { "agent" },
      probes = vim.tbl_extend("force", fakefs({ [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory" }),
        { scan_project = function() return res end }),
      aux = { empty = "/e" }, config = { network = "open" },
    })
    local text = table.concat(ui.lines(p, { home = HOME }), "\n")
    H.match(text, "Not read at all: 1 over 256 KB, 1 binary", true)
  end)
end)

-- ------------------------------------------------------------ 7. the ~/.claude.json copy

describe("the ~/.claude.json copy keeps the login state and drops the rest", function()
  local function scrub(data, project)
    return sanitize.claude_json(vim.deepcopy(data), { project })
  end
  local DATA = {
    numStartups = 3, theme = "dark",
    mcpServers = {
      gh = { command = "npx", args = { "-y", "srv", "--token", GH }, env = { GITHUB_TOKEN = GH }, headers = { Authorization = "Bearer " .. GH } },
      api = { type = "http", url = "https://user:Tr0ub4dor9xQ@api.internal/mcp", headers = { ["X-Key"] = "k" } },
      plain = { command = "node", args = { "server.js" } },
    },
    primaryApiKey = "sk-ant-" .. string.rep("a", 50), customApiKeyResponses = { approved = { "abc" } },
    oauthAccount = { accountUuid = "u-1", emailAddress = "me@corp.example", displayName = "Me" },
    userID = "anon-123", history = { "an old prompt" },
    projects = { ["/p"] = { hasTrustDialogAccepted = true, mcpServers = { x = { command = "c", env = { K = "v" } } } }, ["/other"] = { history = { "other" } } },
  }

  it("removes MCP credentials (env, headers, token arguments, URL passwords) and keeps the servers", function()
    local out = scrub(DATA, "/p")
    H.eq("npx", out.mcpServers.gh.command)
    H.eq(nil, out.mcpServers.gh.env)
    H.eq(nil, out.mcpServers.gh.headers)
    H.eq("", out.mcpServers.gh.args[4])
    H.eq("", out.mcpServers.api.url)
    H.eq({ "server.js" }, out.mcpServers.plain.args)
    H.eq(nil, out.projects["/p"].mcpServers.x.env, "project-level MCP servers too")
    H.no_match(vim.json.encode(out), GH, true)
  end)

  it("removes API keys, the account's e-mail and name, the anonymous id and the old history", function()
    local out = scrub(DATA, "/p")
    H.eq(nil, out.primaryApiKey)
    H.eq(nil, out.customApiKeyResponses)
    H.eq(nil, out.userID)
    H.eq(nil, out.history)
    H.eq(nil, out.oauthAccount.emailAddress)
    H.eq(nil, out.oauthAccount.displayName)
    H.eq("u-1", out.oauthAccount.accountUuid)
    H.eq(3, out.numStartups)
    H.eq({ "/p" }, vim.tbl_keys(out.projects))
  end)

  it("a key whose NAME says credential loses its value at any depth", function()
    local out = scrub({ a = { b = { apiToken = "x", password = "y", keep = 1 } } }, "/p")
    H.eq({ keep = 1 }, out.a.b)
  end)

  it("the file the sandbox gets is the scrubbed copy", function()
    local d = H.tmpdir()
    write(d .. "/in.json", vim.json.encode(DATA))
    H.ok(sb.write_scrubbed_claude_json(d .. "/in.json", d .. "/out.json", "/p"))
    local raw = table.concat(vim.fn.readfile(d .. "/out.json"), "\n")
    H.no_match(raw, GH, true)
    H.no_match(raw, "me@corp.example", true)
    H.no_match(raw, "anon-123", true)
  end)
end)

-- ----------------------------------------------- 8. files left behind by a dead nvim

describe("private copies of a Neovim that was killed", function()
  it("are removed by the next launch (claude.json copy, socket directory, git configs), and nothing else", function()
    local project, tmp = H.tmpdir(), H.tmpdir()
    write(project .. "/.git/config", '[remote "o"]\n\turl = https://u:' .. GH .. "@github.com/x/y\n")
    write(uv.os_homedir() .. "/.claude.json", '{"numStartups":1}\n')
    local cmd, err, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd, err)
    local temps = vim.list_extend({}, h.temp)
    temps[#temps + 1] = h.net_dir
    H.ok(#temps >= 2, vim.inspect(temps))
    for _, t in ipairs(temps) do
      H.ok(uv.fs_stat(t), "exists while live: " .. t)
    end
    local bystander = H.tmpdir() .. "/bystander.txt"
    write(bystander, "mine")
    -- the registry file of a nvim that died: same content, a pid that is gone
    local dead_pid = vim.system({ "sh", "-c", "echo $$" }, { text = true }):wait().stdout:match("%d+")
    H.ok(dead_pid)
    local dir = store.dir() .. "/live"
    local entries = vim.fn.readdir(dir)
    H.eq(1, #entries)
    local lines = vim.fn.readfile(dir .. "/" .. entries[1])
    lines[#lines + 1] = "temp\t" .. bystander
    uv.fs_unlink(dir .. "/" .. entries[1])
    vim.fn.writefile(lines, dir .. "/" .. dead_pid .. "-1-x")
    sb.reap_orphans()
    for _, t in ipairs(temps) do
      H.eq(nil, uv.fs_lstat(t), "left behind: " .. t)
    end
    H.ok(uv.fs_stat(bystander), "a recorded path that wrap() does not create is never deleted")
    h.release()
  end)
end)

-- ---------------------------------------------------- 9. suite hermeticity (the runner)

local function nested(body, env)
  local dir = H.tmpdir()
  write(dir .. "/inner_spec.lua", body)
  local e = vim.tbl_extend("force", { XYNO_TEST_WORKER = "0" }, env or {})
  local r = vim.system({ vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/inner_spec.lua" }, { text = true, env = e }):wait(180000)
  return r.stdout or "", r.code
end

describe("the runner", function()
  it("does not honour the caller's TMPDIR (a deep one broke every proxy socket path)", function()
    local report = H.tmpdir() .. "/report"
    local deep = H.tmpdir() .. "/" .. string.rep("very-deep-directory-name/", 4)
    vim.fn.mkdir(deep, "p")
    local out, code = nested([[
      it("reports", function() vim.fn.writefile({ vim.env.XYNO_TEST_SCRATCH, vim.env.XYNO_TEST_ROOT }, vim.env.XYNO_TEST_REPORT) end)
    ]], { TMPDIR = deep, XYNO_TEST_REPORT = report })
    H.eq(0, code, out)
    local got = vim.fn.readfile(report)
    H.eq("/tmp/xyno-run-", got[1]:sub(1, 14), "the scratch directory follows TMPDIR: " .. got[1])
    H.no_match(got[1], "very-deep", true)
  end)

  it("fails (not skips) when bubblewrap works for the runner but the plugin cannot start a sandbox", function()
    if not H.sandbox_available() then
      return harness.skip("needs a working bubblewrap")
    end
    local bin = H.tmpdir()
    local state = H.tmpdir() .. "/state"
    write(bin .. "/bwrap", ("#!/bin/sh\nif [ -e %s ]; then echo 'bwrap: fake failure' >&2; exit 1; fi\ntouch %s\nexit 0\n"):format(state, state), tonumber("755", 8))
    local out, code = nested([[
      local H = require("xynotest.helpers")
      it("needs a sandbox", function() H.need_sandbox() end)
    ]], { PATH = bin .. ":" .. vim.env.PATH })
    H.eq(1, code, out)
    H.match(out, "bubblewrap works on this machine", true, out)
    H.match(out, "failed=1", true)
  end)

  it("kills a spec file that hangs and fails the run with a clear line", function()
    local out, code = nested([[
      it("hangs", function() vim.wait(120000) end)
    ]], { XYNO_TEST_FILE_TIMEOUT_MS = "2500" })
    H.eq(1, code, out)
    H.match(out, "timed out", true, out)
  end)
end)
