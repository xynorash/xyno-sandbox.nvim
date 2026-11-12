-- Specs for the mutants that two independent verifiers reported as surviving the third round
-- (names as in CHANGELOG.md): the argv of kept /run entries, a socket under /tmp, home_allow outside
-- or through a symlink, NO_PROXY, hard-link aliases, '..' in approvals, submodule and sanitizer
-- branches, the URL placeholder filter, key file names, /var/run, kept /run entries, $NVIM, the
-- relay, a double release and the front door of approvals. Each assertion is written against an
-- observable result, not against a line of the source.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local sanitize = require("xyno_sandbox.sanitize")
local scan = require("xyno_sandbox.scan")
local store = require("xyno_sandbox.store")
local exceptions = require("xyno_sandbox.exceptions")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

--- entries: path -> type; links: path -> target (lstat says "link", stat/realpath follow it)
local function fakefs(entries, links, info)
  links = links or {}
  local function follow(x)
    local seen = 0
    while links[x] and seen < 10 do
      x = links[x]
      seen = seen + 1
    end
    return x
  end
  return {
    stat_type = function(x)
      return entries[follow(x)]
    end,
    lstat_type = function(x)
      return links[x] and "link" or entries[x]
    end,
    exists = function(x)
      return links[x] ~= nil or entries[x] ~= nil
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
    read_line = function()
      return nil
    end,
    realpath = function(x)
      local r = follow(x)
      return (entries[r] ~= nil) and r or nil
    end,
    stat_info = function(x)
      return (info or {})[x]
    end,
  }
end

local function build(extra, over, links)
  local entries = vim.tbl_extend("force", {
    [HOME] = "directory",
    [HOME .. "/.claude"] = "directory",
    [PROJECT] = "directory",
    [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT,
    tmp_dir = TMP,
    cwd = PROJECT,
    home = HOME,
    uid = 1000,
    probes = fakefs(entries, links),
    env = { PATH = "/usr/bin" },
    cmd = { "agent" },
    aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git", net_dir = "/aux/net" },
    config = { network = "open", home = "denylist" },
  }, over or {}))
end

--- Does argv contain these consecutive arguments?
local function has_seq(argv, ...)
  local want = { ... }
  for i = 1, #argv - #want + 1 do
    local all = true
    for j = 1, #want do
      all = all and argv[i + j - 1] == want[j]
    end
    if all then
      return i
    end
  end
end

-- ----------------------------------------------------------------- run_keep, /var/run, $NVIM

describe("entries of /run that are kept", function()
  local entries = {
    ["/run"] = "directory",
    ["/run/current-system"] = "directory",
    ["/run/booted-system"] = "directory",
    ["/run/opengl-driver"] = "directory",
    ["/run/user"] = "directory",
    ["/run/user/1000"] = "directory",
  }
  it("are mounted read-only in the argv, after /run was replaced, and never writable", function()
    local p = build(entries)
    local argv = plan.argv(p)
    local tm = has_seq(argv, "--tmpfs", "/run")
    H.ok(tm, "/run is emptied")
    for _, k in ipairs({ "/run/current-system", "/run/booted-system", "/run/opengl-driver" }) do
      local i = has_seq(argv, "--ro-bind", k, k)
      H.ok(i, k .. " is bound back read-only")
      H.ok(i > tm, k .. " comes after the tmpfs it sits in")
      H.eq(nil, has_seq(argv, "--bind", k, k), k .. " must not be writable")
    end
    H.eq(nil, has_seq(argv, "--ro-bind", "/run/user", "/run/user"), "the sockets directory is not kept")
    H.eq(nil, has_seq(argv, "--bind", "/run/user/1000", "/run/user/1000"))
    H.eq(3, #p.run_keep)
  end)

  it("policy.keep_run adds one, read-only, only below a masked directory", function()
    local p = build(
      vim.tbl_extend(
        "force",
        entries,
        { ["/run/extra"] = "directory", ["/srv"] = "directory", ["/srv/x"] = "directory" }
      ),
      { config = { network = "open", home = "denylist", policy = { keep_run = { "/run/extra", "/srv/x" } } } }
    )
    local argv = plan.argv(p)
    H.ok(has_seq(argv, "--ro-bind", "/run/extra", "/run/extra"))
    H.eq(nil, has_seq(argv, "--ro-bind", "/srv/x", "/srv/x"), "not below a masked directory: nothing to bring back")
    H.eq(nil, has_seq(argv, "--bind", "/run/extra", "/run/extra"))
  end)

  it("a missing entry is not mounted", function()
    local p = build({ ["/run"] = "directory" })
    H.eq({}, p.run_keep)
    H.eq(nil, has_seq(plan.argv(p), "--ro-bind", "/run/current-system", "/run/current-system"))
  end)
end)

describe("/var/run", function()
  it("a real directory is replaced by an empty tmpfs in the argv; the usual symlink to /run is not touched", function()
    local p = build({ ["/var/run"] = "directory", ["/run"] = "directory" })
    H.ok(has_seq(plan.argv(p), "--tmpfs", "/var/run"))
    local q = build({ ["/var/run"] = "link", ["/run"] = "directory" })
    H.eq(nil, has_seq(plan.argv(q), "--tmpfs", "/var/run"))
    local r = build({ ["/run"] = "directory" })
    H.eq(nil, has_seq(plan.argv(r), "--tmpfs", "/var/run"), "absent")
  end)
  it("a writable approval of /var/run (or below) is refused", function()
    local ok = plan.validate_exception(
      { kind = "writable", value = "/var/run/x" },
      { home = HOME, probes = fakefs({ ["/var/run/x"] = "directory" }) }
    )
    H.eq(false, ok)
  end)
end)

describe("sockets named by the environment", function()
  it("one under /tmp is not hidden: the sandbox's /tmp is empty anyway", function()
    for _, c in ipairs({
      { "SSH_AUTH_SOCK", "/tmp/ssh-AbC123/agent.4242" },
      { "GPG_AGENT_INFO", "/tmp/gpg-xyz/S.gpg-agent:1:1" },
      { "DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/dbus-abc,guid=1" },
      { "NVIM", "/tmp/nvim.me/abc/0" },
    }) do
      local path = c[2]:gsub("^unix:path=", ""):gsub(",.*", ""):gsub(":%d.*", "")
      local p = build({ ["/tmp"] = "directory", [path] = "socket" }, { env = { PATH = "/usr/bin", [c[1]] = c[2] } })
      for _, h in ipairs(p.hidden) do
        H.not_ok(h.path == path, c[1] .. " under /tmp must not be hidden")
      end
    end
  end)

  it("one outside the masked directories is bound over with an empty file, for both nvim variables", function()
    for _, var in ipairs({ "NVIM", "NVIM_LISTEN_ADDRESS" }) do
      local p = build(
        { ["/srv-x"] = "directory", ["/srv-x/nvim.sock"] = "socket" },
        { env = { PATH = "/usr/bin", [var] = "/srv-x/nvim.sock" } }
      )
      H.ok(has_seq(plan.argv(p), "--ro-bind", "/aux/empty", "/srv-x/nvim.sock"), var)
    end
  end)
end)

-- ----------------------------------------------------------------- the home allowlist

describe("policy.home_allow", function()
  local entries = {
    ["/opt"] = "directory",
    ["/opt/tool"] = "directory",
    ["/opt/other"] = "directory",
    [HOME .. "/data"] = "directory",
    [HOME .. "/data/sub"] = "directory",
    [HOME .. "/realdir"] = "directory",
    [HOME .. "/file.txt"] = "file",
  }
  local links = {
    [HOME .. "/linkdir"] = HOME .. "/realdir",
    [HOME .. "/escape"] = "/opt/other",
    [HOME .. "/dangling"] = HOME .. "/nowhere",
  }
  local function allowed(list)
    local p =
      build(entries, { config = { network = "open", home = "allowlist", policy = { home_allow = list } } }, links)
    local out = {}
    for _, a in ipairs(p.home_allow) do
      out[a.path] = a.why
    end
    return out, p
  end

  it("only shows paths inside $HOME: a path elsewhere, $HOME itself and a missing path are ignored", function()
    local out = allowed({ "/opt/tool", HOME, "~", HOME .. "/missing", HOME .. "/data" })
    H.eq("policy.home_allow", out[HOME .. "/data"])
    H.eq(nil, out["/opt/tool"], "outside $HOME")
    H.eq(nil, out[HOME], "$HOME as a whole")
    H.eq(nil, out[HOME .. "/missing"])
  end)

  it("a child of an allowed path is not listed again", function()
    local out = allowed({ HOME .. "/data", HOME .. "/data/sub" })
    H.ok(out[HOME .. "/data"])
    H.eq(nil, out[HOME .. "/data/sub"])
  end)

  it(
    "a symlink is replaced by what it points to (bwrap cannot mount on a link); the link itself is not shown",
    function()
      local out = allowed({ HOME .. "/linkdir" })
      H.eq(nil, out[HOME .. "/linkdir"], "the link itself")
      H.eq("policy.home_allow", out[HOME .. "/realdir"], "its target")
    end
  )

  it("a symlink to somewhere outside $HOME, and a dangling one, show nothing", function()
    local out, p = allowed({ HOME .. "/escape", HOME .. "/dangling" })
    H.eq(nil, out[HOME .. "/escape"])
    H.eq(nil, out["/opt/other"], "the target is outside $HOME")
    H.eq(nil, out[HOME .. "/dangling"])
    for _, a in ipairs(p.home_allow) do
      H.not_ok(a.why == "policy.home_allow", "nothing from policy.home_allow: " .. a.path)
    end
  end)

  it("none of it applies in the denylist view", function()
    local p = build(
      entries,
      { config = { network = "open", home = "denylist", policy = { home_allow = { HOME .. "/data" } } } },
      links
    )
    H.eq({}, p.home_allow)
  end)
end)

-- ----------------------------------------------------------------- NO_PROXY

describe("proxy variables of a filtered sandbox", function()
  it("NO_PROXY and no_proxy are set to the empty string (nothing bypasses the relay)", function()
    local p = build({}, { config = { network = "filtered", home = "denylist" } })
    local argv = plan.argv(p)
    H.ok(has_seq(argv, "--setenv", "NO_PROXY", ""), "NO_PROXY")
    H.ok(has_seq(argv, "--setenv", "no_proxy", ""), "no_proxy")
    for _, n in ipairs({ "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy" }) do
      H.ok(has_seq(argv, "--setenv", n, "http://127.0.0.1:" .. p.net.port), n)
    end
  end)

  it("an open network sets none of them", function()
    local argv = plan.argv(build({}, { config = { network = "open", home = "denylist" } }))
    H.eq(nil, has_seq(argv, "--setenv", "NO_PROXY", ""))
    H.eq(nil, has_seq(argv, "--setenv", "no_proxy", ""))
  end)

  it("inside a real filtered sandbox the variables are empty even when the caller has set them", function()
    H.need_sandbox()
    sb.config.network = "filtered"
    local project = H.tmpdir()
    local cmd, err, h = sb.wrap(
      { "sh", "-c", 'echo "[$NO_PROXY][$no_proxy][$HTTPS_PROXY]"' },
      project,
      H.tmpdir(),
      { env = { NO_PROXY = "*", no_proxy = "*" } }
    )
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    H.match(r.stdout or "", "[][][http://127.0.0.1:", true, (r.stdout or "") .. (r.stderr or ""))
  end)
end)

-- ----------------------------------------------------------------- '..' and the front door

describe("approvals and '..'", function()
  it("plan.normalize refuses a path with '..' (it never drops the segment)", function()
    H.eq(nil, plan.normalize("/a/../b"))
    H.eq(nil, plan.normalize("/a/b/.."))
    H.eq(nil, plan.normalize("/.."))
    H.eq(nil, plan.normalize("relative/x"))
    H.eq(nil, plan.normalize(12))
    H.eq("/a/b/c", plan.normalize("/a/./b//c/"))
    H.eq("/", plan.normalize("/"))
    H.eq("/a/..b/c..", plan.normalize("/a/..b/c.."), "a name that merely contains dots is fine")
  end)

  it("a writable or unhide approval with '..' is refused whatever it would resolve to", function()
    local ctx = {
      home = HOME,
      probes = fakefs({ [PROJECT .. "/etc"] = "directory", ["/etc"] = "directory", [HOME .. "/.ssh"] = "directory" }),
    }
    for _, kind in ipairs({ "writable", "unhide" }) do
      for _, v in ipairs({ PROJECT .. "/../../etc", PROJECT .. "/../.ssh", "/etc/..", PROJECT .. "/.." }) do
        local ok, why = plan.validate_exception({ kind = kind, value = v }, ctx)
        H.eq(false, ok, kind .. " " .. v)
        H.match(why, "without '..'", true, kind .. " " .. v)
      end
    end
  end)

  it("sb.approve refuses it, logs the refusal, and remembers nothing", function()
    local project = H.tmpdir()
    local e, why = sb.approve(project, "writable", project .. "/../../etc", "project")
    H.eq(nil, e)
    H.match(why, "without '..'", true)
    H.eq({}, sb.approvals(project))
    H.eq("refused", store.read_log()[1].decision)
  end)
end)

describe("the front door of approvals", function()
  local ctx = { home = HOME, probes = fakefs({}) }
  it("an unknown kind is refused for every shape of the argument", function()
    for _, exc in ipairs({
      { kind = "bogus", value = "x" },
      { kind = nil, value = "x" },
      { value = "x" },
      { kind = "", value = "x" },
      { kind = "Env", value = "MY_TOKEN" },
      { kind = 7, value = "x" },
      "env",
      12,
      false,
    }) do
      local ok, why = plan.validate_exception(exc, ctx)
      H.eq(false, ok, vim.inspect(exc))
      H.match(why, "unknown exception kind", true, vim.inspect(exc))
    end
    local ok = plan.validate_exception(nil, ctx)
    H.eq(false, ok)
  end)

  it("an empty value or one that is not a string is refused for every kind", function()
    for _, kind in ipairs({ "env", "unhide", "writable", "host" }) do
      for _, v in ipairs({ "", 12, false, {}, true }) do
        local ok, why = plan.validate_exception({ kind = kind, value = v }, ctx)
        H.eq(false, ok, kind .. " " .. vim.inspect(v))
        H.match(why, "empty value", true, kind .. " " .. vim.inspect(v))
      end
      local ok2, why2 = plan.validate_exception({ kind = kind }, ctx)
      H.eq(false, ok2)
      H.match(why2, "empty value", true)
    end
  end)

  it("an env value must be a variable name", function()
    for _, v in ipairs({
      "NOT A NAME",
      "1ABC",
      "A-B",
      "A=B",
      "$(x)",
      "A B",
      "a.b",
      " MY_TOKEN",
      "MY_TOKEN ",
      "MY_TOKEN\n",
      "MY_TOKEN=1",
      "é",
    }) do
      local ok, why = plan.validate_exception({ kind = "env", value = v }, ctx)
      H.eq(false, ok, vim.inspect(v))
      H.match(why, "not an environment variable name", true, vim.inspect(v))
    end
    for _, v in ipairs({ "MY_TOKEN", "_X_KEY", "a_secret" }) do
      H.eq(true, (plan.validate_exception({ kind = "env", value = v }, ctx)), v)
    end
  end)

  it("the logged decision for a refusal names the reason and the kind, never anything else", function()
    local project = H.tmpdir()
    local e, why = exceptions.decide(project, "approved", { kind = "bogus", value = "x" })
    H.eq(nil, e)
    H.match(why, "unknown exception kind", true)
    local log = store.read_log()
    H.eq("refused", log[#log].decision)
  end)
end)

-- ----------------------------------------------------------------- git configs

describe("git configs of submodules and the sanitizer", function()
  local TOKEN = "ghp_" .. string.rep("Zq7x", 9)

  it("every submodule config gets a sanitized copy, in the plan and on disk", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.tmpdir()
    local function cfg(url)
      return '[remote "origin"]\n\turl = https://u:'
        .. TOKEN
        .. "@github.com/"
        .. url
        .. "\n\ttoken = "
        .. TOKEN
        .. "\n"
    end
    local function w(path, text)
      vim.fn.mkdir(vim.fs.dirname(path), "p")
      vim.fn.writefile(vim.split(text, "\n"), path)
    end
    w(project .. "/.git/config", cfg("x/main"))
    w(project .. "/.git/modules/a/config", cfg("x/a"))
    w(project .. "/.git/modules/b/config", cfg("x/b"))
    local cmd, err, h = sb.wrap({ "true" }, project, H.tmpdir())
    H.ok(cmd, err)
    local srcs = {}
    for _, g in ipairs(h.plan.git_configs) do
      srcs[#srcs + 1] = g.src
      local text = table.concat(vim.fn.readfile(g.copy), "\n")
      H.no_match(text, TOKEN, true, g.src)
      H.no_match(text, "token =", true, g.src)
      H.match(text, "github.com/x/", true, g.src)
    end
    table.sort(srcs)
    h.release()
    H.eq({ project .. "/.git/config", project .. "/.git/modules/a/config", project .. "/.git/modules/b/config" }, srcs)
  end)

  local function clean(t)
    return (sanitize.git_config(t))
  end

  it("drops token and password in any case, with or without spaces, and a bare key", function()
    for _, line in ipairs({
      "token = S3CR3T",
      "Token = S3CR3T",
      "TOKEN=S3CR3T",
      "password=S3CR3T",
      "PassWord = S3CR3T",
      "  password   =   S3CR3T",
      "askpass = S3CR3T",
      "extraHeader = Authorization: S3CR3T",
    }) do
      local out = clean('[remote "o"]\n\t' .. line .. "\n\turl = https://h/x\n")
      H.no_match(out, "S3CR3T", true, line)
      H.match(out, "url = https://h/x", true, line)
    end
  end)

  it("a key with no value (a bare key means true) is dropped by name as well, and its neighbours stay", function()
    for _, k in ipairs({ "token", "Password", "askpass", "extraheader" }) do
      local out = clean('[remote "o"]\n\t' .. k .. "\n\turl = https://h/x\n")
      H.eq(nil, out:lower():find(k:lower(), 1, true), k .. " kept: " .. out)
      H.match(out, "url = https://h/x", true, k)
    end
    H.match(clean("[core]\n\tbare\n"), "bare", true)
  end)

  it("drops the credential helper only in a credential section, in any case", function()
    H.no_match(clean("[credential]\n\thelper = store S3CR3T\n"), "S3CR3T", true)
    H.no_match(clean('[credential "https://h"]\n\thelper = store S3CR3T\n'), "S3CR3T", true)
    H.no_match(clean('[CREDENTIAL "https://h"]\n\tHELPER = store S3CR3T\n'), "S3CR3T", true)
    H.match(clean("[alias]\n\thelper = status\n"), "helper = status", true)
    H.match(clean('[remote "o"]\n\thelper = x\n'), "helper = x", true)
    H.match(clean("[credential]\n\tusername = bob\n"), "username = bob", true)
  end)

  it("a section header is judged on its own line, in any case, and its URL credentials go too", function()
    local out = clean('[URL "https://u:S3CR3T@h/"]\n\tinsteadOf = x\n')
    H.no_match(out, "S3CR3T", true)
    H.match(out, "insteadOf = x", true)
    H.no_match(clean("[HTTP]\n\tEXTRAHEADER = a: S3CR3T\n"), "S3CR3T", true)
    H.no_match(clean('[Http "https://h/"]\n\textraheader = a: S3CR3T\n'), "S3CR3T", true)
  end)

  it("a continued value is dropped to its end and no further", function()
    local out =
      clean("[http]\n\textraHeader = a \\\n\t  b-S3CR3T \\\n\t  c-S3CR3T\n\tproxy = http://p\n[core]\n\teditor = vi\n")
    H.no_match(out, "S3CR3T", true)
    H.match(out, "proxy = http://p", true)
    H.match(out, "editor = vi", true)
    -- a dropped value without a continuation does not swallow the next line
    local out2 = clean('[remote "o"]\n\ttoken = S3CR3T\n\turl = https://h/x\n\tfetch = +refs/*:refs/*\n')
    H.match(out2, "url = https://h/x", true)
    H.match(out2, "fetch = +refs/*:refs/*", true)
    -- a kept value with a trailing backslash keeps its continuation line
    local out3 = clean("[alias]\n\tx = log \\\n\t  --oneline\n")
    H.match(out3, "--oneline", true)
  end)

  it("reports what it removed without ever naming the secret", function()
    local _, changes = sanitize.git_config('[remote "o"]\n\ttoken = S3CR3T\n\turl = https://u:S3CR3T@h/x\n')
    H.ok(#changes >= 2, vim.inspect(changes))
    H.no_match(table.concat(changes, "\n"), "S3CR3T", true)
  end)
end)

-- ----------------------------------------------------------------- scan: URL credentials, key names

describe("credentials in a URL", function()
  local function found(url)
    return vim.tbl_contains(scan.text(url), "credentials in a URL")
  end
  it("a real-looking password is found, in many shapes", function()
    for _, u in ipairs({
      "https://bob:Zq7xK9mPqL2@h.example.org/x",
      "postgres://app:Zq7xK9mPqL2@db:5432/x",
      "KEY='ftp://u:Zq7xK9mPqL2@h'",
      "git+ssh://git:Zq7xK9mPqL2@h/x.git",
      "amqp://u:abcdEFGH1234@broker",
    }) do
      H.ok(found(u), u)
    end
  end)
  it("a password that spells out that it is a placeholder is not", function()
    for _, w in ipairs({ "password", "passw0rd", "changeme", "secret", "example", "xxxxxxxx", "********", "redacted" }) do
      H.not_ok(found("https://bob:my" .. w .. "99@h/x"), w .. " inside the password")
      H.not_ok(found("https://bob:" .. w:upper() .. "1234@h/x"), w:upper())
    end
  end)
  it("a password of 7 characters or fewer is not judged; 8 is", function()
    H.not_ok(found("https://bob:Zq7xK9m@h/x"))
    H.ok(found("https://bob:Zq7xK9mP@h/x"))
  end)
  it("template and shell shapes are not secrets: each of $ { } < > % alone", function()
    for _, ch in ipairs({ "$", "{", "}", "<", ">", "%" }) do
      H.not_ok(found("https://bob:Zq7xK9" .. ch .. "mPqL@h/x"), ch)
    end
    H.not_ok(found("https://bob:${DB_PASSWORD}@h/x"))
    H.not_ok(found("https://bob:<password>@h/x"))
  end)
  it("a URL without a password, or with the user only, is not", function()
    H.not_ok(found("https://h/x"))
    H.not_ok(found("https://bob@h/x"))
    H.not_ok(found("see https://example.com:8080/path"))
  end)
end)

describe("private key file names", function()
  local g, e = plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT
  it("a key file is secret by name with any suffix, the public key never", function()
    for _, base in ipairs({ "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519" }) do
      for _, suffix in ipairs({ "", ".bak", "_work", "_sk", "2", ".old", "~", "-backup" }) do
        H.ok(plan.is_secret_name(base .. suffix, g, e), base .. suffix)
      end
      H.not_ok(plan.is_secret_name(base .. ".pub", g, e), base .. ".pub")
      H.not_ok(plan.is_secret_name(base .. "_work.pub", g, e), base .. "_work.pub")
    end
  end)
  it("a name that only resembles one is not", function()
    for _, n in ipairs({ "my_id_rsa_notes", "valid_rsa", "id_rsa_parser.rs", "identity.rs" }) do
      H.not_ok(plan.is_secret_name(n, g, e) and n:match("^id_") == nil, n)
    end
  end)
end)

-- ----------------------------------------------------------------- hard-link aliases

describe("hard links of a hidden file inside the project", function()
  it("every other name is hidden, each with the reason, and the plan counts them", function()
    local entries = {
      [PROJECT .. "/.env"] = "file",
      [PROJECT .. "/a.txt"] = "file",
      [PROJECT .. "/sub"] = "directory",
      [PROJECT .. "/sub/b.txt"] = "file",
      [PROJECT .. "/other.txt"] = "file",
    }
    local info = { [PROJECT .. "/.env"] = { nlink = 4, dev = 7, ino = 11 } }
    local probes = fakefs(
      vim.tbl_extend("force", {
        [HOME] = "directory",
        [HOME .. "/.claude"] = "directory",
        [PROJECT] = "directory",
        [TMP] = "directory",
        [PROJECT .. "/.git"] = "directory",
      }, entries),
      nil,
      info
    )
    probes.scan_project = function()
      return {
        hits = {},
        files = 4,
        multi = {
          { path = PROJECT .. "/.env", dev = 7, ino = 11, nlink = 4 },
          { path = PROJECT .. "/a.txt", dev = 7, ino = 11, nlink = 4 },
          { path = PROJECT .. "/sub/b.txt", dev = 7, ino = 11, nlink = 4 },
          { path = PROJECT .. "/other.txt", dev = 7, ino = 12, nlink = 2 },
        },
      }
    end
    local p = plan.build({
      project = PROJECT,
      tmp_dir = TMP,
      cwd = PROJECT,
      home = HOME,
      uid = 1000,
      probes = probes,
      env = { PATH = "/usr/bin" },
      cmd = { "agent" },
      aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
      config = { network = "open", home = "denylist" },
    })
    local why = {}
    for _, h in ipairs(p.hidden) do
      why[h.path] = h.why
    end
    H.match(why[PROJECT .. "/a.txt"], "hard link of the hidden " .. PROJECT .. "/.env", true)
    H.match(why[PROJECT .. "/sub/b.txt"], "hard link of the hidden " .. PROJECT .. "/.env", true)
    H.eq(nil, why[PROJECT .. "/other.txt"], "another inode")
    local rec
    for _, l in ipairs(p.hardlinks) do
      rec = rec or (l.path == PROJECT .. "/.env" and l)
    end
    H.eq(4, rec.links)
    H.eq(2, rec.masked)
    H.eq(1, rec.unaccounted, "one name is outside the project")
    H.match(table.concat(p.notes, "\n"), "1 more hard link outside the project", true)
  end)
end)

-- ----------------------------------------------------------------- the relay

describe("the relay's lifetime and address", function()
  local RELAY = H.repo .. "/lua/xyno_sandbox/relay.lua"
  local function start()
    local dir = H.tmpdir()
    vim.fn.mkdir(dir .. "/net", "p")
    vim.fn.writefile({}, dir .. "/net/proxy.sock")
    local port = 20000 + (uv.hrtime() % 20000)
    local ready = dir .. "/ready"
    local script = ('"%s" -u NONE -i NONE --headless -l "%s" "%s" %d "%s" </dev/null >/dev/null 2>&1 & wait'):format(
      vim.v.progpath,
      RELAY,
      dir .. "/net/proxy.sock",
      port,
      ready
    )
    local sh = vim.system({ "sh", "-c", script, "xyno-r4-parent" })
    H.ok(
      vim.wait(10000, function()
        return uv.fs_stat(ready) ~= nil
      end, 50),
      "the relay did not come up"
    )
    return { sh = sh, marker = dir .. "/net/proxy.sock", port = port }
  end
  local function relay_pid(r)
    local ps = vim.tbl_filter(function(p)
      return not p[2]:match("^sh ")
    end, H.procs(r.marker))
    H.eq(1, #ps)
    return ps[1][1]
  end

  for _, sig in ipairs({ { "SIGHUP", 1 }, { "SIGTERM", 15 }, { "SIGINT", 2 } }) do
    it("exits on " .. sig[1], function()
      local r = start()
      uv.kill(relay_pid(r), sig[2])
      H.eq({}, H.wait_gone(r.marker, 4000), "the relay ignored " .. sig[1])
      r.sh:kill(9)
    end)
  end

  it("listens on 127.0.0.1 and on nothing else (checked per address family)", function()
    local r = start()
    local hexport = ("%04X"):format(r.port)
    local seen = {}
    for _, file in ipairs({ "/proc/net/tcp", "/proc/net/tcp6" }) do
      local f = io.open(file)
      if f then
        for line in f:lines() do
          local addr, port, st = line:match("^%s*%d+:%s+(%x+):(%x+)%s+%x+:%x+%s+(%x+)")
          if port == hexport and st == "0A" then
            seen[#seen + 1] = file:match("tcp6") and ("v6:" .. addr) or addr
          end
        end
        f:close()
      end
    end
    H.wait_gone(r.marker, 100)
    r.sh:kill(9)
    for _, ps in ipairs(H.procs(r.marker)) do
      uv.kill(ps[1], 9)
    end
    H.eq({ "0100007F" }, seen)
  end)

  it(
    "a connection from another address is not possible: the relay refuses the non-loopback address of this host",
    function()
      -- (the machine's other addresses cannot be assumed; 127.0.0.2 is also loopback but not the bound address)
      local r = start()
      local connected
      local c = uv.new_tcp()
      c:connect("127.0.0.2", r.port, function(err)
        connected = err == nil
        c:close()
      end)
      vim.wait(2000, function()
        return connected ~= nil
      end, 20)
      H.wait_gone(r.marker, 100)
      r.sh:kill(9)
      for _, ps in ipairs(H.procs(r.marker)) do
        uv.kill(ps[1], 9)
      end
      H.eq(false, connected, "bound to 0.0.0.0 it would accept 127.0.0.2")
    end
  )
end)

-- ----------------------------------------------------------------- release

describe("release", function()
  it("a second call touches nothing: not the proxy, not a path that was recreated meanwhile", function()
    H.need_sandbox()
    sb.config.network = "filtered"
    local project, tmp = H.tmpdir(), H.tmpdir()
    vim.fn.writefile({ "SECRET=1" }, project .. "/.env")
    local cmd, err, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd, err)
    local closes = 0
    local close = h.proxy.close
    h.proxy.close = function(...)
      closes = closes + 1
      return close(...)
    end
    local victim = h.temp[1]
    H.ok(victim, "a private file of the launch")
    h.release()
    H.eq(nil, uv.fs_lstat(victim))
    -- the path is recreated (a later launch of the same Neovim, a bystander): a second release must not remove it
    vim.fn.writefile({ "bystander" }, victim)
    h.release()
    h.release()
    H.eq(1, closes)
    H.ok(uv.fs_stat(victim), "a second release deleted a file it no longer owns")
    uv.fs_unlink(victim)
    H.eq(0, sb.running())
  end)
end)
