-- Fifth hardening round: what the third verification found.
--   F1/F2 the login file: a project hard link of it, and writable in home = "denylist"
--   F3    credential files the hidden list missed
--   F4/F5 files that run outside the sandbox, planted in subdirectories and in editor directories of the root
--   F6    the content scan on one very long line
--   F7    token boundaries and formats
--   S     the survivors of the independent mutation run
-- Plan specs use a fake filesystem; the behavioural ones run real commands in a real sandbox on the suite's
-- private $HOME. The mutation table in CHANGELOG.md names the edit that makes each fail.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local scan = require("xyno_sandbox.scan")
local store = require("xyno_sandbox.store")
local ui = require("xyno_sandbox.ui")
local net = require("xyno_sandbox.net")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
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
local function read(path)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local t = f:read("a")
  f:close()
  return t
end

local PROJECT, TMP, FHOME = "/h/proj", "/h/scratch", "/h"

local function fakefs(entries, info)
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
      return entries[x] and x or nil
    end,
    stat_info = function(x)
      return (info or {})[x]
    end,
  }
end

local function build(extra, over, info, scan_result, realmap)
  local entries = vim.tbl_extend("force", {
    [FHOME] = "directory",
    [FHOME .. "/.claude"] = "directory",
    [PROJECT] = "directory",
    [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  local probes = fakefs(entries, info)
  if realmap then
    probes.realpath = function(x)
      return realmap[x] or (entries[x] and x or nil)
    end
  end
  if scan_result then
    probes.scan_project = function()
      return scan_result
    end
  end
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT,
    tmp_dir = TMP,
    cwd = PROJECT,
    home = FHOME,
    uid = 1000,
    probes = probes,
    env = { PATH = "/usr/bin" },
    cmd = { "agent" },
    aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
    config = { network = "open" },
  }, over or {}))
end

local function hidden_map(p)
  local out = {}
  for _, h in ipairs(p.hidden) do
    out[h.path] = h
  end
  return out
end
local function readonly_map(p)
  local out = {}
  for _, r in ipairs(p.readonly) do
    out[r.path] = r
  end
  return out
end

-- ------------------------------------------------------- F1, F2: the login file

describe("the login file ~/.claude/.credentials.json", function()
  local CRED = FHOME .. "/.claude/.credentials.json"

  for _, mode in ipairs({ "allowlist", "denylist" }) do
    it("a project hard link of it is hidden (" .. mode .. ")", function()
      local extra = { [CRED] = "file", [PROJECT .. "/hl_claude"] = "file" }
      local info = { [CRED] = { nlink = 2, dev = 7, ino = 41 } }
      local scanned =
        { hits = {}, files = 1, multi = { { path = PROJECT .. "/hl_claude", dev = 7, ino = 41, nlink = 2 } } }
      local p = build(extra, { config = { network = "open", home = mode } }, info, scanned)
      local h = hidden_map(p)[PROJECT .. "/hl_claude"]
      H.ok(h, "the writable second name of the login stays writable otherwise")
      H.match(h.why, "hard link of " .. CRED, true)
      local entry
      for _, l in ipairs(p.hardlinks) do
        entry = entry or (l.alias == PROJECT .. "/hl_claude" and l)
      end
      H.ok(entry and entry.code, "listed in the preview data")
    end)
  end

  it("is read-only also in home = denylist (the allowlist view binds it read-only already)", function()
    local extra = { [CRED] = "file" }
    local d = build(extra, { config = { network = "open", home = "denylist" } })
    H.ok(readonly_map(d)[CRED], "denylist: locked read-only")
    local a = build(extra, { config = { network = "open", home = "allowlist" } })
    H.eq(CRED, a.claude.credentials)
  end)

  it("a writable approval for it is refused (it is a file the agent must not rewrite)", function()
    local ok = plan.validate_exception({ kind = "writable", value = FHOME .. "/.claude/.credentials.json" }, {
      home = FHOME,
      probes = {
        exists = function()
          return true
        end,
        realpath = function(x)
          return x
        end,
      },
    })
    H.not_ok(ok)
  end)

  it("really cannot be changed through a project hard link or directly, in either home mode", function()
    H.need_sandbox()
    for _, mode in ipairs({ "allowlist", "denylist" }) do
      sb.config.home, sb.config.network = mode, "open"
      local home = uv.os_homedir()
      local cred = home .. "/.claude/.credentials.json"
      local before = read(cred)
      H.ok(before, "the runner's fake login exists")
      local project = home .. "/login-link-" .. mode
      write(project .. "/Cargo.toml", "[package]\n")
      H.ok(uv.fs_link(cred, project .. "/hl_claude"))
      local cmd, err, h = sb.wrap(
        { "sh", "-c", 'echo PWNED >> hl_claude; echo PWNED >> "$HOME/.claude/.credentials.json"; echo done' },
        project,
        H.tmpdir()
      )
      H.ok(cmd, err)
      local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
      h.release()
      local out = (r.stdout or "") .. (r.stderr or "")
      uv.fs_unlink(project .. "/hl_claude")
      vim.fn.delete(project, "rf")
      H.match(out, "done", true, out)
      H.eq(before, read(cred), mode .. ": the host login file is unchanged")
    end
  end)
end)

-- ------------------------------------------------------- F3: more credentials

describe("credential files the hidden list missed (home = denylist)", function()
  local files = {
    "/.config/sops/age/keys.txt",
    "/.gem/credentials",
    "/.config/pypoetry/auth.toml",
    "/.pip/pip.conf",
    "/.config/pip/pip.conf",
    "/.npm/_logs",
  }
  it("each is hidden", function()
    for _, rel in ipairs(files) do
      local extra = { [FHOME .. rel] = rel == "/.npm/_logs" and "directory" or "file" }
      local acc = FHOME
      for seg in vim.fs.dirname(rel):gmatch("[^/]+") do
        acc = acc .. "/" .. seg
        extra[acc] = "directory"
      end
      local p = build(extra, { config = { network = "open", home = "denylist" } })
      local shown = rel:find("^/.config/sops") and "/.config/sops" or rel -- (the whole directory of the age keys)
      H.ok(hidden_map(p)[FHOME .. shown], rel .. " is hidden")
    end
  end)

  it("really are unreadable in a sandbox", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "denylist", "open"
    local home = uv.os_homedir()
    local made = {}
    for _, rel in ipairs(files) do
      if rel == "/.npm/_logs" then
        write(home .. rel .. "/2026-01-01-debug.log", "CANARY-npm-log\n")
      else
        write(home .. rel, "CANARY-" .. rel .. "\n")
      end
      made[#made + 1] = rel
    end
    local project = home .. "/creds-r5"
    write(project .. "/Cargo.toml", "[package]\n")
    local script = {}
    for _, rel in ipairs(files) do
      script[#script + 1] = ('cat "$HOME%s" "$HOME%s"/* 2>/dev/null'):format(rel, rel)
    end
    local cmd, err, h = sb.wrap({ "sh", "-c", table.concat(script, "; ") .. "; echo done" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    for _, rel in ipairs(made) do
      vim.fn.delete(home .. rel, "rf")
    end
    vim.fn.delete(home .. "/.config/sops", "rf")
    vim.fn.delete(project, "rf")
    H.match(r.stdout, "done", true)
    H.no_match(r.stdout, "CANARY", true, r.stdout)
  end)
end)

-- ------------------------------------------------- F5: editor directories of the project root

describe("files of the project root that act outside the sandbox: editors, hooks, debuggers", function()
  local dirs = { ".zed", ".idea", ".helix", ".husky", ".devcontainer" }
  local files = { ".pre-commit-config.yaml", ".lldbinit", ".gdbinit" }

  it("the ones that exist are read-only", function()
    local extra = {}
    for _, d in ipairs(dirs) do
      extra[PROJECT .. "/" .. d] = "directory"
    end
    for _, f in ipairs(files) do
      extra[PROJECT .. "/" .. f] = "file"
    end
    local ro = readonly_map(build(extra))
    for _, n in ipairs(vim.list_extend(vim.deepcopy(dirs), files)) do
      H.ok(ro[PROJECT .. "/" .. n], n .. " is locked")
    end
  end)

  it(
    "the ones that are absent cannot be created (directories masked, files bound to an empty read-only file)",
    function()
      local p = build()
      local masks, guards = {}, {}
      for _, m in ipairs(p.masks) do
        masks[m.path] = true
      end
      for _, g in ipairs(p.guard_files) do
        guards[g.path] = true
      end
      for _, d in ipairs(dirs) do
        H.ok(masks[PROJECT .. "/" .. d], d .. " masked while absent")
      end
      for _, f in ipairs(files) do
        H.ok(guards[PROJECT .. "/" .. f], f .. " guarded while absent")
      end
    end
  )

  it("really cannot be created, replaced or renamed in a sandbox, and no placeholder is left behind", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "allowlist", "open"
    local home = uv.os_homedir()
    local project = home .. "/editors-r5"
    write(project .. "/Cargo.toml", "[package]\n")
    write(project .. "/.idea/workspace.xml", "<x/>\n")
    write(project .. "/.husky/pre-commit", "echo ok\n")
    local script = table.concat({
      "mkdir -p .zed && echo '{\"tasks\":1}' > .zed/tasks.json",
      "mkdir -p .helix && echo x > .helix/languages.toml",
      "mkdir -p .devcontainer && echo x > .devcontainer/devcontainer.json",
      "echo x > .pre-commit-config.yaml",
      "echo x > .lldbinit",
      "echo x > .gdbinit",
      "echo PWNED >> .idea/workspace.xml",
      "echo PWNED >> .husky/pre-commit",
      "mv .idea .idea-old",
      "mv .husky h2",
      "echo done",
    }, "; ")
    local cmd, err, h = sb.wrap({ "sh", "-c", script }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    H.match(r.stdout, "done", true, (r.stdout or "") .. (r.stderr or ""))
    local seen = {}
    for _, n in ipairs({
      ".zed",
      ".helix",
      ".devcontainer",
      ".pre-commit-config.yaml",
      ".lldbinit",
      ".gdbinit",
      ".idea-old",
      "h2",
    }) do
      seen[n] = uv.fs_lstat(project .. "/" .. n) ~= nil
    end
    local idea, husky = read(project .. "/.idea/workspace.xml"), read(project .. "/.husky/pre-commit")
    vim.fn.delete(project, "rf")
    for n, exists in pairs(seen) do
      H.not_ok(exists, n .. " must not exist on the host after the run")
    end
    H.eq("<x/>\n", idea)
    H.eq("echo ok\n", husky)
  end)
end)

-- --------------------------------------------- F4: subdirectories of the project

describe("files that act outside the sandbox, in subdirectories of the project", function()
  it("the ones that exist are read-only in every subdirectory the walk found", function()
    local extra = {}
    for _, d in ipairs({ "sub", "crates", "crates/a" }) do
      extra[PROJECT .. "/" .. d] = "directory"
    end
    local names = {
      ".cargo",
      ".claude",
      ".vscode",
      ".zed",
      ".idea",
      ".helix",
      ".husky",
      ".devcontainer",
    }
    local fnames =
      { ".envrc", ".mise.toml", ".nvim.lua", ".exrc", ".mcp.json", ".pre-commit-config.yaml", ".lldbinit", ".gdbinit" }
    for _, d in ipairs({ "sub", "crates/a" }) do
      for _, n in ipairs(names) do
        extra[PROJECT .. "/" .. d .. "/" .. n] = "directory"
      end
      for _, n in ipairs(fnames) do
        extra[PROJECT .. "/" .. d .. "/" .. n] = "file"
      end
    end
    local ro = readonly_map(build(extra))
    for _, d in ipairs({ "sub", "crates/a" }) do
      for _, n in ipairs(vim.list_extend(vim.deepcopy(names), fnames)) do
        H.ok(ro[PROJECT .. "/" .. d .. "/" .. n], d .. "/" .. n .. " locked")
      end
    end
  end)

  it("the plan says what is not prevented, and which directories are compared at the end", function()
    local p = build({ [PROJECT .. "/sub"] = "directory" })
    H.eq({ PROJECT .. "/sub" }, p.watch.dirs)
    H.ok(#p.watch.names >= 10)
    H.has(p.watch.names, ".git")
    H.has(p.watch.names, ".cargo")
    H.match(table.concat(p.notes, "\n"), "CREATES in a subdirectory", true)
    H.match(table.concat(ui.lines(p, { home = FHOME }), "\n"), "CREATES in a subdirectory", true)
    H.no_match(
      table.concat(build().notes, "\n"),
      "CREATES in a subdirectory",
      true,
      "a project without subdirectories has nothing to say"
    )
  end)

  it("the number of compared directories is bounded", function()
    local extra = {}
    for i = 1, plan.WATCH_DIRS_MAX + 30 do
      extra[PROJECT .. "/d" .. i] = "directory"
    end
    H.eq(plan.WATCH_DIRS_MAX, #build(extra).watch.dirs)
  end)

  it(
    "a file the agent plants beyond the masked directories is quarantined when the run ends; what was there before is not",
    function()
      H.need_sandbox()
      sb.config.home, sb.config.network = "allowlist", "open"
      local home = uv.os_homedir()
      local project = home .. "/planted-r5"
      write(project .. "/Cargo.toml", "[package]\n")
      write(project .. "/old/.envrc", "# mine\n")
      -- enough shallow directories to use the whole mask budget, so "deep" is NOT prevented
      for i = 1, 60 do
        vim.fn.mkdir(project .. ("/a%02d"):format(i), "p")
      end
      vim.fn.mkdir(project .. "/zz/er/est", "p")
      local script = table.concat({
        "mkdir -p zz/er/est/.cargo && echo '[build]' > zz/er/est/.cargo/config.toml",
        "mkdir -p zz/er/est/.claude && echo '{}' > zz/er/est/.claude/settings.json",
        "echo x > zz/er/est/.mcp.json",
        "mkdir -p zz/er/est/.vscode && echo '{}' > zz/er/est/.vscode/tasks.json",
        "echo x > zz/er/est/.envrc",
        "echo x > zz/er/est/rust-toolchain.toml",
        "echo PWNED >> old/.envrc",
        "echo done",
      }, "; ")
      local cmd, err, h = sb.wrap({ "sh", "-c", script }, project, H.tmpdir())
      H.ok(cmd, err)
      local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
      local msgs = H.capture_notify(function()
        h.release()
      end)
      H.match(r.stdout, "done", true, (r.stdout or "") .. (r.stderr or ""))
      local planted = vim.deepcopy(h.planted)
      local old = read(project .. "/old/.envrc")
      local still = {}
      for _, n in ipairs({ ".cargo", ".claude", ".mcp.json", ".vscode", ".envrc", "rust-toolchain.toml" }) do
        still[n] = uv.fs_lstat(project .. "/zz/er/est/" .. n) ~= nil
      end
      local dirty = sb.dirty(project)
      local q = h.quarantine and read(h.quarantine .. "/zz/er/est/.cargo/config.toml")
      vim.fn.delete(project, "rf")
      H.eq("# mine\n", old, "an existing .envrc of a subdirectory is read-only")
      local set = {}
      for _, x in ipairs(planted) do
        set[x:sub(#project + 2)] = true
      end
      for _, n in ipairs({ ".cargo", ".claude", ".mcp.json", ".vscode", ".envrc", "rust-toolchain.toml" }) do
        H.ok(set["zz/er/est/" .. n], n .. " is reported: " .. vim.inspect(planted))
        H.not_ok(still[n], n .. " is removed from the project")
      end
      H.eq("[build]\n", q, "a copy is kept in the quarantine")
      H.ok(dirty, "the project is marked for review")
      sb.clear_dirty(project)
      H.eq(1, #vim.tbl_filter(function(m)
        return m[2] == vim.log.levels.ERROR
      end, msgs), "one loud error")
      H.match(msgs[1][1], "created 6 files that act outside the sandbox", true)
    end
  )

  it("a run that plants nothing reports nothing", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "allowlist", "open"
    local home = uv.os_homedir()
    local project = home .. "/quiet-r5"
    write(project .. "/Cargo.toml", "[package]\n")
    write(project .. "/sub/.envrc", "# mine\n")
    local cmd, err, h = sb.wrap({ "sh", "-c", "echo hi > sub/file.txt; echo done" }, project, H.tmpdir())
    H.ok(cmd, err)
    vim.system(cmd, { text = true, cwd = project }):wait(60000)
    local msgs = H.capture_notify(function()
      h.release()
    end)
    vim.fn.delete(project, "rf")
    H.eq({}, h.planted)
    H.eq(0, #msgs)
  end)
end)

-- ------------------------------------------------------------- F6: the scan on long lines

describe("the content scan on lines that are very long", function()
  local N = 256 * 1024
  local shapes = {
    letters = ("a"):rep(N),
    hex = ("deadbeef"):rep(N / 8),
    base64 = ("QUJD"):rep(N / 4),
    dashes = ("-"):rep(N),
    begins = ("-----BEGIN "):rep(math.floor(N / 11)),
    sk = ("sk-a"):rep(N / 4),
    urls = ("a://"):rep(N / 4),
    userinfo = ("a://:"):rep(N / 5),
    akia = ("AKIA"):rep(N / 4),
    ghp = ("ghp_a"):rep(N / 5),
    minified = ("function(a,b){return a+b}"):rep(N / 25),
    spaces = ("A "):rep(N / 2),
  }
  for name, text in pairs(shapes) do
    it(name .. ": " .. #text .. " bytes on one line take well under a second", function()
      local t0 = uv.hrtime()
      scan.text(text)
      local ms = (uv.hrtime() - t0) / 1e6
      H.ok(ms < 1000, ("%s took %d ms"):format(name, ms))
    end)
  end

  it("a project with one 256 KB line of letters is scanned in time and not reported as cut short", function()
    local project = H.tmpdir()
    write(project .. "/minified.js", ("a"):rep(256 * 1024))
    local t0 = uv.hrtime()
    local res = scan.project(project, {})
    local ms = (uv.hrtime() - t0) / 1e6
    H.ok(ms < 1500, ms .. " ms")
    H.eq(false, res.truncated)
    H.eq(1, res.files)
  end)

  it("the time budget is checked INSIDE a file: a deadline in the past stops text() between lines", function()
    local kinds, timed_out = scan.text("a\nb\nc\n", uv.hrtime() - 1)
    H.eq({}, kinds)
    H.eq(true, timed_out)
    local _, ok = scan.text("a\nb\nc\n", uv.hrtime() + 1e10)
    H.eq(false, ok)
  end)

  it("project() reports 'truncated' when its time ran out INSIDE a file (not only between files)", function()
    local project = H.tmpdir()
    local lines = {}
    for i = 1, 20000 do
      lines[i] = "line number " .. i .. " of a long but harmless file"
    end
    write(project .. "/big.txt", table.concat(lines, "\n"):sub(1, 250 * 1024))
    local saved_ms = scan.MAX_MS
    scan.MAX_MS = 3 -- (the walk and the stat of the one file take far less; the lines of the file take far more)
    local res = scan.project(project, {})
    scan.MAX_MS = saved_ms
    H.eq(true, res.truncated)
    H.match(res.why, "3 ms", true)
    H.eq(0, #res.hits)
  end)

  it("the URL pattern still finds credentials in a URL, in every position of a line", function()
    local url = "postgres://admin:Tr0ub4dor9xz@db.internal"
    for _, fmt in ipairs({
      "%s",
      "DATABASE_URL=%s",
      'u = "%s"',
      "x" .. ("a"):rep(50) .. " %s",
      "1abc+def.ghi-jkl://x/ %s",
      "see (%s) now",
      "%s %s",
    }) do
      H.has(scan.text(fmt:format(url, url)), "credentials in a URL", fmt)
    end
    H.eq({}, scan.text("https://example.com/path?x=1"))
    H.eq({}, scan.text("https://user:short@host.com"))
    H.eq({}, scan.text("a" .. ("b"):rep(100) .. "://x:y@z"))
  end)
end)

-- --------------------------------------------------------------- F7: boundaries, formats

describe("token formats and boundaries (round 5)", function()
  local function kinds(s)
    return (scan.text(s))
  end

  it("a private key header in any case, with tabs or several spaces, is found", function()
    for _, h in ipairs({
      "-----begin rsa private key-----",
      "-----Begin Private Key-----",
      "-----BEGIN\tRSA\tPRIVATE\tKEY-----",
      "-----BEGIN  RSA   PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    }) do
      H.has(kinds("x=" .. h .. "MIIE"), "private key", h)
      H.has(kinds(h), "private key", h)
    end
    H.eq({}, kinds("-----BEGIN PUBLIC KEY-----"))
    H.eq({}, kinds("-----BEGIN CERTIFICATE-----"))
    H.eq({}, kinds("-----begin public key-----"))
  end)

  it("tokens of 41 or more characters, and tokens glued to the end of a word, are found", function()
    local gh = "ghp_" .. ("Zq7x"):rep(9)
    H.has(kinds(gh), "GitHub token")
    H.has(kinds(gh .. "Q"), "GitHub token", "41 characters")
    H.has(kinds(gh .. "QQQQQQQQQQ"), "GitHub token", "longer")
    H.has(kinds("tokenghp_" .. ("Zq7x"):rep(9)), "GitHub token", "glued to an identifier")
    H.has(kinds("1" .. gh), "GitHub token", "digit before")
    H.has(kinds("idAKIAJ5Q7R2M9TXLB4NWC"), "AWS access key id", "lower-case before an AWS key id")
    H.has(kinds("_AKIAJ5Q7R2M9TXLB4NWC"), "AWS access key id", "underscore before")
    H.eq({}, kinds("MALASIAJ5Q7R2M9TXLB4NWC"), "an upper-case word is not an AWS key id")
    H.eq({}, kinds("ghp_" .. ("Zq7x"):rep(7)), "a shorter one is not a token")
    H.has(kinds("glpat" .. "-aB3dE5fG7hI9jK1lM3nO"), "GitLab token", "26 characters")
    H.has(kinds("glpat" .. "-aB3dE5fG7hI9jK1lM3nOpQ"), "GitLab token", "longer than 26")
    H.eq({}, kinds("glpat" .. "-aB3dE5fG7hI9jK1lM3n"), "25 characters")
  end)

  it("the formats added in round 5 are found, and a near miss is not", function()
    local cases = {
      { "Hugging Face token", "hf_" .. ("aBcDeFgHiJ"):rep(3) .. "abcd" },
      { "DigitalOcean token", "dop_v1_" .. ("0123456789abcdef"):rep(4) },
      { "Shopify token", "shpat_" .. ("0123456789abcdef"):rep(2) },
      { "Slack app token", "xapp-1-A0123456789-0123456789012-" .. ("ab12"):rep(8) },
      { "Stripe test key", "sk_test_" .. ("4eC39HqLyjWD"):rep(2) .. "arjtT1zd" },
      { "OpenAI key", "sk-" .. ("aB3dE5fG7h"):rep(4) .. "aB3dE5fG" },
    }
    for _, c in ipairs(cases) do
      H.has(kinds(c[2]), c[1], c[2])
      H.has(kinds("KEY=" .. c[2]), c[1], "assigned")
      H.eq({}, kinds(c[2]:sub(1, 12)), "a short prefix is not a token: " .. c[2]:sub(1, 12))
    end
    H.eq({}, kinds("sk-" .. ("a"):rep(20)), "a short sk- string")
    H.eq({}, kinds("dop_v1_" .. ("0123456789abcdef"):rep(4) .. "0"), "a DigitalOcean token has exactly 64 characters")
  end)

  it("wrappers: quotes, =, :, JSON, YAML, base64 wrappers and CRLF all keep a key header findable", function()
    local hdr = "-----BEGIN RSA PRIVATE KEY-----"
    for _, fmt in ipairs({
      "key=%sMIIE",
      'key="%s"',
      "key:%s",
      '{"k":"%s\\nMIIE"}',
      "k: |\n  %s\n  MIIE",
      "%s\r\nMIIE\r\n",
      "'%s'",
      "<k>%s</k>",
      "[%s]",
      "(%s)",
      "a,%s,b",
      "export K=%s",
      "# %s",
    }) do
      H.has(kinds(fmt:format(hdr)), "private key", fmt)
    end
    for _, k in ipairs({ 0, 1, 2 }) do
      local enc = vim.base64.encode(("y"):rep(k) .. hdr .. "\nMIIE\n")
      for _, fmt in ipairs({ "%s", 'k="%s"', "k: %s", '{"k":"%s"}', "k=%s\r" }) do
        H.has(kinds(fmt:format(enc)), "private key (base64)", fmt .. " at " .. k)
      end
    end
  end)
end)

-- ------------------------------------------------------------- S: the survivors

describe("the readiness probe runs the isolation the agent really gets", function()
  it("probe_argv carries every isolation flag, the read-only root and the net switch", function()
    for _, net_on in ipairs({ false, true }) do
      local a = plan.probe_argv(net_on)
      local text = "\0" .. table.concat(a, "\0") .. "\0"
      for _, f in ipairs(plan.ISOLATION_FLAGS) do
        H.ok(text:find("\0" .. f .. "\0", 1, true), "probe lacks " .. f)
      end
      H.ok(text:find("\0--ro-bind\0/\0/\0", 1, true), "the probe's root is bound read-only")
      H.not_ok(text:find("\0--bind\0/\0/\0", 1, true), "never a writable root")
      H.eq(net_on, text:find("\0--unshare-net\0", 1, true) ~= nil)
    end
  end)

  it("the real command line contains every flag of the probe (the same isolation)", function()
    local p = build()
    local argv = plan.argv(p)
    local probe = plan.probe_argv(true)
    local text = "\0" .. table.concat(argv, "\0") .. "\0"
    for _, f in ipairs(plan.ISOLATION_FLAGS) do
      H.ok(text:find("\0" .. f .. "\0", 1, true), "the command lacks " .. f)
    end
    H.eq("bwrap", probe[1])
    H.ok(text:find("\0--ro-bind\0/\0/\0", 1, true))
  end)
end)

describe("sandbox.plan() with a refused status", function()
  it("returns nil and the reason instead of a plan", function()
    local old = vim.env.PATH
    vim.env.PATH = "/nonexistent-xyno-path"
    local p, reason = sb.plan({ "agent" }, vim.uv.cwd(), vim.uv.cwd())
    vim.env.PATH = old
    H.eq(nil, p)
    H.ok(type(reason) == "string" and reason ~= "", "a reason comes with it")
  end)
end)

describe("approvals and options (survivors)", function()
  it("an env approval for ENV needs the expert flag (ENV is sourced by sh)", function()
    local ok, why = plan.validate_exception({ kind = "env", value = "ENV" }, { home = FHOME })
    H.not_ok(ok)
    H.match(why, "decides which code runs", true)
    H.match(
      select(2, plan.validate_exception({ kind = "env", value = "BASH_ENV" }, { home = FHOME })),
      "decides which code runs",
      true
    )
  end)

  it(
    "policy.readonly may name $HOME or a parent (a lock cannot expose anything); writable and hidden may not",
    function()
      local base = { network = "open" }
      local function errs(policy)
        return sb.validate_opts(vim.tbl_extend("force", base, { policy = policy }))
      end
      H.eq({}, errs({ readonly = { "~" } }))
      local e = errs({ writable = { "~" } })
      H.ok(#e > 0, "writable ~ refused")
      e = errs({ hidden = { "~" } })
      H.ok(#e > 0, "hidden ~ refused")
    end
  )

  it("a duplicate policy.guard_files entry gives ONE guard file", function()
    local p = build(
      nil,
      { config = { network = "open", policy = { guard_files = { "extra.rc", "extra.rc", "./extra.rc", ".envrc" } } } }
    )
    local n = 0
    for _, g in ipairs(p.guard_files) do
      if g.path == PROJECT .. "/extra.rc" then
        n = n + 1
      end
    end
    H.eq(1, n)
    local e = 0
    for _, g in ipairs(p.guard_files) do
      if g.path == PROJECT .. "/.envrc" then
        e = e + 1
      end
    end
    H.eq(1, e, "also for a default name listed again")
  end)

  it("a bare agent command that is a symlink out of its $PATH directory shows the real file too (own home)", function()
    local extra = {
      [FHOME .. "/bin"] = "directory",
      [FHOME .. "/bin/agent"] = "file",
      [FHOME .. "/tools"] = "directory",
      [FHOME .. "/tools/agent-real"] = "file",
    }
    local over = {
      env = { PATH = FHOME .. "/bin:/usr/bin" },
      cmd = { "agent" },
      config = { network = "open", home = "allowlist" },
    }
    local p = build(extra, over, nil, nil, { [FHOME .. "/bin/agent"] = FHOME .. "/tools/agent-real" })
    local paths = vim.tbl_map(function(a)
      return a.path
    end, p.home_allow)
    H.has(paths, FHOME .. "/tools/agent-real")
    -- a command with a slash is NOT looked up in $PATH: "rel/agent" finds nothing there
    local q = build(
      extra,
      vim.tbl_extend("force", over, { cmd = { "bin/agent" } }),
      nil,
      nil,
      { [FHOME .. "/bin/agent"] = FHOME .. "/tools/agent-real" }
    )
    local qp = vim.tbl_map(function(a)
      return a.path
    end, q.home_allow)
    H.not_ok(vim.tbl_contains(qp, FHOME .. "/tools/agent-real"), "a relative path is not resolved through PATH")
  end)

  it("the same for a bare agent command in a $PATH directory of ANOTHER user's home", function()
    local extra = {
      ["/home"] = "directory",
      ["/home/alice"] = "directory",
      ["/home/alice/.local"] = "directory",
      ["/home/alice/.local/bin"] = "directory",
      ["/home/alice/.local/bin/agent"] = "file",
      ["/home/alice/.local/share"] = "directory",
      ["/home/alice/.local/share/agent"] = "directory",
      ["/home/alice/.local/share/agent/agent-real"] = "file",
    }
    local p = build(
      extra,
      { env = { PATH = "/home/alice/.local/bin:/usr/bin" }, cmd = { "agent" } },
      nil,
      nil,
      { ["/home/alice/.local/bin/agent"] = "/home/alice/.local/share/agent/agent-real" }
    )
    local shown = vim.tbl_map(function(a)
      return a.path
    end, p.homes.allow)
    H.has(shown, "/home/alice/.local/share/agent/agent-real")
    local q = build(
      extra,
      { env = { PATH = "/home/alice/.local/bin:/usr/bin" }, cmd = { ".local/bin/agent" } },
      nil,
      nil,
      { ["/home/alice/.local/bin/agent"] = "/home/alice/.local/share/agent/agent-real" }
    )
    local qs = vim.tbl_map(function(a)
      return a.path
    end, q.homes.allow)
    H.not_ok(vim.tbl_contains(qs, "/home/alice/.local/share/agent/agent-real"))
  end)

  it("a tree that is not too large gets no 'tree is large' note", function()
    local extra =
      { [FHOME .. "/tools"] = "directory", [FHOME .. "/tools/bin"] = "directory", [FHOME .. "/tools/bin/x"] = "file" }
    local p = build(
      extra,
      { env = { PATH = FHOME .. "/tools/bin:/usr/bin" }, config = { network = "open", home = "allowlist" } }
    )
    H.no_match(table.concat(p.notes, "\n"), "is large", true)
  end)

  it("a hard link of a credential is recorded with its alias, count and mask", function()
    local extra =
      { [FHOME .. "/.aws"] = "directory", [FHOME .. "/.aws/credentials"] = "file", [PROJECT .. "/c"] = "file" }
    local info = { [FHOME .. "/.aws/credentials"] = { nlink = 2, dev = 3, ino = 8 } }
    local scanned = { hits = {}, files = 1, multi = { { path = PROJECT .. "/c", dev = 3, ino = 8, nlink = 2 } } }
    local p = build(extra, nil, info, scanned)
    local rec
    for _, l in ipairs(p.hardlinks) do
      rec = rec or (l.alias == PROJECT .. "/c" and l)
    end
    H.ok(rec, "a record for the alias")
    H.eq(FHOME .. "/.aws/credentials", rec.path)
    H.eq(2, rec.links)
    H.eq(1, rec.masked)
    H.eq(0, rec.unaccounted)
    H.not_ok(rec.code, "a credential, not code")
  end)
end)

describe("secret files that only their path gives away", function()
  it("a base name that is a secret only below a certain directory is hidden there and nowhere else", function()
    local extra = {
      [PROJECT .. "/sub"] = "directory",
      [PROJECT .. "/sub/.docker"] = "directory",
      [PROJECT .. "/sub/.docker/config.json"] = "file",
      [PROJECT .. "/sub/.m2"] = "directory",
      [PROJECT .. "/sub/.m2/Settings.XML"] = "file",
      [PROJECT .. "/sub/other"] = "directory",
      [PROJECT .. "/sub/other/config.json"] = "file",
      [PROJECT .. "/config.json"] = "file",
    }
    local h = hidden_map(build(extra))
    H.ok(h[PROJECT .. "/sub/.docker/config.json"], ".docker/config.json")
    H.ok(h[PROJECT .. "/sub/.m2/Settings.XML"], ".m2/settings.xml, in any case")
    H.eq(nil, h[PROJECT .. "/sub/other/config.json"], "config.json elsewhere is ordinary")
    H.eq(nil, h[PROJECT .. "/config.json"])
  end)

  it("the same inside a toolchain tree shown from $HOME", function()
    local extra = {
      [FHOME .. "/tools"] = "directory",
      [FHOME .. "/tools/bin"] = "directory",
      [FHOME .. "/tools/.docker"] = "directory",
      [FHOME .. "/tools/.docker/config.json"] = "file",
      [FHOME .. "/tools/config.json"] = "file",
    }
    local p = build(
      extra,
      { env = { PATH = FHOME .. "/tools/bin:/usr/bin" }, config = { network = "open", home = "allowlist" } }
    )
    local h = hidden_map(p)
    H.ok(h[FHOME .. "/tools/.docker/config.json"], "hidden in the shown tree")
    H.eq(nil, h[FHOME .. "/tools/config.json"])
  end)
end)

describe("the network address check (survivors)", function()
  it("documentation ranges and octet limits", function()
    H.not_ok(net.is_public_ip("203.0.113.5"))
    H.not_ok(net.is_public_ip("203.0.113.0"))
    H.ok(net.is_public_ip("203.0.114.5"))
    H.ok(net.is_public_ip("203.1.113.5"))
    H.ok(net.is_public_ip("8.8.8.255"), "255 is a valid octet")
    H.not_ok(net.is_public_ip("8.8.8.256"), "256 is not")
    H.not_ok(net.is_public_ip("256.8.8.8"))
    H.ok(net.is_public_ip("8.8.255.8"))
  end)
end)

describe("the state file (survivors)", function()
  it("save() reports an encoding failure and writes nothing", function()
    local ok, err = store.save({ approvals = {}, seen = {}, bad = function() end })
    H.eq(false, ok)
    H.ok(err, "an error text")
    H.eq(nil, uv.fs_stat(store.dir() .. "/state.json.tmp"))
  end)
end)

-- --------------------------------------------------------------- the runner

describe("the runner removes what an earlier, killed run left", function()
  local reaper = dofile(H.repo .. "/tests/reaper.lua")
  local function dir_with(parent, name, owner, age_s)
    local d = parent .. "/" .. name
    vim.fn.mkdir(d, "p")
    if owner then
      write(d .. "/.owner", owner)
    end
    write(d .. "/data", "x")
    if age_s then
      local t = os.time() - age_s
      uv.fs_utime(d, t, t)
    end
    return d
  end
  local function exists(d)
    return uv.fs_lstat(d) ~= nil
  end

  it("reap_stale: a root and a scratch directory of a dead runner go; a live runner's and strangers' stay", function()
    local base = H.tmpdir()
    local live = reaper.owner_tag()
    H.match(live, "^%d+:%d+$")
    local dead_root = dir_with(base, "xyno-sandbox-test-DEAD01", "999999:1")
    local dead_tmp = dir_with(base, "xyno-run-DEAD02", "999999:1")
    local reused = dir_with(base, "xyno-sandbox-test-REUSE1", uv.os_getpid() .. ":1") -- (our pid, another start time)
    local live_root = dir_with(base, "xyno-sandbox-test-LIVE01", live)
    local live_tmp = dir_with(base, "xyno-run-LIVE02", live .. "\n") -- (a trailing newline does not make it dead)
    local garbage = dir_with(base, "xyno-run-GARBAGE", "not an owner tag")
    local stranger = dir_with(base, "my-own-notes", "999999:1")
    local young = dir_with(base, "xyno-sandbox-test-YOUNG1", nil, 3600)
    local old = dir_with(base, "xyno-sandbox-test-OLD001", nil, 3 * 86400)
    local probe_old = dir_with(base, ".probe-OLD001", nil, 3600)
    local probe_new = dir_with(base, ".probe-NEW001", nil, 5)
    local plain_file = base .. "/xyno-run-FILE"
    write(plain_file, "x")
    local n = reaper.reap_stale({ base, base .. "/does-not-exist" })
    H.eq(6, n, "dead_root, dead_tmp, reused, garbage, old, probe_old")
    for name, d in pairs({
      dead_root = dead_root,
      dead_tmp = dead_tmp,
      reused = reused,
      garbage = garbage,
      old = old,
      probe_old = probe_old,
    }) do
      H.not_ok(exists(d), name .. " is removed")
    end
    for name, d in pairs({
      live_root = live_root,
      live_tmp = live_tmp,
      stranger = stranger,
      young = young,
      probe_new = probe_new,
      plain_file = plain_file,
    }) do
      H.ok(exists(d), name .. " stays")
    end
    H.eq(0, reaper.reap_stale({ base }), "a second pass finds nothing")
  end)

  it("a symlink with the runner's name is never followed or removed", function()
    local base = H.tmpdir()
    local target = H.tmpdir()
    write(target .. "/precious", "x")
    uv.fs_symlink(target, base .. "/xyno-run-LINK01")
    H.eq(0, reaper.reap_stale({ base }))
    H.ok(exists(target .. "/precious"))
    H.ok(exists(base .. "/xyno-run-LINK01"))
  end)

  it("the default places searched are /tmp and /var/tmp, then the places the runner makes its roots in", function()
    H.eq({ "/tmp", "/var/tmp" }, reaper.default_bases)
    local saved_env = vim.env.XYNO_TEST_REAP_BASES
    vim.env.XYNO_TEST_REAP_BASES = nil
    local bases = reaper.bases(H.repo)
    vim.env.XYNO_TEST_REAP_BASES = saved_env
    H.has(bases, "/tmp")
    H.has(bases, "/var/tmp")
    local base = H.tmpdir()
    vim.env.XYNO_TEST_REAP_BASES = base .. ":/does/not/exist"
    local only = reaper.bases(H.repo)
    vim.env.XYNO_TEST_REAP_BASES = saved_env
    H.eq({ base }, only, "XYNO_TEST_REAP_BASES replaces the list")
  end)

  it("a run removes the leftovers of an earlier run that was killed (end to end)", function()
    local base = H.tmpdir()
    local dead_root = dir_with(base, "xyno-sandbox-test-DEAD01", "999999:1")
    local dead_tmp = dir_with(base, "xyno-run-DEAD02", "999999:1")
    local live_root = dir_with(base, "xyno-sandbox-test-LIVE01", reaper.owner_tag())
    local dir = H.tmpdir()
    write(dir .. "/inner_spec.lua", 'it("runs", function() end)')
    local r = vim
      .system(
        { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/inner_spec.lua" },
        { text = true, env = { XYNO_TEST_WORKER = "0", XYNO_TEST_BASE = base, XYNO_TEST_REAP_BASES = base } }
      )
      :wait(180000)
    local out = (r.stdout or "") .. (r.stderr or "")
    H.eq(0, r.code, out)
    H.match(out, "removed 2 private root", true, out)
    H.not_ok(exists(dead_root), "dead root")
    H.not_ok(exists(dead_tmp), "dead scratch")
    H.ok(exists(live_root), "live root")
  end)

  it("every root and scratch directory carries the owner file while the run is going", function()
    local base = H.tmpdir()
    local dir = H.tmpdir()
    write(
      dir .. "/inner_spec.lua",
      [[
      it("owner", function()
        local f = io.open(vim.env.XYNO_TEST_ROOT .. "/.owner", "rb")
        local g = io.open(vim.env.XYNO_TEST_SCRATCH .. "/.owner", "rb")
        assert(f and g and f:read("a"):match("^%d+:%d+$") and g:read("a"):match("^%d+:%d+$"), "owner files")
      end)]]
    )
    local r = vim
      .system(
        { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/inner_spec.lua" },
        { text = true, env = { XYNO_TEST_WORKER = "0", XYNO_TEST_BASE = base, XYNO_TEST_REAP_BASES = base } }
      )
      :wait(180000)
    local out = (r.stdout or "") .. (r.stderr or "")
    H.eq(0, r.code, out)
    H.match(out, "passed=1", true, out)
  end)
end)
