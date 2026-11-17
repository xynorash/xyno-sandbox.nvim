-- Fourth hardening round: what the second verification of the third round found.
--   (a) approvals for paths that run code outside the sandbox, generated from a category list
--   (b) hard links of such files inside the project
--   (c) the private-key header and the other token boundaries of the content scan
--   (d) what a kill -9 of Neovim leaves in its temporary directory
--   (f) the runner without a usable $HOME
-- Plan specs use a fake filesystem; the behavioural ones run real commands in a real sandbox on the
-- suite's private $HOME. The mutation table in CHANGELOG.md names the edit that makes each fail.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local scan = require("xyno_sandbox.scan")
local store = require("xyno_sandbox.store")
local ui = require("xyno_sandbox.ui")
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

-- ------------------------------------------------------------------ (a) code that runs outside

local HOME = "/home/spec-user"
local function check(path, extra)
  return plan.validate_exception(
    { kind = "writable", value = path },
    vim.tbl_extend("force", {
      home = HOME,
      probes = {
        exists = function()
          return true
        end,
        realpath = function(x)
          return x
        end,
      },
    }, extra or {})
  )
end

describe("a writable approval for a path that runs code outside the sandbox", function()
  -- the paths the verifier approved successfully before this round
  local reported = {
    "/.config/direnv",
    "/.config/direnv/direnvrc",
    "/.config/mise",
    "/.config/mise/config.toml",
    "/.claude/settings.json",
    "/.claude/hooks",
    "/.claude/hooks/pre.sh",
    "/.claude/commands",
    "/.claude/agents",
    "/.config/nvim",
    "/.config/nvim/lua/plugins.lua",
    "/.local/share/nvim",
    "/.local/share/nvim/lazy/plugin/init.lua",
    "/.zshenv",
    "/.profile",
    "/.zprofile",
    "/.bash_profile",
    "/.inputrc",
    "/.config/git",
    "/.config/git/config",
    "/.gitconfig",
    "/.config/autostart",
    "/.config/autostart/a.desktop",
    "/.config/systemd/user/a.service",
    "/.cargo/config.toml",
    "/.cargo/bin",
    "/.cargo/bin/cargo-x",
    "/.rustup",
    "/.rustup/toolchains/stable/bin/rustc",
    "/.config/fish",
    "/.config/fish/config.fish",
    "/.tmux.conf",
  }

  it("is refused for every path the verifier reported, with the category named", function()
    for _, rel in ipairs(reported) do
      local ok, why = check(HOME .. rel)
      H.not_ok(ok, rel .. " must be refused")
      H.match(why, "outside the sandbox later (", true, rel)
    end
  end)

  it("is refused for every path of the category list, its children and each of its parents", function()
    H.ok(#plan.CODE_RUNS_OUTSIDE >= 6, "the categories")
    for _, group in ipairs(plan.CODE_RUNS_OUTSIDE) do
      H.ok(group.category and group.category ~= "" and #group.paths > 0, vim.inspect(group.category))
      for _, rel in ipairs(group.paths) do
        local ok, why = check(HOME .. rel)
        H.not_ok(ok, group.category .. ": " .. rel)
        H.match(why, group.category, true, rel)
        H.not_ok((check(HOME .. rel .. "/child")), "child of " .. rel)
        local parent = rel
        while true do
          parent = parent:match("^(.*)/[^/]+$")
          if not parent or parent == "" then
            break
          end
          H.not_ok((check(HOME .. parent)), "parent " .. parent .. " of " .. rel)
        end
      end
    end
  end)

  it("the forbidden list IS the flattened category list (nothing is listed twice by hand)", function()
    local n = 0
    for _, group in ipairs(plan.CODE_RUNS_OUTSIDE) do
      n = n + #group.paths
    end
    H.eq(n, #plan.WRITABLE_FORBIDDEN_HOME)
    H.eq(plan.CODE_RUNS_OUTSIDE[1].paths[1], plan.WRITABLE_FORBIDDEN_HOME[1])
  end)

  it("the expert flag does not open it (it only concerns environment variables)", function()
    H.not_ok((check(HOME .. "/.bashrc", { expert = true })))
    H.not_ok((check(HOME .. "/.config/direnv", { expert = true })))
  end)

  it("a symlink that leads to one is refused, naming the target", function()
    local ok, why = plan.validate_exception({ kind = "writable", value = HOME .. "/innocent" }, {
      home = HOME,
      probes = {
        exists = function()
          return true
        end,
        realpath = function()
          return HOME .. "/.config/mise"
        end,
      },
    })
    H.not_ok(ok)
    H.match(why, "resolves to " .. HOME .. "/.config/mise", true)
  end)

  it("an ordinary directory in $HOME is still fine", function()
    for _, rel in ipairs({
      "/projects/x",
      "/.local/share/app",
      "/.config/someapp",
      "/work/direnv-notes",
      "/.cache/x",
      "/Documents",
    }) do
      local ok, why = check(HOME .. rel)
      H.ok(ok, rel .. ": " .. tostring(why))
    end
  end)

  it("policy.writable for one is ignored with a note", function()
    local p = plan.build({
      project = "/mnt/proj",
      tmp_dir = "/mnt/scratch",
      home = HOME,
      env = {},
      cmd = { "agent" },
      config = {
        network = "open",
        policy = { writable = { HOME .. "/.config/direnv", HOME .. "/.claude/hooks", "/mnt/ok" } },
      },
      aux = { empty = "/e" },
      probes = {
        stat_type = function()
          return "directory"
        end,
        lstat_type = function()
          return "directory"
        end,
        exists = function()
          return true
        end,
        list = function()
          return {}
        end,
        glob = function()
          return {}
        end,
        read_line = function()
          return nil
        end,
        realpath = function(x)
          return x
        end,
      },
    })
    local text = table.concat(p.notes, "\n")
    H.match(text, "policy.writable " .. HOME .. "/.config/direnv is ignored", true)
    H.match(text, "policy.writable " .. HOME .. "/.claude/hooks is ignored", true)
    local paths = vim.tbl_map(function(w)
      return w.path
    end, p.writable)
    H.not_ok(vim.tbl_contains(paths, HOME .. "/.config/direnv"))
    H.has(paths, "/mnt/ok")
  end)

  it("sb.approve refuses it and logs the refusal", function()
    local home = uv.os_homedir()
    write(home .. "/.config/direnv/direnvrc", "# x\n")
    local e, why = sb.approve(H.tmpdir(), "writable", home .. "/.config/direnv", "project")
    H.eq(nil, e)
    H.match(why, "outside the sandbox later", true)
    H.eq("refused", store.read_log()[1].decision)
  end)
end)

-- ------------------------------------------------------------------ (b) hard links

local PROJECT, TMP = "/h/proj", "/h/scratch"
local FHOME = "/h"

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

local function build(extra, over, info, scan_result)
  local entries = vim.tbl_extend("force", {
    [FHOME] = "directory",
    [FHOME .. "/.claude"] = "directory",
    [PROJECT] = "directory",
    [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  local probes = fakefs(entries, info)
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

describe("a project file that is a hard link of a file that runs outside the sandbox", function()
  -- target (a file of the fake $HOME or of the project), the project name that links to it
  local cases = {
    { "/.bashrc", "dot_bashrc" },
    { "/.zshenv", "zshenv.txt" },
    { "/.profile", "p" },
    { "/.gitconfig", "gitconfig.bak" },
    { "/.config/git/config", "gc" },
    { "/.config/direnv/direnvrc", "rc" },
    { "/.config/mise/config.toml", "m.toml" },
    { "/.claude/settings.json", "s.json" },
    { "/.claude/hooks/pre.sh", "pre" },
    { "/.config/nvim/init.lua", "init.txt" },
    { "/.local/share/nvim/site/plugin/x.lua", "x" },
    { "/.cargo/config.toml", "cc" },
    { "/.local/bin/tool", "tool" },
    { "/.config/fish/config.fish", "fish" },
    { "/.tmux.conf", "tmux" },
    { "/.config/autostart/a.desktop", "a.desktop" },
    { "/.config/systemd/user/a.service", "svc" },
  }

  local function entries_for(rel, name)
    local e = { [PROJECT .. "/" .. name] = "file" }
    local acc = FHOME
    for seg in rel:gmatch("[^/]+") do
      acc = acc .. "/" .. seg
      e[acc] = "directory"
    end
    e[FHOME .. rel] = "file"
    return e
  end

  for _, c in ipairs(cases) do
    for _, mode in ipairs({ "allowlist", "denylist" }) do
      it(c[1] .. " linked as " .. c[2] .. " is hidden (" .. mode .. ")", function()
        local extra = entries_for(c[1], c[2])
        local info = { [FHOME .. c[1]] = { nlink = 2, dev = 7, ino = 99 } }
        local scanned =
          { hits = {}, files = 1, multi = { { path = PROJECT .. "/" .. c[2], dev = 7, ino = 99, nlink = 2 } } }
        local p = build(extra, { config = { network = "open", home = mode } }, info, scanned)
        local h = hidden_map(p)[PROJECT .. "/" .. c[2]]
        H.ok(h, "the writable name of " .. c[1] .. " stays writable")
        H.match(h.why, "hard link of " .. FHOME .. c[1] .. ", which runs outside the sandbox", true)
        local entry
        for _, l in ipairs(p.hardlinks) do
          entry = entry or (l.alias == PROJECT .. "/" .. c[2] and l)
        end
        H.ok(entry and entry.code, "listed in the preview data")
        local text = table.concat(ui.lines(p, { home = FHOME }), "\n")
        H.match(text, "Hidden files that have other hard links", true)
        H.match(text, c[1], true)
      end)
    end
  end

  it("a different inode with the same link count is left alone", function()
    local extra = entries_for("/.bashrc", "other")
    local info = { [FHOME .. "/.bashrc"] = { nlink = 2, dev = 7, ino = 99 } }
    local scanned = { hits = {}, files = 1, multi = { { path = PROJECT .. "/other", dev = 7, ino = 5, nlink = 2 } } }
    local p = build(extra, nil, info, scanned)
    H.eq(nil, hidden_map(p)[PROJECT .. "/other"])
  end)

  it("a different device with the same inode number is left alone", function()
    local extra = entries_for("/.bashrc", "other")
    local info = { [FHOME .. "/.bashrc"] = { nlink = 2, dev = 7, ino = 99 } }
    local scanned = { hits = {}, files = 1, multi = { { path = PROJECT .. "/other", dev = 8, ino = 99, nlink = 2 } } }
    H.eq(nil, hidden_map(build(extra, nil, info, scanned))[PROJECT .. "/other"])
  end)

  it(
    "a file of the project that is locked read-only (.git/hooks, .git/config, .envrc) is covered through its other names",
    function()
      for _, c in ipairs({
        { "/.git/hooks/pre-commit", "hookcopy" },
        { "/.git/config", "gitcfg" },
        { "/.envrc", "envrc.txt" },
      }) do
        local extra = {
          [PROJECT .. c[1]] = "file",
          [PROJECT .. "/" .. c[2]] = "file",
          [PROJECT .. "/.git/hooks"] = "directory",
        }
        local info = { [PROJECT .. c[1]] = { nlink = 2, dev = 7, ino = 77 } }
        local scanned = {
          hits = {},
          files = 2,
          multi = {
            { path = PROJECT .. "/" .. c[2], dev = 7, ino = 77, nlink = 2 },
            { path = PROJECT .. c[1], dev = 7, ino = 77, nlink = 2 },
          },
        }
        local p = build(extra, nil, info, scanned)
        local h = hidden_map(p)
        H.ok(h[PROJECT .. "/" .. c[2]], c[1] .. " has a writable second name")
        H.match(h[PROJECT .. "/" .. c[2]].why, "hard link of " .. PROJECT .. c[1], true)
        H.eq(nil, h[PROJECT .. c[1]], "the read-only name itself is not hidden")
      end
    end
  )

  it("a name that sits below a path mounted read-only anyway is not hidden again", function()
    local extra = {
      [PROJECT .. "/.vscode"] = "directory",
      [PROJECT .. "/.vscode/tasks.json"] = "file",
      [PROJECT .. "/.envrc"] = "file",
    }
    local info = { [PROJECT .. "/.envrc"] = { nlink = 2, dev = 7, ino = 3 } }
    local scanned = {
      hits = {},
      files = 2,
      multi = {
        { path = PROJECT .. "/.vscode/tasks.json", dev = 7, ino = 3, nlink = 2 },
        { path = PROJECT .. "/.envrc", dev = 7, ino = 3, nlink = 2 },
      },
    }
    local p = build(extra, nil, info, scanned)
    H.eq(nil, hidden_map(p)[PROJECT .. "/.vscode/tasks.json"])
  end)

  it("any other multi-link file is reported (count, first names, a note): its other names cannot be seen", function()
    local extra = { [PROJECT .. "/a.txt"] = "file", [PROJECT .. "/b.txt"] = "file", [PROJECT .. "/c.txt"] = "file" }
    local scanned = {
      hits = {},
      files = 3,
      multi = {
        { path = PROJECT .. "/a.txt", dev = 7, ino = 1, nlink = 2 },
        { path = PROJECT .. "/b.txt", dev = 7, ino = 1, nlink = 2 },
        { path = PROJECT .. "/c.txt", dev = 7, ino = 2, nlink = 3 },
      },
    }
    local p = build(extra, nil, {}, scanned)
    H.ok(p.multilinks, "plan.multilinks")
    H.eq(3, p.multilinks.count)
    H.eq(3, #p.multilinks.sample)
    local notes = table.concat(p.notes, "\n")
    H.match(notes, "3 project files have other hard links", true)
    H.match(notes, "/h/proj/a.txt", true)
    H.match(table.concat(ui.lines(p, { home = FHOME }), "\n"), "3 project files have other hard links", true)
  end)

  it("a project without multi-link files has no entry and no note", function()
    local p = build({ [PROJECT .. "/a.txt"] = "file" }, nil, {}, { hits = {}, files = 1, multi = {} })
    H.eq(nil, p.multilinks)
    H.no_match(table.concat(p.notes, "\n"), "hard link", true)
  end)

  it(
    "the comparison is bounded: a huge tree of a protected directory cannot crowd out the rest, and says so",
    function()
      local extra = {
        [PROJECT .. "/x"] = "file",
        [FHOME .. "/.bashrc"] = "file",
        [FHOME .. "/.config"] = "directory",
        [FHOME .. "/.local"] = "directory",
        [FHOME .. "/.local/share"] = "directory",
        [FHOME .. "/.local/share/nvim"] = "directory",
      }
      for i = 1, plan.HARDLINK_CODE_MAX + 50 do
        extra[FHOME .. "/.local/share/nvim/f" .. i] = "file"
      end
      local info = { [FHOME .. "/.bashrc"] = { nlink = 2, dev = 7, ino = 9 } }
      local scanned = { hits = {}, files = 1, multi = { { path = PROJECT .. "/x", dev = 7, ino = 9, nlink = 2 } } }
      local p = build(extra, nil, info, scanned)
      H.ok(hidden_map(p)[PROJECT .. "/x"], "~/.bashrc is checked before the big directory")
      H.match(table.concat(p.notes, "\n"), "hard-link check of files that run outside the sandbox stopped after", true)
    end
  )

  it(
    "really cannot be written through in a sandbox (allowlist and denylist), and the host file is unchanged",
    function()
      H.need_sandbox()
      for _, mode in ipairs({ "allowlist", "denylist" }) do
        sb.config.home, sb.config.network = mode, "open"
        local home = uv.os_homedir()
        local project = home .. "/hardlink-code-" .. mode
        write(project .. "/Cargo.toml", "[package]\n")
        write(home .. "/.bashrc", "# real bashrc\n")
        write(home .. "/.config/direnv/direnvrc", "# real direnvrc\n")
        write(project .. "/.git/hooks/pre-commit", "#!/bin/sh\n", tonumber("755", 8))
        H.ok(uv.fs_link(home .. "/.bashrc", project .. "/dot_bashrc"))
        H.ok(uv.fs_link(home .. "/.config/direnv/direnvrc", project .. "/dot_direnvrc"))
        H.ok(uv.fs_link(project .. "/.git/hooks/pre-commit", project .. "/hook_alias"))
        local cmd, err, h = sb.wrap(
          { "sh", "-c", "echo PWNED >> dot_bashrc; echo PWNED >> dot_direnvrc; echo PWNED >> hook_alias; echo done" },
          project,
          H.tmpdir()
        )
        H.ok(cmd, err)
        local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
        h.release()
        local out = (r.stdout or "") .. (r.stderr or "")
        H.match(out, "done", true, out)
        local bashrc = table.concat(vim.fn.readfile(home .. "/.bashrc"), "\n")
        local direnv = table.concat(vim.fn.readfile(home .. "/.config/direnv/direnvrc"), "\n")
        local hook = table.concat(vim.fn.readfile(project .. "/.git/hooks/pre-commit"), "\n")
        uv.fs_unlink(home .. "/.bashrc")
        vim.fn.delete(home .. "/.config/direnv", "rf")
        vim.fn.delete(project, "rf")
        H.no_match(bashrc, "PWNED", true, mode .. " ~/.bashrc written through a hard link")
        H.no_match(direnv, "PWNED", true, mode .. " direnvrc written through a hard link")
        H.no_match(hook, "PWNED", true, mode .. " .git hook written through a hard link")
      end
    end
  )
end)

-- ------------------------------------------------------------------ (c) scan boundaries

describe("the content scan, token boundaries", function()
  local tokens = {
    { "AWS access key id", "AKIAJ5Q7R2M9TXLB4NWC" },
    { "GitHub token", "ghp_" .. string.rep("Zq7x", 9), true },
    { "GitLab token", "glpat" .. "-aB3dE5fG7hI9jK1lM3nO", true },
    { "Slack token", "xoxb-1234567890-abcdefghijkl", true },
    { "Stripe live key", "sk_live" .. "_4eC39HqLyjWDarjtT1zdp7dc", true },
    { "Anthropic key", "sk-ant-api03-" .. string.rep("Zq7xK9mP", 6), true },
    { "Google API key", "AIza" .. string.rep("Zq7xK9mPqL", 3) .. "abcde" },
    { "npm token", "npm_" .. string.rep("Zq7x", 9), true },
  }
  local wrappers = {
    ["bare"] = "%s",
    ["env assignment"] = "KEY=%s",
    ["env assignment with export and semicolon"] = "export KEY=%s;",
    ["spaces around ="] = "key = %s",
    ["double quotes"] = 'KEY="%s"',
    ["single quotes"] = "KEY='%s'",
    ["colon"] = "key:%s",
    ["yaml"] = "token: %s",
    ["yaml list"] = "- %s",
    ["json"] = '{"token":"%s"}',
    ["json array"] = '["%s","x"]',
    ["json with an escaped newline before"] = '{"a":"x\\n%s"}',
    ["json with an escaped tab before"] = '{"a":"x\\t%s\\n"}',
    ["parentheses"] = "(%s)",
    ["brackets"] = "[%s]",
    ["angle brackets"] = "<%s>",
    ["comma"] = "a,%s,b",
    ["header"] = "Authorization: Bearer %s",
    ["url query"] = "https://h/x?token=%s&y=1",
    ["url path"] = "https://h/%s/x",
    ["markdown code"] = "`%s`",
    ["trailing comment"] = "KEY=%s # real",
    ["tab separated"] = "KEY\t%s",
  }

  for _, t in ipairs(tokens) do
    for name, fmt in pairs(wrappers) do
      it(t[1] .. " is found: " .. name, function()
        H.has(scan.text(fmt:format(t[2])), t[1])
        H.has(scan.text("first line\n" .. fmt:format(t[2]) .. "\nlast line\n"), t[1], "on a line of its own")
        H.has(scan.text(("first\r\n%s\r\nlast\r\n"):format(fmt:format(t[2]))), t[1], "with CRLF line ends")
      end)
    end
    it(t[1] .. " follows the word-boundary rule of its format", function()
      -- a token with a distinctive prefix is one wherever it starts (round 5: tokenghp_..., 1ghp_...); an AWS key id
      -- is not looked for inside an upper-case word (...ASIAPACIFIC...)
      if t[1] == "AWS access key id" then
        H.eq({}, scan.text("A" .. t[2]), "upper-case letter before")
        H.has(scan.text("a" .. t[2]), t[1], "lower-case letter before")
        H.has(scan.text("_" .. t[2]), t[1], "underscore before")
      else
        H.has(scan.text("a" .. t[2]), t[1], "word character before")
        H.has(scan.text("_" .. t[2]), t[1], "underscore before")
      end
      if not t[3] then -- (the open-ended formats simply take the extra characters into the token)
        H.eq({}, scan.text(t[2] .. "Q"), "word character after")
        H.eq({}, scan.text(t[2] .. "_x"), "underscore after")
      end
    end)
  end

  it("a private key header is found wherever it sits, also glued to its neighbours", function()
    local forms = {
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
    }
    local around = {
      "%s",
      "%sMIIEowIBAAKCAQEA",
      "key=%sMIIEowIBAAKCAQEA",
      "key=%s",
      'KEY="%s"',
      "KEY='%s'",
      '{"k":"%s\\nMIIE"}',
      '{"k":"%s\\r\\nMIIE"}',
      "x%sx",
      "token:%s",
      "  %s  ",
      "# %s",
      "PRIVATE_KEY=%sb3BlbnNzaC1rZXk",
      "value: |%s",
      "%s\r",
      "\xef\xbb\xbf%s",
    }
    for _, f in ipairs(forms) do
      for _, a in ipairs(around) do
        H.has(scan.text(a:format(f)), "private key", f .. " in " .. a)
      end
    end
    H.has(scan.text("a\r\n" .. forms[1] .. "\r\nMIIE\r\n"), "private key", "CRLF")
  end)

  it("public keys and certificates are not private keys", function()
    for _, f in ipairs({
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN CERTIFICATE-----",
      "-----BEGIN RSA PUBLIC KEY-----",
      "-----BEGIN X509 CRL-----",
    }) do
      H.eq({}, scan.text("key=" .. f .. "MIIE"), f)
    end
  end)

  it("a private key inside base64, at any alignment, is found; a certificate in base64 is not", function()
    for _, hdr in ipairs({
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
    }) do
      for k = 0, 2 do
        local body = ("y"):rep(k) .. hdr .. "\nMIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----\n"
        local enc = vim.base64.encode(body)
        H.has(scan.text("data: " .. enc), "private key (base64)", hdr .. " shifted by " .. k)
        H.has(scan.text('{"key":"' .. enc .. '"}'), "private key (base64)", "in json")
        H.has(scan.text("  tls.key: " .. enc .. "\r\n"), "private key (base64)", "in yaml with CRLF")
      end
    end
    H.eq({}, scan.text("data: " .. vim.base64.encode("-----BEGIN CERTIFICATE-----\nMIIE\n")))
    H.eq({}, scan.text("data: " .. vim.base64.encode("-----BEGIN PUBLIC KEY-----\nMIIE\n")))
  end)

  it("the AWS secret key pattern keeps its own boundaries (quotes, colon, CRLF)", function()
    local secret = string.rep("aB3dE5fG7h", 4)
    for _, fmt in ipairs({
      "aws_secret_access_key = %s",
      'AWS_SECRET_ACCESS_KEY="%s"',
      "aws_secret_access_key: %s\r",
      '{"aws_secret_access_key":"%s"}',
    }) do
      H.has(scan.text(fmt:format(secret)), "AWS secret access key", fmt)
    end
  end)

  it("the project walk stops after its directory budget and says so", function()
    local project = H.tmpdir()
    for i = 1, 120 do
      vim.fn.mkdir(project .. "/d/" .. i, "p") -- (the budget is lowered below: 6000 directories would prove no more)
    end
    local saved_max = scan.MAX_DIRS
    scan.MAX_DIRS = 50
    local res = scan.project(project, {})
    scan.MAX_DIRS = saved_max
    H.eq(true, res.truncated)
    H.match(res.why, "directories", true)
  end)
end)

describe("the project walk, other budgets", function()
  it("reads a file system that reports no entry types (type 'unknown' or nil) by asking for each entry", function()
    local project = H.tmpdir()
    write(project .. "/a/b/secret.txt", "key=ghp_" .. string.rep("Zq7x", 9) .. "\n")
    write(project .. "/top.txt", "nothing\n")
    local orig = uv.fs_scandir_next
    uv.fs_scandir_next = function(h)
      local name = orig(h)
      return name, "unknown"
    end
    local ok, res = pcall(scan.project, project, {})
    uv.fs_scandir_next = orig
    H.ok(ok, tostring(res))
    H.eq(2, res.files, "both files were seen")
    H.eq(1, #res.hits, "and the one below two directories was read")
  end)

  it("stops on the time budget while entering directories, even when there is no file to count", function()
    local project = H.tmpdir()
    for i = 1, 20 do
      vim.fn.mkdir(project .. "/d" .. i .. "/e", "p")
    end
    local saved_ms = scan.MAX_MS
    scan.MAX_MS = -1
    local res = scan.project(project, {})
    scan.MAX_MS = saved_ms
    H.eq(true, res.truncated)
    H.match(res.why, "ms", true)
    H.eq(0, res.files)
  end)
end)

-- ------------------------------------------------------------------ performance

describe("scanning a large project", function()
  it("skips target/ and node_modules/ without listing them, and a plan for it builds fast", function()
    local project = H.tmpdir()
    write(project .. "/Cargo.toml", "[package]\nname='x'\n")
    write(project .. "/src/main.rs", "fn main() {}\n")
    local n = 0
    for d = 1, 40 do
      local dir = project .. "/target/debug/deps/d" .. d
      vim.fn.mkdir(dir, "p")
      for f = 1, 500 do
        local fh = io.open(dir .. "/f" .. f .. ".o", "wb")
        fh:write("x")
        fh:close()
        n = n + 1
      end
    end
    local t0 = uv.hrtime()
    local res = scan.project(project, {})
    local ms = (uv.hrtime() - t0) / 1e6
    H.eq(false, res.truncated)
    H.eq(2, res.files, "only the two project files were looked at (target/ is skipped)")
    H.ok(ms < 500, ("scan of a project with %d files in target/ took %.0f ms"):format(n, ms))
    sb.config.network = "open"
    local t1 = uv.hrtime()
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    local pms = (uv.hrtime() - t1) / 1e6
    H.ok(p, "plan")
    H.ok(pms < 2000, ("plan for a project with %d files in target/ took %.0f ms"):format(n, pms))
  end)

  it("a source tree beyond the file budget stops and says so, within the time budget", function()
    local project = H.tmpdir()
    local saved_max = scan.MAX_FILES
    scan.MAX_FILES = 100
    for d = 1, 5 do
      for f = 1, 60 do
        write(project .. "/out/d" .. d .. "/f" .. f .. ".txt", "hello\n")
      end
    end
    local res = scan.project(project, {})
    scan.MAX_FILES = saved_max
    H.eq(true, res.truncated)
    H.match(res.why, "files", true)
    H.eq(100, res.files)
  end)
end)

describe("secret name matching", function()
  -- the algorithm the matcher replaced: one Lua pattern per glob, compiled again for every name
  local function reference(name, globs, except)
    local n = name:lower()
    if n:sub(-4) == ".pub" then
      return false
    end
    for _, e in ipairs(except or {}) do
      if n == e:lower() then
        return false
      end
    end
    for _, g in ipairs(globs) do
      local pat = "^" .. g:lower():gsub("[%^%$%(%)%%%.%[%]%+%-%?]", "%%%0"):gsub("%*", ".*") .. "$"
      if n:match(pat) then
        return true
      end
    end
    return false
  end

  it("gives the same answer as one pattern per glob, for the default list, odd globs and odd names", function()
    local globs = vim.list_extend(
      vim.deepcopy(plan.PROJECT_SECRET_GLOBS),
      { "a*b*c", "x?y", "[z]", "pre*", "*suf", "MiXed*Case", "*.k+" }
    )
    local names = {}
    for _, g in ipairs(vim.list_extend(vim.deepcopy(globs), { "*" })) do
      for _, fill in ipairs({ "", "x", "ab.c", "Q-1_2" }) do
        local n = g:gsub("%*", fill)
        for _, v in ipairs({ n, n:upper(), "p" .. n, n .. "z", n .. ".pub", n .. "~", "dir/" .. n }) do
          names[#names + 1] = v
        end
      end
    end
    vim.list_extend(
      names,
      { "", ".", "..", "a", "abc", "README.md", "Cargo.toml", "main.rs", ".ENV", ".Env.Example", "id_rsa.PUB" }
    )
    local m = plan.secret_matcher(globs, plan.PROJECT_SECRET_EXCEPT)
    for _, n in ipairs(names) do
      H.eq(reference(n, globs, plan.PROJECT_SECRET_EXCEPT), m(n), "name " .. vim.inspect(n))
      H.eq(
        reference(n, globs, plan.PROJECT_SECRET_EXCEPT),
        plan.is_secret_name(n, globs, plan.PROJECT_SECRET_EXCEPT),
        "cached " .. vim.inspect(n)
      )
    end
    H.ok(#names > 3000, "enough names to mean something: " .. #names)
    -- a lone "*" matches every name but a public key
    local all = plan.secret_matcher({ "*" })
    H.eq(true, all("anything"))
    H.eq(true, all(""))
    H.eq(false, all("k.pub"))
    -- some names must come out false and some true, or the comparison above proves nothing
    local t, f = 0, 0
    for _, n in ipairs(names) do
      if m(n) then
        t = t + 1
      else
        f = f + 1
      end
    end
    H.ok(t > 500 and f > 500, ("true %d, false %d"):format(t, f))
  end)

  it("follows a list that grows between calls (policy.secret_files is appended to a copy)", function()
    local globs = { "a.txt" }
    H.eq(false, plan.is_secret_name("b.txt", globs))
    globs[#globs + 1] = "b.*"
    H.eq(true, plan.is_secret_name("b.txt", globs))
    H.eq(false, plan.is_secret_name("b.txt", globs, { "b.txt" }))
  end)

  it("matches 100000 names within 3 s (the one-pattern-per-glob algorithm needed 18 s)", function()
    local globs = plan.PROJECT_SECRET_GLOBS
    local t0 = uv.hrtime()
    local hits = 0
    for i = 1, 100000 do
      if plan.is_secret_name("file" .. i .. ".o", globs, plan.PROJECT_SECRET_EXCEPT) then
        hits = hits + 1
      end
    end
    local ms = (uv.hrtime() - t0) / 1e6
    H.eq(0, hits)
    H.ok(ms < 3000, ("100000 names took %.0f ms"):format(ms))
  end)

  it("a plan for a directory of 30000 files outside the skipped ones builds in a few seconds at most", function()
    local project = H.tmpdir()
    write(project .. "/Cargo.toml", "[package]\nname='x'\n")
    for d = 1, 30 do
      local dir = project .. "/out/d" .. d
      vim.fn.mkdir(dir, "p")
      for f = 1, 1000 do
        local fh = io.open(dir .. "/file" .. f .. ".txt", "wb")
        fh:write("x")
        fh:close()
      end
    end
    write(project .. "/out/d3/.env", "S=1\n")
    sb.config.network = "open"
    local t0 = uv.hrtime()
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    local ms = (uv.hrtime() - t0) / 1e6
    H.ok(p)
    local found
    for _, h in ipairs(p.hidden) do
      found = found or h.path == project .. "/out/d3/.env"
    end
    H.ok(found, "a secret by name in a big directory is still found")
    H.ok(ms < 4000, ("plan took %.0f ms"):format(ms))
  end)
end)

-- ------------------------------------------------------------------ (d) kill -9

describe("a Neovim that was killed (kill -9)", function()
  local function spawn_child(base, state, project, network)
    local child = base .. "/child.lua"
    write(
      child,
      ([[
      vim.opt.rtp:prepend(%q)
      local sb = require("xyno_sandbox")
      require("xyno_sandbox.store").dir_override = %q
      sb.config.network = %q
      sb.config.home = "denylist"
      local cmd, err, h = sb.wrap({ "true" }, %q, vim.fn.tempname() .. "-scratch")
      if not cmd then io.stderr:write(tostring(err)) os.exit(3) end
      local out = { vim.fn.fnamemodify(vim.fn.tempname(), ":h") }
      for _, t in ipairs(h.temp) do out[#out + 1] = t end
      if h.net_dir then out[#out + 1] = h.net_dir end
      vim.fn.writefile(out, %q)
      vim.wait(120000)
    ]]):format(H.repo, state, network, project, base .. "/report")
    )
    return child
  end

  local function run(network)
    H.need_sandbox()
    local base = H.tmpdir()
    local state = H.tmpdir() .. "/state"
    store.dir_override = state
    local project = H.tmpdir()
    write(project .. "/.env", "SECRET=1\n")
    write(
      project .. "/.git/config",
      '[remote "o"]\n\turl = https://u:ghp_' .. string.rep("Zq7x", 9) .. "@github.com/x/y\n"
    )
    write(uv.os_homedir() .. "/.claude.json", '{"numStartups":1}\n')
    local child = spawn_child(base, state, project, network)
    local proc = vim.system(
      { vim.v.progpath, "--headless", "-u", "NONE", "-l", child },
      { text = true, env = { TMPDIR = base } }
    )
    H.ok(
      vim.wait(30000, function()
        return uv.fs_stat(base .. "/report") ~= nil
      end, 50),
      "the child did not wrap"
    )
    local report = vim.fn.readfile(base .. "/report")
    local nvim_tmp = table.remove(report, 1)
    H.match(nvim_tmp, base, true, "the child's own temporary directory")
    local empties = vim.tbl_filter(function(f)
      return f:match("%.empty$")
    end, report)
    H.ok(#empties >= 1, "the launch created its empty file: " .. vim.inspect(report))
    for _, f in ipairs(report) do
      H.ok(uv.fs_lstat(f), "exists while the child lives: " .. f)
    end
    uv.kill(proc.pid, 9)
    proc:wait(10000)
    H.ok(uv.fs_stat(nvim_tmp), "kill -9 leaves Neovim's temporary directory behind")
    -- the next launch (any wrap(), here the reaper directly)
    sb.reap_orphans()
    for _, f in ipairs(report) do
      H.eq(nil, uv.fs_lstat(f), "left behind: " .. f)
    end
    H.eq(nil, uv.fs_lstat(nvim_tmp), "the emptied temporary directory of the dead Neovim is removed too: " .. nvim_tmp)
    H.ok(uv.fs_stat(base), "only that directory: its parent stays")
  end

  it("leaves nothing after the next launch (open network)", function()
    run("open")
  end)

  it("leaves nothing after the next launch (filtered network: the socket directory too)", function()
    run("filtered")
  end)

  it("a temporary directory of a dead Neovim that still holds something of its own is kept", function()
    H.need_sandbox()
    local base = H.tmpdir()
    local d = base .. "/nvim.someone/abc123"
    write(d .. "/0.empty", "")
    write(d .. "/mine.txt", "keep")
    local dead_pid = vim.system({ "sh", "-c", "echo $$" }, { text = true }):wait().stdout:match("%d+")
    local dir = store.dir() .. "/live"
    vim.fn.mkdir(dir, "p")
    vim.fn.writefile({ "/some/project", "temp\t" .. d .. "/0.empty", "dir\t" .. d }, dir .. "/" .. dead_pid .. "-1-x")
    sb.reap_orphans()
    H.eq(nil, uv.fs_lstat(d .. "/0.empty"))
    H.ok(uv.fs_stat(d .. "/mine.txt"), "a file this plugin did not create is never removed")
    H.ok(uv.fs_stat(d), "and its directory stays")
  end)

  it("an empty file that is not empty (or not named .empty) is never deleted by the reaper", function()
    local base = H.tmpdir()
    local f1, f2 = base .. "/1.empty", base .. "/2.txt"
    write(f1, "content")
    write(f2, "")
    local dead_pid = vim.system({ "sh", "-c", "echo $$" }, { text = true }):wait().stdout:match("%d+")
    local dir = store.dir() .. "/live"
    vim.fn.mkdir(dir, "p")
    vim.fn.writefile({ "/p", "temp\t" .. f1, "temp\t" .. f2 }, dir .. "/" .. dead_pid .. "-1-y")
    sb.reap_orphans()
    H.ok(uv.fs_stat(f1) and uv.fs_stat(f2))
  end)

  it("each launch gets its own empty file, removed by release()", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.tmpdir()
    write(project .. "/.env", "S=1\n")
    local cmd, err, h = sb.wrap({ "true" }, project, H.tmpdir())
    H.ok(cmd, err)
    local cmd2, _, h2 = sb.wrap({ "true" }, project, H.tmpdir())
    H.ok(cmd2)
    H.ok(h.plan.empty_file and h2.plan.empty_file and h.plan.empty_file ~= h2.plan.empty_file, "one file per launch")
    H.ok(uv.fs_stat(h.plan.empty_file))
    h.release()
    H.eq(nil, uv.fs_lstat(h.plan.empty_file), "removed with its launch")
    H.ok(uv.fs_stat(h2.plan.empty_file), "the other launch is not affected")
    h2.release()
    H.eq(nil, uv.fs_lstat(h2.plan.empty_file))
  end)
end)

-- ------------------------------------------------------------------ (f) the runner

local function nested(body, env)
  local dir = H.tmpdir()
  write(dir .. "/inner_spec.lua", body)
  local e = vim.tbl_extend("force", { XYNO_TEST_WORKER = "0" }, env or {})
  local r = vim
    .system(
      { vim.v.progpath, "--headless", "-l", H.repo .. "/tests/run.lua", dir .. "/inner_spec.lua" },
      { text = true, env = e }
    )
    :wait(180000)
  return (r.stdout or "") .. (r.stderr or ""), r.code
end

describe("the runner without a usable $HOME", function()
  it("HOME=/nonexistent does not die with E739: it runs (or skips cleanly) and exits 0", function()
    -- (an OUTER run with the same unusable HOME is itself using <checkout>/.test-root: compare what is in it)
    local function listing()
      local names = {}
      for n in vim.fs.dir(H.repo .. "/.test-root") do
        names[#names + 1] = n
      end
      table.sort(names)
      return names
    end
    local before = listing()
    local out, code =
      nested('it("runs", function() end)', { HOME = "/nonexistent", XDG_CACHE_HOME = "", XYNO_TEST_BASE = "" })
    H.no_match(out, "E739", true, out)
    H.eq(0, code, out)
    H.match(out, "RESULT passed=", true, out)
    if H.repo:sub(1, 5) ~= "/tmp/" then
      -- a checkout outside /tmp can hold the private root itself (.test-root): the run then really runs
      H.match(out, "passed=1", true, out)
      H.no_match(out, "SKIP all specs", true, out)
      H.eq(before, listing(), "the nested run's private root inside the fallback directory is removed again")
      if #before == 0 then
        H.eq(nil, uv.fs_stat(H.repo .. "/.test-root"), "the fallback directory itself is removed again")
      end
    end
  end)

  it("with nowhere to put the private root it SKIPs with a reason (exit 0), never crashes", function()
    -- a copy of the runner in a directory under /tmp: the checkout-local fallback is then not usable either
    local dir = H.tmpdir()
    vim.fn.mkdir(dir .. "/tests", "p")
    vim.fn.writefile(vim.fn.readfile(H.repo .. "/tests/run.lua"), dir .. "/tests/run.lua")
    vim.fn.writefile(vim.fn.readfile(H.repo .. "/tests/reaper.lua"), dir .. "/tests/reaper.lua")
    write(dir .. "/tests/x_spec.lua", 'it("never runs", function() error("boom") end)')
    local r = vim
      .system({ vim.v.progpath, "--headless", "-l", dir .. "/tests/run.lua" }, {
        text = true,
        env = { HOME = "/nonexistent", XDG_CACHE_HOME = "", XYNO_TEST_BASE = "", XYNO_TEST_WORKER = "0" },
      })
      :wait(60000)
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "E739", true, out)
    H.eq(0, r.code, out)
    H.match(out, "SKIP all specs (no writable directory outside /tmp", true, out)
    H.match(out, "skipped=1", true, out)
    H.no_match(out, "boom", true, out)
  end)
end)
