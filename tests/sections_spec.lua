-- Every section of the preview has its own check: its heading, the count, an entry that must be
-- in it and one that must not. A section that disappears from ui.lines() fails here by name.
local H = require("xynotest.helpers")
local plan = require("xyno_sandbox.plan")
local ui = require("xyno_sandbox.ui")

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"
local SECRET_VALUE = "TOPSECRETVALUE"

local function fakefs(entries)
  return {
    stat_type = function(p) return entries[p] end,
    lstat_type = function(p) return entries[p] end,
    exists = function(p) return entries[p] ~= nil end,
    list = function(dir)
      local out, prefix = {}, dir .. "/"
      for p, t in pairs(entries) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), t }
        end
      end
      table.sort(out, function(a, b) return a[1] < b[1] end)
      return out
    end,
    glob = function(pat)
      local out = {}
      local lp = "^" .. pat:gsub("[%-%.%+%[%]%(%)%$%^%%]", "%%%0"):gsub("%*", "[^/]*") .. "$"
      for p in pairs(entries) do
        if p:match(lp) then out[#out + 1] = p end
      end
      table.sort(out)
      return out
    end,
    read_line = function() return nil end,
    realpath = function(p) return entries[p] and p or nil end,
  }
end

local ENTRIES = {
  [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
  [PROJECT .. "/.git"] = "directory", [PROJECT .. "/.env"] = "file", [PROJECT .. "/.mise.toml"] = "file",
  [PROJECT .. "/.vscode"] = "directory", [HOME .. "/.ssh"] = "directory", ["/run"] = "directory", ["/var/tmp"] = "directory",
  [HOME .. "/.claude/projects"] = "directory", [HOME .. "/.claude/projects/-h-proj"] = "directory",
  [HOME .. "/.claude/.credentials.json"] = "file", [HOME .. "/.claude/shell-snapshots"] = "directory",
}

local function build(cfg, env)
  return plan.build({
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = fakefs(ENTRIES),
    env = vim.tbl_extend("force", { PATH = "/usr/bin", GITHUB_TOKEN = SECRET_VALUE, MY_API_KEY = SECRET_VALUE, TERM = "xterm" }, env or {}),
    cmd = { "agent", "-p", "prompt" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", net_dir = "/aux/net" },
    config = cfg,
  })
end

--- The lines of the section whose heading starts with `title` (up to the next blank line).
local function section(lines, title)
  for i, l in ipairs(lines) do
    if l:sub(1, #title) == title then
      local out = { heading = l }
      for j = i + 1, #lines do
        if lines[j] == "" then
          break
        end
        out[#out + 1] = lines[j]
      end
      return out
    end
  end
end

local function text_of(s)
  return table.concat(s, "\n")
end

local function sections(cfg)
  return ui.lines(build(cfg), { home = HOME }), build(cfg)
end

describe("sections of the preview (allowlist, filtered network)", function()
  local lines, p
  before_each(function()
    lines, p = sections({ home = "allowlist", network = "filtered" })
  end)

  it("Network socket directory: the one directory that is the way out, read-only", function()
    local s = H.ok(section(lines, "Network socket directory"), "section missing")
    H.match(s.heading, "(1)", true)
    H.match(text_of(s), "--ro-bind /aux/net /aux/net", true)
    H.match(text_of(s), "the only way out", true)
  end)

  it("Agent transcripts: only this project's directory, writable; the others are not listed", function()
    local s = H.ok(section(lines, "Agent transcripts"), "section missing")
    H.match(text_of(s), "--bind ~/.claude/projects/-h-proj ~/.claude/projects/-h-proj", true)
    H.match(text_of(s), "this project's transcripts, writable", true)
    H.no_match(text_of(s), "--ro-bind ~/.claude/projects ", true)
  end)

  it("Agent state (~/.claude): the login read-only, the throw-away directory", function()
    local s = H.ok(section(lines, "Agent state"), "section missing")
    H.match(text_of(s), "--tmpfs ~/.claude", true)
    H.match(text_of(s), "--ro-bind ~/.claude/.credentials.json ~/.claude/.credentials.json", true)
  end)

  it("Writable: the project, the scratch directory, with their reasons and the count", function()
    local s = H.ok(section(lines, "Writable"), "section missing")
    H.eq(("Writable (%d)"):format(#p.writable), s.heading)
    H.match(text_of(s), "~/proj  [project]", true)
    H.match(text_of(s), "~/scratch  [scratch]", true)
    H.no_match(text_of(s), "none", true)
  end)

  it("Read-only: files that would run outside the sandbox, with their reasons", function()
    local s = H.ok(section(lines, "Read-only (would run"), "section missing")
    H.match(text_of(s), "~/proj/.mise.toml  [project]", true)
    H.match(text_of(s), "~/proj/.vscode  [project]", true)
    H.no_match(text_of(s), ".git  [", true, "git directories are listed in their own section")
  end)

  it("git directories locked: the project's .git, counted", function()
    local s = H.ok(section(lines, "Read-only inside the writable paths, git directories locked"), "section missing")
    H.eq("Read-only inside the writable paths, git directories locked (1)", s.heading)
    H.eq({ "  ~/proj/.git" }, vim.list_slice(s, 1, 1))
  end)

  it("Absent files and directories guarded: what cannot be created", function()
    local s = H.ok(section(lines, "Absent files and directories guarded"), "section missing")
    H.match(text_of(s), "~/proj/.envrc  [absent .envrc]", true)
    H.match(text_of(s), "~/proj/.cargo  [absent .cargo]", true)
    H.no_match(text_of(s), ".mise.toml", true, "an existing file is read-only, not 'absent'")
  end)

  it("Hidden project secrets and Hidden credential paths: split by origin", function()
    local a = H.ok(section(lines, "Hidden project secrets and sockets"), "project section missing")
    H.match(text_of(a), "~/proj/.env  [file, project secret]", true)
    local dl = sections({ home = "denylist", network = "open" })
    local b = H.ok(section(dl, "Hidden credential paths"), "credential section missing")
    H.match(text_of(b), "~/.ssh  [dir, credentials]", true)
    H.no_match(text_of(b), ".env", true)
    H.match(text_of(section(lines, "Hidden credential paths")), "none", true, "in the allowlist view an unmounted ~/.ssh needs no hiding")
  end)

  it("Stripped environment variables: names only, never a value", function()
    local s = H.ok(section(lines, "Stripped environment variables"), "section missing")
    H.match(text_of(s), "GITHUB_TOKEN", true)
    H.match(text_of(s), "MY_API_KEY", true)
    H.no_match(table.concat(lines, "\n"), SECRET_VALUE, true)
  end)

  it("the `env -i` line states the number of variables passed and that stripped values do not exist", function()
    local line
    for _, l in ipairs(lines) do
      if l:match("^Environment: ") then line = l end
    end
    H.ok(line, "Environment line missing")
    H.match(line, "bwrap starts with `env -i`", true)
    H.match(line, ("and %d variables"):format(#p.env_pass), true)
    H.match(line, "stripped values never exist in the sandbox", true)
    H.ok(#p.env_pass >= 2)
  end)

  it("Set inside the sandbox: the proxy variables, values hidden", function()
    local s = H.ok(section(lines, "Set inside the sandbox"), "section missing")
    H.match(text_of(s), "--setenv HTTPS_PROXY <value not shown>", true)
  end)

  it("Isolation: the flag line", function()
    local line
    for _, l in ipairs(lines) do
      if l:match("^Isolation  ") then line = l end
    end
    H.ok(line)
    H.match(line, "--die-with-parent", true)
    H.match(line, "--unshare-net", true)
  end)

  it("Home view and Other users' homes: when /home exists", function()
    H.ok(section(lines, "Home view"), "section missing")
  end)
end)

describe("sections of the preview in other modes", function()
  it("denylist view: all transcripts read-only in 'Agent transcripts', no Agent state section", function()
    local lines = sections({ home = "denylist", network = "open" })
    local s = H.ok(section(lines, "Agent transcripts"), "section missing")
    H.match(text_of(s), "--ro-bind ~/.claude/projects ~/.claude/projects", true)
    H.eq(nil, section(lines, "Agent state"))
    H.eq(nil, section(lines, "Network socket directory"), "no proxy directory with an open network")
    H.eq(nil, section(lines, "Set inside the sandbox"))
  end)

  it("an unsandboxed plan states it and lists nothing else", function()
    local text = text_of(ui.lines({ mode = "unsandboxed", via = "sandbox=false", reason = "off", project = PROJECT, agent = { cmd = { "a" } } }, { home = HOME }))
    H.match(text, "UNSANDBOXED (sandbox=false): off", true)
    H.no_match(text, "Writable", true)
  end)
end)

describe("the section checks bite", function()
  it("a preview that drops a section fails the specs above by name (spot check: ui.lines without 'net' ops)", function()
    local real = plan.ops
    plan.ops = function(pl)
      return vim.tbl_filter(function(o) return o.section ~= "net" and o.section ~= "projects" end, real(pl))
    end
    local lines = sections({ home = "allowlist", network = "filtered" })
    plan.ops = real
    H.eq(nil, section(lines, "Network socket directory"))
    H.eq(nil, section(lines, "Agent transcripts"))
  end)
end)
