-- ~/.claude in the allowlist view: the agent gets a throw-away directory with its login file
-- (read-only) and THIS project's transcripts; other projects' transcripts, settings, history and
-- sessions are not there. ~/.claude.json is a copy limited to the current project.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local ui = require("xyno_sandbox.ui")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"
local function fakefs(entries)
  return {
    stat_type = function(p) return entries[p] end,
    lstat_type = function(p) return entries[p] end,
    exists = function(p) return entries[p] ~= nil end,
    list = function() return {} end,
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
local CLAUDE = {
  [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
  [HOME .. "/.claude/.credentials.json"] = "file", [HOME .. "/.claude/settings.json"] = "file",
  [HOME .. "/.claude/CLAUDE.md"] = "file", [HOME .. "/.claude/history.jsonl"] = "file",
  [HOME .. "/.claude/projects"] = "directory", [HOME .. "/.claude/projects/-other-project"] = "directory",
  [HOME .. "/.claude/projects/-other-project/memory"] = "directory", [HOME .. "/.claude/projects/-h-proj"] = "directory",
  [HOME .. "/.claude/projects/-h-proj/memory"] = "directory", [HOME .. "/.claude/sessions"] = "directory",
  [HOME .. "/.claude/plugins"] = "directory", [HOME .. "/.claude/hooks"] = "directory",
}
local function build(over, entries)
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = fakefs(entries or CLAUDE),
    env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/e", claude_json = "/aux/cj" },
    config = { network = "open" },
  }, over or {}))
end
local function argv_text(p)
  return "\0" .. table.concat(plan.argv(p), "\0") .. "\0"
end
local function has(p, ...)
  return argv_text(p):find("\0" .. table.concat({ ... }, "\0") .. "\0", 1, true) ~= nil
end

describe("the allowlist view of ~/.claude", function()
  it("is a throw-away tmpfs with the login (read-only) and this project's transcripts (writable)", function()
    local p = build()
    H.eq("minimal", p.claude.mode)
    H.ok(has(p, "--tmpfs", HOME .. "/.claude"))
    H.ok(has(p, "--ro-bind", HOME .. "/.claude/.credentials.json", HOME .. "/.claude/.credentials.json"))
    H.ok(has(p, "--bind", HOME .. "/.claude/projects/-h-proj", HOME .. "/.claude/projects/-h-proj"))
    H.not_ok(has(p, "--bind", HOME .. "/.claude", HOME .. "/.claude"), "the real ~/.claude is not writable")
  end)

  it("shows nothing else of it: not the other projects' transcripts, settings, history, sessions, plugins", function()
    local text = argv_text(plan.build and build())
    for _, secret in ipairs({ "/.claude/projects\0", "-other-project", "settings.json", "CLAUDE.md", "history.jsonl", "/.claude/sessions",
      "/.claude/plugins", "/.claude/hooks" }) do
      H.no_match(text, secret, true, secret .. " must not be mounted")
    end
  end)

  it("keeps the memory of this project read-only (it auto-loads into the next unsandboxed session)", function()
    local p = build()
    H.ok(has(p, "--ro-bind", HOME .. "/.claude/projects/-h-proj/memory", HOME .. "/.claude/projects/-h-proj/memory"))
  end)

  it("the denylist view keeps the old behaviour (whole directory writable, executable parts read-only)", function()
    local p = build({ config = { network = "open", home = "denylist" } })
    H.eq("full", p.claude.mode)
    H.ok(has(p, "--bind", HOME .. "/.claude", HOME .. "/.claude"))
    H.ok(has(p, "--ro-bind", HOME .. "/.claude/settings.json", HOME .. "/.claude/settings.json"))
  end)

  it("policy.claude_share shows chosen names read-only; the login, transcripts and history are not shareable", function()
    local p = build({ config = { network = "open", policy = { claude_share = { "settings.json", "CLAUDE.md", "projects", "history.jsonl", "../x" } } } })
    H.ok(has(p, "--ro-bind", HOME .. "/.claude/settings.json", HOME .. "/.claude/settings.json"))
    H.ok(has(p, "--ro-bind", HOME .. "/.claude/CLAUDE.md", HOME .. "/.claude/CLAUDE.md"))
    H.eq(2, #p.claude.shared)
    H.not_ok(argv_text(p):find("history.jsonl", 1, true))
    for _, bad in ipairs({ "projects", "projects/-other-project", "history.jsonl", ".credentials.json", "sessions", "../x", "a/../b" }) do
      H.throws(function() sb.setup({ policy = { claude_share = { bad } } }) end, "claude_share")
    end
    sb.setup({ preview = "never", policy = { claude_share = { "settings.json" } } })
  end)

  it("no login file, no bind: nothing is invented", function()
    local entries = vim.tbl_extend("force", {}, CLAUDE)
    entries[HOME .. "/.claude/.credentials.json"] = nil
    local p = build(nil, entries)
    H.eq(nil, p.claude.credentials)
    H.no_match(argv_text(p), ".credentials.json", true)
  end)

  it("the preview names the section and lists what is shown", function()
    local text = table.concat(ui.lines(build()), "\n")
    H.match(text, "Agent state", true)
    H.match(text, "~/.claude/.credentials.json", true)
    H.match(text, "thrown away", true)
  end)
end)

describe("the ~/.claude.json copy", function()
  local function scrub(json, project)
    local d = H.tmpdir()
    local f = assert(io.open(d .. "/in.json", "wb"))
    f:write(json)
    f:close()
    local ok = sb.write_scrubbed_claude_json(d .. "/in.json", d .. "/out.json", project)
    local out
    if ok then
      out = vim.json.decode(table.concat(vim.fn.readfile(d .. "/out.json"), "\n"))
    end
    return ok, out, d .. "/out.json"
  end

  it("keeps the current project's record and the login state, drops every other project", function()
    local project = H.tmpdir()
    local ok, out, path = scrub(vim.json.encode({
      oauthAccount = { emailAddress = "u@example.com", accountUuid = "uuid-1" }, numStartups = 3, mcpServers = vim.empty_dict(),
      projects = { [project] = { allowedTools = {}, hasTrustDialogAccepted = true }, ["/secret/other"] = { history = { "prompt of another project" } } },
      githubRepoPaths = { ["a/b"] = { "/secret/other" } },
    }), project)
    H.ok(ok)
    H.eq({ [project] = { allowedTools = {}, hasTrustDialogAccepted = true } }, out.projects)
    H.eq("uuid-1", out.oauthAccount.accountUuid, "the login state stays")
    H.eq(nil, out.oauthAccount.emailAddress, "the e-mail address does not")
    H.eq(3, out.numStartups)
    H.eq(nil, out.githubRepoPaths)
    H.eq(tonumber("600", 8), bit.band(vim.uv.fs_stat(path).mode, tonumber("777", 8)))
    H.eq("{}", vim.json.encode(out.mcpServers), "an empty object stays an object")
  end)

  it("a file that does not parse is not shared", function()
    local ok = scrub("{not json", "/x")
    H.eq(false, ok)
  end)

  it("a missing projects table stays missing", function()
    local ok, out = scrub('{"numStartups":1}', "/x")
    H.ok(ok)
    H.eq(nil, out.projects)
  end)
end)

describe("a real sandbox", function()
  local home, project, tmp, login
  local function setup_home()
    home = vim.uv.os_homedir()
    login = vim.fn.readfile(home .. "/.claude/.credentials.json") -- the suite's fake login: put back afterwards
    project = H.tmpdir()
    tmp = H.tmpdir()
    local name = (vim.uv.fs_realpath(project)):gsub("[^%w]", "-")
    local function w(rel, text)
      vim.fn.mkdir(vim.fs.dirname(home .. "/.claude/" .. rel), "p")
      vim.fn.writefile({ text }, home .. "/.claude/" .. rel)
    end
    w(".credentials.json", '{"fake":"login"}')
    w("settings.json", "SETTINGS-CANARY")
    w("CLAUDE.md", "GLOBAL-INSTRUCTIONS-CANARY")
    w("history.jsonl", "HISTORY-CANARY")
    w("projects/-other-project/s.jsonl", "OTHER-TRANSCRIPT-CANARY")
    w("projects/" .. name .. "/mine.jsonl", "OWN-TRANSCRIPT")
    w("sessions/s1", "SESSION-CANARY")
    return name
  end
  local function run(script)
    H.need_sandbox()
    sb.config.network = "open"
    local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    return (r.stdout or "") .. (r.stderr or "")
  end
  after_each(function()
    if login then
      vim.fn.writefile(login, vim.uv.os_homedir() .. "/.claude/.credentials.json")
      login = nil
    end
    for _, f in ipairs({ "settings.json", "CLAUDE.md", "history.jsonl", "sessions", "projects/-other-project", "todos" }) do
      vim.fn.delete(vim.uv.os_homedir() .. "/.claude/" .. f, "rf")
    end
  end)

  it("the agent reads its login and its own transcripts, nothing else of ~/.claude", function()
    local name = setup_home()
    local out = run(('cd "$HOME/.claude" && cat .credentials.json; cat projects/%s/mine.jsonl; ls -A; ls -A projects; '
      .. 'for f in settings.json CLAUDE.md history.jsonl sessions/s1 projects/-other-project/s.jsonl; do cat "$f" 2>/dev/null; done; echo end'):format(name))
    H.match(out, '{"fake":"login"}', true, out)
    H.match(out, "OWN-TRANSCRIPT", true, out)
    for _, canary in ipairs({ "SETTINGS-CANARY", "GLOBAL-INSTRUCTIONS-CANARY", "HISTORY-CANARY", "OTHER-TRANSCRIPT-CANARY", "SESSION-CANARY" }) do
      H.no_match(out, canary, true, out)
    end
    H.no_match(out, "-other-project", true, "the other project's directory is not even listed")
    H.match(out, "end", true, out)
  end)

  it("the login is read-only, own transcripts persist, other writes vanish with the sandbox", function()
    local name = setup_home()
    run(('cd "$HOME/.claude" && (echo hacked > .credentials.json) 2>/dev/null; echo new > projects/%s/new.jsonl; mkdir todos; echo t > todos/t.json; echo x > planted.json'):format(name))
    H.eq({ '{"fake":"login"}' }, vim.fn.readfile(home .. "/.claude/.credentials.json"))
    H.eq({ "new" }, vim.fn.readfile(home .. "/.claude/projects/" .. name .. "/new.jsonl"))
    H.eq(0, vim.fn.filereadable(home .. "/.claude/planted.json"), "nothing else reaches the host")
    H.eq(0, vim.fn.isdirectory(home .. "/.claude/todos"))
  end)

  it("policy.claude_share shows a chosen file, read-only", function()
    setup_home()
    sb.config.policy = { claude_share = { "CLAUDE.md" } }
    local out = run('cat "$HOME/.claude/CLAUDE.md"; (echo x > "$HOME/.claude/CLAUDE.md") 2>&1; cat "$HOME/.claude/settings.json" 2>&1')
    H.match(out, "GLOBAL-INSTRUCTIONS-CANARY", true, out)
    H.no_match(out, "SETTINGS-CANARY", true, out)
    H.eq({ "GLOBAL-INSTRUCTIONS-CANARY" }, vim.fn.readfile(home .. "/.claude/CLAUDE.md"))
  end)
end)
