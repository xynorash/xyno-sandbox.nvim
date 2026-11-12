-- The preview is generated from the same plan as the command line, so EVERY effect of the
-- command line shows up in it: each bind, tmpfs, setenv and flag. Red-team finding 6: the preview
-- left out `--ro-bind / /` (it said "Read-only (0) none") and `--tmpfs /tmp`.
-- This spec parses the real argv by itself (it does not use plan.ops) and diffs it against
-- ui.lines(plan).
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

local TAKES = {
  ["--bind"] = 2,
  ["--ro-bind"] = 2,
  ["--dev-bind"] = 2,
  ["--bind-try"] = 2,
  ["--ro-bind-try"] = 2,
  ["--symlink"] = 2,
  ["--setenv"] = 2,
  ["--unsetenv"] = 1,
  ["--tmpfs"] = 1,
  ["--dev"] = 1,
  ["--proc"] = 1,
  ["--remount-ro"] = 1,
  ["--mqueue"] = 1,
  ["--dir"] = 1,
  ["--chdir"] = 1,
  ["--cap-drop"] = 1,
  ["--cap-add"] = 1,
  ["--file"] = 2,
}

--- The effects of a command line, parsed from the tokens only: { {flag, args...}, ... } between
--- `bwrap` and the `--chdir`, flags without arguments grouped as { "--x" }.
local function parse(argv)
  local i = 1
  -- (bwrap is named by its absolute path in a real launch: the first token whose base name is bwrap)
  while i <= #argv and vim.fs.basename(argv[i]) ~= "bwrap" do
    i = i + 1
  end
  assert(i <= #argv, "no bwrap in the command line")
  i = i + 1
  local ops = {}
  while i <= #argv and argv[i] ~= "--chdir" do
    local f = argv[i]
    assert(f:sub(1, 2) == "--", "unexpected token before --chdir: " .. tostring(f))
    local n = TAKES[f] or 0
    local op = { f }
    for k = 1, n do
      op[#op + 1] = argv[i + k]
    end
    ops[#ops + 1] = op
    i = i + 1 + n
  end
  return ops
end

--- The text of an op as the "Mount order" section prints it.
local function render(op, p)
  local t = {}
  for k, a in ipairs(op) do
    if op[1] == "--setenv" and k == 3 then
      a = "<value not shown>"
    elseif p.empty_file and a == p.empty_file then
      a = "<empty file>"
    end
    t[#t + 1] = a
  end
  return table.concat(t, " ")
end

--- Lines of the "Mount order" section, in order.
local function mount_order(lines)
  local out, on = {}, false
  for _, l in ipairs(lines) do
    if l:match("^Mount order") then
      on = true
    elseif on then
      local rest = l:match("^%s+%d+%. (.*)$")
      if rest then
        out[#out + 1] = rest
      end
    end
  end
  return out
end

local function check(p, real_argv)
  local argv = real_argv or plan.argv(p)
  local ops = parse(argv)
  local lines = ui.lines(p, { full = true, home = "/nonexistent-home" })
  local text = table.concat(lines, "\n")
  -- 1. the isolation flags: all in the one line
  local iso = ops[1]
  H.eq("--die-with-parent", iso[1])
  local flags = {}
  local rest = {}
  for _, op in ipairs(ops) do
    if #op == 1 or op[1] == "--cap-drop" then
      for _, a in ipairs(op) do
        flags[#flags + 1] = a
      end
    else
      rest[#rest + 1] = op
    end
  end
  local isoline = text:match("Isolation  ([^\n]*)")
  H.eq(table.concat(flags, " "), isoline, "isolation flags in the preview")
  -- 2. every other option, in order, is the Mount order section
  local want = {}
  for _, op in ipairs(rest) do
    want[#want + 1] = render(op, p)
  end
  local got = mount_order(lines)
  H.eq(want, got, "the Mount order section must be the argv, option by option")
  -- 3. and every destination / variable name is findable
  for _, op in ipairs(rest) do
    local key = op[1] == "--setenv" and op[2] or op[1] == "--unsetenv" and op[2] or op[#op]
    H.match(text, key, true, "missing from the preview: " .. table.concat(op, " "))
  end
  return argv, ops, lines
end

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

local function fake(extra)
  local entries = vim.tbl_extend("force", {
    [HOME] = "directory",
    [HOME .. "/.claude"] = "directory",
    [PROJECT] = "directory",
    [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
    [HOME .. "/.ssh"] = "directory",
    [HOME .. "/.cargo"] = "directory",
    [PROJECT .. "/.env"] = "file",
    [PROJECT .. "/Cargo.toml"] = "file",
    [HOME .. "/.bash_history"] = "file",
    ["/run"] = "directory",
    ["/var/tmp"] = "directory",
    [PROJECT .. "/sub"] = "directory",
    [PROJECT .. "/sub/Cargo.toml"] = "file",
  }, extra or {})
  return {
    stat_type = function(p)
      return entries[p]
    end,
    lstat_type = function(p)
      return entries[p]
    end,
    exists = function(p)
      return entries[p] ~= nil
    end,
    list = function(dir)
      local out, prefix = {}, dir .. "/"
      for p, t in pairs(entries) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), t }
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
      for p in pairs(entries) do
        if p:match(lp) then
          out[#out + 1] = p
        end
      end
      table.sort(out)
      return out
    end,
    read_line = function()
      return nil
    end,
    realpath = function(p)
      return entries[p] and p or nil
    end,
  }
end

local function build(cfg, exceptions, env)
  return plan.build({
    project = PROJECT,
    tmp_dir = TMP,
    cwd = PROJECT,
    home = HOME,
    uid = 1000,
    probes = fake(),
    env = vim.tbl_extend(
      "force",
      { PATH = "/usr/bin", GITHUB_TOKEN = "x", MY_API_KEY = "y", TERM = "xterm" },
      env or {}
    ),
    cmd = { "agent", "--dangerously-skip-permissions", "-p", "the prompt" },
    aux = { empty = "/aux/empty", claude_json = "/aux/cj", net_dir = "/aux/net" },
    config = cfg,
    exceptions = exceptions or {},
  })
end

describe("preview == argv", function()
  for _, home in ipairs({ "allowlist", "denylist" }) do
    for _, net in ipairs({ "open", "filtered" }) do
      it(
        ("home = %s, network = %s: every bind, tmpfs, setenv and flag of the command line is in the preview"):format(
          home,
          net
        ),
        function()
          check(build({ home = home, network = net }))
        end
      )
    end
  end

  it("with exceptions applied (writable, unhide, env, host) the preview still equals the argv", function()
    local p = build({ home = "denylist", network = "filtered" }, {
      { kind = "unhide", value = HOME .. "/.ssh", scope = "once" },
      { kind = "env", value = "GITHUB_TOKEN", scope = "once" },
      { kind = "writable", value = HOME .. "/.cargo", scope = "once" },
      { kind = "host", value = "github.com", scope = "once" },
    })
    check(p)
  end)

  it(
    "the old omissions are named explicitly: --ro-bind / /, --tmpfs /tmp, --dev, --proc, the masked sockets",
    function()
      local p = build({ home = "allowlist", network = "open" })
      local text = table.concat(ui.lines(p), "\n")
      for _, needle in ipairs({
        "--ro-bind / /",
        "--tmpfs /tmp",
        "--dev /dev",
        "--proc /proc",
        "--tmpfs /run",
        "--tmpfs /var/tmp",
        "--tmpfs " .. HOME,
      }) do
        H.match(text, needle, true, needle .. " missing from the default preview")
      end
      H.no_match(text, "Read-only (0)\n  none\n\nAbsent", true)
    end
  )

  it("a real plan of this machine equals its real wrapped command", function()
    if sb.status_blocking().mode ~= "bwrap" then
      return require("xynotest.harness").skip("needs a working bwrap")
    end
    local project, tmp = H.fixture("basic", { git = true }), H.tmpdir()
    vim.fn.writefile({ "K=v" }, project .. "/.env")
    local p = sb.plan({ "agent", "-p", "prompt" }, project, tmp)
    local wrapped, err, h = sb.wrap(p.agent.cmd, project, tmp, { plan = p })
    H.ok(wrapped, err)
    H.eq(sb.argv(p), wrapped)
    check(p)
    h.release()
  end)

  it("the check bites: a preview that drops a mount, a tmpfs or a setenv fails the diff", function()
    local p = build({ home = "allowlist", network = "filtered" })
    local argv = plan.argv(p)
    local real = plan.ops
    -- a plan whose preview forgets the base mounts (the red team's finding), by removing them from the ops the UI sees
    local function without(section)
      plan.ops = function(pl)
        return vim.tbl_filter(function(o)
          return o.section ~= section
        end, real(pl))
      end
    end
    for _, section in ipairs({ "base", "setenv", "sockets", "home" }) do
      without(section)
      local ok = pcall(check, p, argv)
      plan.ops = real
      H.not_ok(ok, "dropping '" .. section .. "' from the preview must be noticed")
    end
    H.eq(argv, plan.argv(p))
  end)
end)
