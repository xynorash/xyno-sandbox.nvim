-- plan.build / plan.argv: the pure argument plan. No disk, no bwrap: a table-backed fake
-- filesystem goes in through `probes`, the environment is a plain table.
local H = require("xynotest.helpers")
local plan = require("xyno_sandbox.plan")

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

--- A fake filesystem: paths -> "directory"|"file"; `lines` = first lines of files.
local function fakefs(entries, lines)
  local fs = {}
  for p, t in pairs(entries) do
    fs[p] = t
  end
  local probes = {
    stat_type = function(p) return fs[p] end,
    exists = function(p) return fs[p] ~= nil end,
    list = function(dir)
      local out, prefix = {}, dir == "/" and "/" or (dir .. "/")
      for p, t in pairs(fs) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), t }
        end
      end
      table.sort(out, function(a, b) return a[1] < b[1] end)
      return out
    end,
    glob = function(pat)
      local out = {}
      local lua_pat = "^" .. pat:gsub("[%-%.%+%[%]%(%)%$%^%%]", "%%%0"):gsub("%*", "[^/]*") .. "$"
      for p in pairs(fs) do
        if p:match(lua_pat) then
          out[#out + 1] = p
        end
      end
      table.sort(out)
      return out
    end,
    read_line = function(p) return (lines or {})[p] end,
    realpath = function(p) return fs[p] and p or nil end,
  }
  return probes, fs
end

local BASE = {
  [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
  [PROJECT .. "/.git"] = "directory",
}

local function input(over, fs_entries, lines)
  local entries = vim.tbl_extend("force", BASE, fs_entries or {})
  for k, v in pairs(entries) do
    if v == false then
      entries[k] = nil -- `false` removes a path of BASE
    end
  end
  local probes = fakefs(entries, lines)
  over = over or {}
  if over.config and over.config.network == nil then
    over.config = vim.tbl_extend("force", { network = "open" }, over.config) -- these specs pin the filesystem policy
  end
  return vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = probes,
    env = { PATH = "/bin", HOME = HOME, GITHUB_TOKEN = "SECRET-VALUE-1", MY_API_KEY = "SECRET-VALUE-2" },
    cmd = { "agent", "--dangerously-skip-permissions", "-p", "do it" },
    aux = { empty = "/aux/empty", claude_json = "/aux/claude.json" },
    config = { network = "open" },
  }, over)
end

local function paths(list)
  local out = {}
  for _, e in ipairs(list) do
    out[#out + 1] = type(e) == "table" and e.path or e
  end
  return out
end

describe("plan.build is pure", function()
  it("the same input gives the same plan and the same argv, twice", function()
    local a = plan.build(input())
    local b = plan.build(input())
    H.eq(a, b)
    H.eq(plan.argv(a), plan.argv(b))
  end)

  it("does not touch the filesystem: fake paths that exist nowhere are enough", function()
    H.eq(0, vim.fn.isdirectory(PROJECT))
    local p = plan.build(input())
    H.has(paths(p.writable), PROJECT)
    H.has(paths(p.writable), TMP)
  end)

  it("does not mutate its input", function()
    local inp = input({ exceptions = { { kind = "env", value = "GITHUB_TOKEN" } } })
    local before = vim.deepcopy(inp.env)
    plan.build(inp)
    H.eq(before, inp.env)
  end)
end)

describe("plan contents", function()
  it("lists project and scratch as writable, the project's .git as locked", function()
    local p = plan.build(input())
    H.eq({ PROJECT, TMP, HOME .. "/.claude" }, paths(p.writable))
    H.eq({ PROJECT .. "/.git" }, p.git_locked)
    H.eq("open", p.network)
  end)

  it("hidden credential paths: dirs as tmpfs, files as empty files, only the existing ones", function()
    local p = plan.build(input({}, {
      [HOME .. "/.ssh"] = "directory", [HOME .. "/.netrc"] = "file", [HOME .. "/.bash_history"] = "file",
    }))
    local by = {}
    for _, h in ipairs(p.hidden) do
      by[h.path] = h.kind
    end
    H.eq("dir", by[HOME .. "/.ssh"])
    H.eq("file", by[HOME .. "/.netrc"])
    H.eq("file", by[HOME .. "/.bash_history"], "history globs")
    H.eq(nil, by[HOME .. "/.aws"], "absent ones are not listed")
    local a = plan.argv(p)
    H.has(a, "--tmpfs")
    local i
    for k = 1, #a - 2 do
      if a[k] == "--ro-bind" and a[k + 2] == HOME .. "/.netrc" then
        i = k
      end
    end
    H.eq("/aux/empty", a[i + 1])
  end)

  it("stripped env var NAMES only: values appear nowhere in the plan or the argv", function()
    local p = plan.build(input())
    H.eq({ "GITHUB_TOKEN", "MY_API_KEY" }, p.env_strip)
    local dump = vim.inspect(p) .. table.concat(plan.argv(p), " ")
    H.no_match(dump, "SECRET-VALUE", true)
  end)

  it("file-based login keeps no claude auth var; env login keeps them", function()
    local env = { ANTHROPIC_API_KEY = "x" }
    local file = plan.build(input({ env = env }, { [HOME .. "/.claude/.credentials.json"] = "file" }))
    H.eq({ "ANTHROPIC_API_KEY" }, file.env_strip)
    H.eq({}, plan.build(input({ env = env })).env_strip)
  end)

  it("the argv is the plan: every section shows up in it", function()
    local p = plan.build(input({}, { [HOME .. "/.ssh"] = "directory" }))
    local a = plan.argv(p)
    H.eq("bwrap", a[1])
    for _, w in ipairs(p.writable) do
      H.has(table.concat(a, "\0"), "--bind\0" .. w.path .. "\0" .. w.path)
    end
    for _, n in ipairs(p.env_strip) do
      H.has(table.concat(a, "\0"), "--unsetenv\0" .. n)
    end
    H.eq({ "--chdir", PROJECT, "--", "agent", "--dangerously-skip-permissions", "-p", "do it" }, vim.list_slice(a, #a - 6))
  end)

  it("masks absent project dirs and guards absent project files (.envrc, .vscode)", function()
    local p = plan.build(input({}, { [PROJECT .. "/.git"] = false }))
    local masked = paths(p.masks)
    H.has(masked, PROJECT .. "/.git")
    H.has(masked, PROJECT .. "/.cargo")
    H.has(masked, PROJECT .. "/.vscode", "absent .vscode: tasks.json cannot be planted")
    H.has(masked, PROJECT .. "/.claude")
    H.has(paths(p.guard_files), PROJECT .. "/.envrc")
    H.has(paths(p.guard_files), PROJECT .. "/.mise.toml")
    local a = table.concat(plan.argv(p), "\0")
    H.has(a, "--ro-bind\0/aux/empty\0" .. PROJECT .. "/.envrc")
    H.has(a, "--tmpfs\0" .. PROJECT .. "/.vscode\0--remount-ro\0" .. PROJECT .. "/.vscode")
  end)

  it("a present .envrc / .vscode is locked instead of guarded", function()
    local p = plan.build(input({}, { [PROJECT .. "/.envrc"] = "file", [PROJECT .. "/.vscode"] = "directory",
      [PROJECT .. "/.vscode/tasks.json"] = "file" }))
    H.has(paths(p.readonly), PROJECT .. "/.envrc")
    H.has(paths(p.readonly), PROJECT .. "/.vscode")
    H.not_ok(vim.tbl_contains(paths(p.guard_files), PROJECT .. "/.envrc"))
    H.not_ok(vim.tbl_contains(paths(p.masks), PROJECT .. "/.vscode"))
  end)

  it("the project at $HOME gets no project-relative locks or guards", function()
    local p = plan.build(input({ project = HOME, cwd = HOME }))
    H.eq({ TMP, HOME .. "/.claude" }, paths(p.writable), "never $HOME itself")
    H.eq({}, p.guard_files)
    for _, m in ipairs(p.masks) do
      H.match(m.path, HOME .. "/.claude/", true)
    end
  end)
end)

describe("nested git directories and members", function()
  local function nest(levels, leaf)
    local parts = {}
    for i = 1, levels do
      parts[#parts + 1] = "d" .. i
    end
    local d = PROJECT
    local entries = {}
    for _, seg in ipairs(parts) do
      d = d .. "/" .. seg
      entries[d] = "directory"
    end
    entries[d .. "/" .. leaf] = "directory"
    return entries, d
  end

  it("locks a .git 7 levels down (was: only 2)", function()
    local entries, d = nest(7, ".git")
    local p = plan.build(input({}, entries))
    H.has(p.git_locked, d .. "/.git")
  end)

  it("locks .cargo of a workspace member 6 levels down and masks a member without one", function()
    local entries, d = nest(6, ".cargo")
    entries[d .. "/Cargo.toml"] = "file"
    local p = plan.build(input({}, entries))
    H.has(paths(p.readonly), d .. "/.cargo")
    local entries2, d2 = nest(5, "src")
    entries2[d2 .. "/Cargo.toml"] = "file"
    local p2 = plan.build(input({}, entries2))
    H.has(paths(p2.masks), d2 .. "/.cargo")
  end)

  it("stops at the scan depth, and policy.scan_depth moves it", function()
    local entries, d = nest(10, ".git")
    local p = plan.build(input({}, entries))
    H.not_ok(vim.tbl_contains(p.git_locked, d .. "/.git"))
    local p2 = plan.build(input({ config = { policy = { scan_depth = 12 } } }, entries))
    H.has(p2.git_locked, d .. "/.git")
  end)

  it("says so when the walk is truncated", function()
    local old = plan.SCAN_MAX_DIRS
    plan.SCAN_MAX_DIRS = 3
    local entries = {}
    for i = 1, 10 do
      entries[PROJECT .. "/m" .. i] = "directory"
    end
    local p = plan.build(input({}, entries))
    plan.SCAN_MAX_DIRS = old
    H.match(p.notes[1], "stopped after", true)
  end)

  it("skips target, node_modules and hidden dirs for members", function()
    local p = plan.build(input({}, {
      [PROJECT .. "/target"] = "directory", [PROJECT .. "/target/x"] = "directory", [PROJECT .. "/target/x/.cargo"] = "directory",
      [PROJECT .. "/.hid"] = "directory", [PROJECT .. "/.hid/.cargo"] = "directory",
    }))
    H.not_ok(vim.tbl_contains(paths(p.readonly), PROJECT .. "/target/x/.cargo"))
    H.not_ok(vim.tbl_contains(paths(p.readonly), PROJECT .. "/.hid/.cargo"))
  end)
end)

describe("--dangerously-skip-permissions", function()
  it("is reported in plan.agent", function()
    local p = plan.build(input())
    H.eq(true, p.agent.skip_permissions)
    H.eq("--dangerously-skip-permissions", p.agent.flag)
    H.eq(false, plan.build(input({ cmd = { "agent", "-p", "x" } })).agent.skip_permissions)
  end)

  it("strip_skip_permissions removes the flag from the command and says so", function()
    local p = plan.build(input({ config = { strip_skip_permissions = true } }))
    H.eq({ "agent", "-p", "do it" }, p.agent.cmd)
    H.eq(false, p.agent.skip_permissions)
    H.eq(true, p.agent.stripped)
    H.not_ok(vim.tbl_contains(plan.argv(p), "--dangerously-skip-permissions"))
  end)
end)

describe("policy lists", function()
  it("policy.readonly locks extra project-relative and absolute paths when present", function()
    local p = plan.build(input({ config = { policy = { readonly = { "deploy.sh", "/h/shared/x", "~/.toolrc", "missing" } } } },
      { [PROJECT .. "/deploy.sh"] = "file", ["/h/shared/x"] = "file", [HOME .. "/.toolrc"] = "file" }))
    H.has(paths(p.readonly), PROJECT .. "/deploy.sh")
    H.has(paths(p.readonly), "/h/shared/x")
    H.has(paths(p.readonly), HOME .. "/.toolrc")
    H.not_ok(vim.tbl_contains(paths(p.readonly), PROJECT .. "/missing"))
  end)

  it("policy.writable and policy.hidden add existing paths", function()
    local p = plan.build(input({ config = { policy = { writable = { "/data/out" }, hidden = { "~/.secrets", "/data/priv" } } } },
      { ["/data"] = "directory", ["/data/out"] = "directory", [HOME .. "/.secrets"] = "directory", ["/data/priv"] = "file" }))
    H.has(paths(p.writable), "/data/out")
    H.has(paths(p.hidden), HOME .. "/.secrets")
    H.has(paths(p.hidden), "/data/priv")
  end)

  it("policy.scrub adds env names by contains, prefix and exact", function()
    local p = plan.build(input({
      env = { PATH = "x", MYCORP_THING = "1", INTERNAL_FOO = "1", ZED = "1", plain = "1" },
      config = { policy = { scrub = { contains = { "corp" }, prefix = { "internal_" }, exact = { "zed" } } } },
    }))
    H.eq({ "INTERNAL_FOO", "MYCORP_THING", "ZED" }, p.env_strip)
  end)

  it("policy.guard_files / guard_dirs guard more absent names", function()
    local p = plan.build(input({ config = { policy = { guard_files = { "run.sh" }, guard_dirs = { ".idea" } } } }))
    H.has(paths(p.guard_files), PROJECT .. "/run.sh")
    H.has(paths(p.masks), PROJECT .. "/.idea")
  end)
end)

describe("exceptions in the plan", function()
  it("env: the variable is kept and listed as an exception, nothing else changes", function()
    local base = plan.build(input())
    local p = plan.build(input({ exceptions = { { kind = "env", value = "MY_API_KEY", scope = "once" } } }))
    H.eq({ "GITHUB_TOKEN" }, p.env_strip)
    H.eq({ "MY_API_KEY" }, p.env_kept)
    H.eq({ { kind = "env", value = "MY_API_KEY", scope = "once" } }, p.exceptions)
    H.eq(base.writable, p.writable)
    H.eq(base.hidden, p.hidden)
  end)

  it("unhide drops exactly that hidden entry", function()
    local fs = { [HOME .. "/.ssh"] = "directory", [HOME .. "/.aws"] = "directory" }
    local p = plan.build(input({ exceptions = { { kind = "unhide", value = HOME .. "/.aws" } } }, fs))
    H.eq({ HOME .. "/.ssh" }, paths(p.hidden))
  end)

  it("writable adds an existing path; unknown paths and the dangerous ones are rejected", function()
    local fs = { ["/data"] = "directory" }
    local p = plan.build(input({ exceptions = {
      { kind = "writable", value = "/data" }, { kind = "writable", value = "/nope" },
      { kind = "writable", value = "/" }, { kind = "writable", value = HOME }, { kind = "writable", value = "/data/../etc" },
      { kind = "env", value = "bad name" }, { kind = "frob", value = "x" },
    } }, fs))
    H.has(paths(p.writable), "/data")
    H.eq(1, #p.exceptions)
    H.eq(6, #p.rejected)
  end)

  it("a writable exception cannot cover the approvals themselves", function()
    local ok, why = plan.validate_exception({ kind = "writable", value = HOME .. "/.local/state/nvim" },
      { home = HOME, state_dir = HOME .. "/.local/state/nvim/xyno-sandbox", probes = fakefs({ [HOME .. "/.local/state/nvim"] = "directory" }) })
    H.eq(false, ok)
    H.match(why, "approvals", true)
  end)

  it("a plan built without the refused exception equals the plan built before it", function()
    local before = plan.build(input())
    local after = plan.build(input({ exceptions = {} }))
    H.eq(before, after)
  end)
end)
