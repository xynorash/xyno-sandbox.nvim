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
