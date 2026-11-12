-- ONE spec for the policy tables: every entry of every hidden / read-only / masked / refused list is
-- effective in a REAL run (or, for the refusal list, in the real validation). The expected lists live in
-- tests/tables_expected.lua (a copy, written out in full): deleting an entry from lua/xyno_sandbox/plan.lua
-- therefore fails here even though the table loop would silently shrink with it. Adding an entry to plan.lua
-- without adding it to the copy fails the last test.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local EXPECT = dofile(H.repo .. "/tests/tables_expected.lua")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local DIRS = {
  [".cargo"] = true,
  [".vscode"] = true,
  [".zed"] = true,
  [".idea"] = true,
  [".helix"] = true,
  [".husky"] = true,
  [".devcontainer"] = true,
  [".mise"] = true,
  [".config/mise"] = true,
  [".claude"] = true,
  [".git"] = true,
  [".githooks"] = true,
  [".mvn"] = true,
  [".lefthook"] = true,
  [".cargo-husky"] = true,
  [".bundle"] = true,
}
local function is_dir_entry(rel, project_names)
  rel = rel:gsub("^/", "")
  if project_names then
    return DIRS[rel] or false
  end
  local base = vim.fs.basename(rel)
  if
    base:match("%.json$")
    or base:match("%.jsonl$")
    or base:match("%.toml$")
    or base:match("%.conf$")
    or base:match("%.md$")
  then
    return false
  end
  for _, f in ipairs({
    ".vault-token",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".Xauthority",
    ".pulse-cookie",
    "credentials",
    "adbkey",
    ".boto",
    "fish_history",
    ".lesshst",
  }) do
    if base == f then
      return false
    end
  end
  return true
end

local created = {}
local function mk(path, as_dir, canary)
  if uv.fs_lstat(path) then
    return false
  end
  if as_dir then
    vim.fn.mkdir(path, "p")
    local f = assert(io.open(path .. "/inner.txt", "w"))
    f:write(canary, "\n")
    f:close()
  else
    vim.fn.mkdir(vim.fs.dirname(path), "p")
    local f = assert(io.open(path, "w"))
    f:write(canary, "\n")
    f:close()
  end
  created[#created + 1] = path
  return true
end
local function cleanup()
  for i = #created, 1, -1 do
    vim.fn.delete(created[i], "rf")
  end
  created = {}
end

describe("every entry of the policy tables is effective in a real run", function()
  after_each(cleanup)

  it("the credential paths and globs under $HOME are hidden (home = denylist)", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "denylist", "open"
    local home = uv.os_homedir()
    local paths = {}
    for _, rel in ipairs(EXPECT.HIDDEN) do
      local p = home .. rel
      if mk(p, is_dir_entry(rel), "CANARY-" .. rel) then
        paths[#paths + 1] = p
      end
    end
    local globs = {
      ["/.*_history*"] = "/.xyno_r6_history",
      ["/.lesshst"] = "/.lesshst",
      ["/.config/fish/fish_history"] = "/.config/fish/fish_history",
    }
    for _, g in ipairs(EXPECT.HIDDEN_GLOBS) do
      local rel = assert(globs[g], "add a sample name for the glob " .. g)
      if mk(home .. rel, false, "CANARY-" .. g) then
        paths[#paths + 1] = home .. rel
      end
    end
    -- project secrets: directories, path suffixes, name globs
    local project = home .. "/t-tables-project"
    created[#created + 1] = project
    for _, d in ipairs(EXPECT.PROJECT_SECRET_DIRS) do
      mk(project .. "/" .. d, true, "CANARY-pd-" .. d)
      paths[#paths + 1] = project .. "/" .. d
    end
    for _, s in ipairs(EXPECT.PROJECT_SECRET_PATHS) do
      mk(project .. "/sub/" .. s, false, "CANARY-pp-" .. s)
      paths[#paths + 1] = project .. "/sub/" .. s
    end
    local except = {}
    for _, e in ipairs(plan.PROJECT_SECRET_EXCEPT) do
      except[e] = true
    end
    local n = 0
    for _, g in ipairs(EXPECT.PROJECT_SECRET_GLOBS) do
      local name = g:gsub("%*", "x")
      if not except[name] and not name:find("[%[%?]") then
        n = n + 1
        local p = project .. "/globs/" .. name
        if mk(p, false, "CANARY-pg-" .. g) then
          paths[#paths + 1] = p
        end
      end
    end
    H.ok(n > 100, "the glob table is not empty")
    local listing = table.concat(paths, "\n")
    local script = 'while IFS= read -r p; do if grep -rsl CANARY "$p" >/dev/null 2>&1; then echo "LEAK:$p"; fi; done <<\'EOF_LIST\'\n'
      .. listing
      .. "\nEOF_LIST\necho done"
    local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(120000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "done", true, out:sub(1, 2000))
    local leaks = {}
    for l in out:gmatch("LEAK:([^\n]+)") do
      leaks[#leaks + 1] = l
    end
    H.eq({}, leaks, "these paths were readable inside the sandbox")
  end)

  it("the read-only lists cannot be written, at the project root and in a subdirectory, and under ~/.claude", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "denylist", "open"
    local home = uv.os_homedir()
    local project = home .. "/t-tables-ro"
    created[#created + 1] = project
    local targets = {}
    local function plant(base, rel, as_dir)
      local p = base .. "/" .. rel:gsub("^/", "")
      mk(p, as_dir, "orig")
      targets[#targets + 1] = { p, as_dir }
    end
    for _, rel in ipairs(EXPECT.HOME_READONLY) do
      plant(
        home,
        rel,
        DIRS[rel:gsub("^/", "")]
          or rel:match("/hooks$")
          or rel:match("/commands$")
          or rel:match("/agents$")
          or rel:match("/skills$")
          or rel:match("/plugins$")
          or rel:match("/output%-styles$")
          or rel:match("/ide$")
          or rel:match("/rules$")
          or rel:match("/chrome$")
          or rel:match("/security$")
      )
    end
    for _, rel in ipairs(EXPECT.PROJECT_READONLY) do
      plant(project, rel, DIRS[rel] or false)
    end
    for _, rel in ipairs(EXPECT.MEMBER_READONLY) do
      plant(project .. "/sub", rel, DIRS[rel] or false)
    end
    local lines = {}
    for _, t in ipairs(targets) do
      if t[2] then
        lines[#lines + 1] = ("if touch '%s/new-file' 2>/dev/null; then echo 'WRITABLE:%s'; fi"):format(t[1], t[1])
      else
        lines[#lines + 1] = ("if echo pwn >> '%s' 2>/dev/null; then echo 'WRITABLE:%s'; fi"):format(t[1], t[1])
      end
    end
    -- absent names that must not be creatable at the project root
    for _, rel in ipairs(EXPECT.PROJECT_GUARD_FILES) do
      lines[#lines + 1] = ("if [ ! -e '%s' ] && ( : > '%s' ) 2>/dev/null; then echo 'CREATED:%s'; fi"):format(
        project .. "/" .. rel .. ".absent-check",
        project .. "/" .. rel,
        rel
      )
    end
    lines[#lines + 1] = "echo done"
    -- (the guard files / masks are only for ABSENT names: use a second project where none exists)
    local cmd, err, h = sb.wrap({ "bash", "-c", table.concat(lines, "\n") }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(120000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "done", true, out:sub(1, 2000))
    H.no_match(out, "WRITABLE:", true, out:sub(1, 3000))
  end)

  it("absent names of the guard lists cannot be created at the project root", function()
    H.need_sandbox()
    sb.config.home, sb.config.network = "denylist", "open"
    local project = uv.os_homedir() .. "/t-tables-absent"
    vim.fn.mkdir(project, "p")
    created[#created + 1] = project
    local lines = {}
    for _, rel in ipairs(EXPECT.PROJECT_GUARD_FILES) do
      lines[#lines + 1] = ("( : > '%s' ) 2>/dev/null && echo 'CREATED:%s'"):format(project .. "/" .. rel, rel)
    end
    for _, rel in ipairs(EXPECT.PROJECT_MASK_IF_ABSENT) do
      lines[#lines + 1] = ("mkdir '%s' 2>/dev/null && echo 'CREATED:%s'"):format(project .. "/" .. rel, rel)
    end
    lines[#lines + 1] = "echo done"
    local cmd, err, h = sb.wrap({ "bash", "-c", table.concat(lines, "\n") }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "done", true, out)
    H.no_match(out, "CREATED:", true, out)
  end)

  it("/run and /var/tmp are empty tmpfs mounts in the sandbox", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.tmpdir()
    local keep = {}
    for _, k in ipairs(plan.RUN_KEEP) do
      keep[vim.fs.basename(k)] = true
    end
    local cmd, err, h =
      sb.wrap({ "bash", "-c", "ls -A /run; echo ===; ls -A /var/tmp; echo done" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local run_part, vt_part = (r.stdout or ""):match("^(.-)===\n(.*)done")
    H.ok(run_part, r.stdout)
    for name in run_part:gmatch("[^\n]+") do
      H.ok(keep[name], "/run/" .. name .. " is visible")
    end
    H.eq("", vim.trim(vt_part))
    H.eq({ "/run", "/var/tmp" }, EXPECT.MASKED_SYSTEM)
  end)

  it("a writable approval is refused for every path that runs code outside the sandbox", function()
    local home = uv.os_homedir()
    local ctx = { home = home, probes = plan.real_probes(), state_dir = store.dir() }
    local bad = {}
    for _, rel in ipairs(EXPECT.CODE_RUNS_OUTSIDE) do
      local ok = plan.validate_exception({ kind = "writable", value = home .. rel }, ctx)
      if ok then
        bad[#bad + 1] = rel
      end
    end
    H.eq({}, bad, "writable approvals that were accepted")
    H.ok(#EXPECT.CODE_RUNS_OUTSIDE > 100)
  end)

  it("the expected lists are the tables of plan.lua (a new entry needs a line in tests/tables_expected.lua)", function()
    local code = {}
    for _, g in ipairs(plan.CODE_RUNS_OUTSIDE) do
      vim.list_extend(code, g.paths)
    end
    local actual = vim.tbl_extend("force", {}, {
      HIDDEN = plan.HIDDEN,
      HIDDEN_GLOBS = plan.HIDDEN_GLOBS,
      HOME_READONLY = plan.HOME_READONLY,
      PROJECT_READONLY = plan.PROJECT_READONLY,
      MEMBER_READONLY = plan.MEMBER_READONLY,
      PROJECT_SECRET_GLOBS = plan.PROJECT_SECRET_GLOBS,
      PROJECT_SECRET_DIRS = plan.PROJECT_SECRET_DIRS,
      PROJECT_SECRET_PATHS = plan.PROJECT_SECRET_PATHS,
      MASKED_SYSTEM = plan.MASKED_SYSTEM,
      PROJECT_GUARD_FILES = plan.PROJECT_GUARD_FILES,
      PROJECT_MASK_IF_ABSENT = plan.PROJECT_MASK_IF_ABSENT,
      CODE_RUNS_OUTSIDE = code,
    })
    for name, list in pairs(actual) do
      H.eq(EXPECT[name], list, name)
    end
  end)
end)
