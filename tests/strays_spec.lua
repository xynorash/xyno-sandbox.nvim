-- Stray placeholder files. Empty .git/.envrc/.exrc/.mcp.json/.mise.toml (and .nvim.lua, .nvimrc,
-- .cargo, .claude, .vscode) appeared in /tmp during red-team sessions and broke unrelated specs
-- (a stray /tmp/.git makes every tool think /tmp is a repository).
--
-- Cause: bwrap creates the mount point of a guard (the empty read-only .envrc, the .git mask, ...)
-- in the real project directory. Two paths left them behind:
--   1. a project that is a shared directory such as /tmp: the guards were created directly in it,
--      for every sandbox started there, and any not-released run kept them;
--   2. a Neovim that died (kill, crash) between wrap() and handle.release() never removed them.
-- Fixes: shared directories (/tmp, /var/tmp, /run, /, $HOME's parents, ...) are not mounted
-- writable and get no placeholders; every launch records its placeholders in the live registry and
-- the next launch removes the ones of a dead Neovim that are still empty.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local STRAYS = { ".git", ".envrc", ".exrc", ".mcp.json", ".mise.toml", ".nvim.lua", ".nvimrc", ".cargo", ".claude", ".vscode" }

local function snapshot(dir)
  local out = {}
  for _, n in ipairs(STRAYS) do
    out[n] = vim.uv.fs_lstat(dir .. "/" .. n) ~= nil
  end
  return out
end

--- A pid that is certainly dead.
local function dead_pid()
  local r = vim.system({ "true" }):wait()
  local pid
  local obj = vim.system({ "sh", "-c", "echo $$" }, { text = true }):wait()
  pid = tonumber(vim.trim(obj.stdout or ""))
  H.ok(pid and r.code == 0)
  H.ok(vim.uv.kill(pid, 0) ~= 0, "the pid is gone")
  return pid
end

local function placeholder(dir, rel, kind)
  if kind == "dir" then
    vim.fn.mkdir(dir .. "/" .. rel, "p")
  else
    vim.fn.writefile({}, dir .. "/" .. rel)
    vim.uv.fs_chmod(dir .. "/" .. rel, tonumber("444", 8))
  end
end

describe("a shared directory as the project", function()
  it("creates no placeholders and no writable bind: plans for /tmp, /var/tmp, /run, / and $HOME's parent", function()
    for _, shared in ipairs({ "/tmp", "/var/tmp", "/dev/shm", "/run", "/", "/home", "/var" }) do
      local p = sb.plan({ "agent" }, shared, H.tmpdir())
      H.eq({}, p.guard_files, shared)
      for _, m in ipairs(p.masks) do
        H.not_ok(m.cleanup, shared .. " got a project placeholder: " .. m.path)
        H.not_ok(m.path:sub(1, #shared + 1) == shared .. "/" and shared ~= "/" and m.path:match("^" .. vim.pesc(shared) .. "/%.[%w]+$"),
          shared .. " got a mask directly inside: " .. m.path)
      end
      for _, w in ipairs(p.writable) do
        H.not_ok(w.why == "project", shared .. " mounted writable")
      end
      local text = table.concat(plan.argv(p), "\0")
      for _, n in ipairs({ ".git", ".envrc", ".mcp.json" }) do
        H.no_match(text, "\0" .. (shared == "/" and "" or shared) .. "/" .. n .. "\0", true, shared .. "/" .. n)
      end
      H.match(table.concat(p.notes, "\n"), "shared system directory", true, shared)
    end
  end)

  it("a real run with /tmp as the project leaves /tmp exactly as it was", function()
    H.need_sandbox()
    sb.config.network = "open"
    local before = snapshot("/tmp")
    local tmp = H.tmpdir()
    local cmd, err, h = sb.wrap({ "bash", "-c", "echo x > /tmp/created-inside 2>/dev/null; echo done" }, "/tmp", tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = "/tmp" }):wait(60000)
    h.release()
    H.match(r.stdout or "", "done", true, (r.stdout or "") .. (r.stderr or ""))
    H.eq(before, snapshot("/tmp"), "nothing was created in /tmp")
    H.eq(nil, vim.uv.fs_stat("/tmp/created-inside"), "and the agent could not write to the host's /tmp")
  end)

  it("a project below a shared directory still gets its placeholders (they are removed on release)", function()
    local project = H.tmpdir()
    local p = sb.plan({ "agent" }, project, H.tmpdir())
    H.ok(#p.guard_files > 0 and #p.masks > 0)
  end)
end)

describe("placeholders of a Neovim that died", function()
  it("are removed by the next launch while they are still empty; a file that got content stays", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    placeholder(project, ".envrc", "file")
    placeholder(project, ".mcp.json", "file")
    placeholder(project, ".vscode", "dir")
    placeholder(project, ".cargo", "dir")
    vim.fn.writefile({ "real = content" }, project .. "/.exrc")
    vim.fn.mkdir(store.dir() .. "/live", "p")
    local pid = dead_pid()
    local items = {
      { project .. "/.envrc", "file" }, { project .. "/.mcp.json", "file" }, { project .. "/.vscode", "dir" },
      { project .. "/.cargo", "dir" }, { project .. "/.exrc", "file" },
    }
    local lines = { project }
    for _, it in ipairs(items) do
      lines[#lines + 1] = it[2] .. "\t" .. it[1]
    end
    vim.fn.writefile(lines, store.dir() .. "/live/" .. pid .. "-1-1")
    sb.config.network = "open"
    local _, _, h = sb.wrap({ "true" }, H.tmpdir(), tmp) -- any launch sweeps
    h.release()
    for _, rel in ipairs({ ".envrc", ".mcp.json", ".vscode", ".cargo" }) do
      H.eq(nil, vim.uv.fs_lstat(project .. "/" .. rel), rel .. " should have been swept")
    end
    H.eq({ "real = content" }, vim.fn.readfile(project .. "/.exrc"), "content is never touched")
    H.eq(nil, vim.uv.fs_stat(store.dir() .. "/live/" .. pid .. "-1-1"), "the dead registration is dropped")
  end)

  it("end to end: a crashed launch (no release) is cleaned by the next one", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd, err)
    H.eq(0, vim.system(cmd, { cwd = project }):wait(60000).code)
    local made = snapshot(project)
    H.ok(made[".envrc"] and made[".git"] and made[".mcp.json"], "bwrap left its mount points in the project")
    -- the Neovim that started it dies: its registration belongs to a dead pid, release() never runs
    local live = store.dir() .. "/live"
    local pid = dead_pid()
    for name in vim.fs.dir(live) do
      vim.uv.fs_rename(live .. "/" .. name, live .. "/" .. pid .. "-" .. name:gsub("^%d+%-", ""))
    end
    local _, _, h2 = sb.wrap({ "true" }, H.tmpdir(), tmp)
    h2.release()
    h.release() -- (this process's handle; its registration is gone, the files are already swept)
    H.eq(snapshot(project), vim.tbl_map(function() return false end, made), "all placeholders swept")
  end)

  it("a live sandbox of the same project keeps the placeholders it still mounts", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local _, _, live = sb.wrap({ "true" }, project, tmp) -- registered by THIS (live) process
    placeholder(project, ".envrc", "file")
    local pid = dead_pid()
    vim.fn.writefile({ project, "file\t" .. project .. "/.envrc" }, store.dir() .. "/live/" .. pid .. "-9-9")
    local _, _, h2 = sb.wrap({ "true" }, H.tmpdir(), tmp)
    H.ok(vim.uv.fs_lstat(project .. "/.envrc"), "kept: another sandbox of the project still runs")
    h2.release()
    live.release()
    H.eq(nil, vim.uv.fs_lstat(project .. "/.envrc"), "removed once the last one is released")
  end)
end)
