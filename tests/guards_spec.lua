-- Gaps closed in the real sandbox: absent project files (.envrc, .vscode/tasks.json) cannot be
-- planted, nested .git and workspace members deeper than before are read-only, and the
-- placeholders and temp files are cleaned up when the run ends.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")

local saved = vim.deepcopy(sb.config)
after_each(function()
  sb.config = vim.deepcopy(saved)
end)

local function mkdir(p) vim.fn.mkdir(p, "p") end

--- Run bash `script` in the sandbox of `project`; returns stdout+stderr, handle.
local function inside(project, script, keep_handle)
  H.need_sandbox()
  local tmp = H.tmpdir()
  local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, tmp)
  H.ok(cmd, err)
  local r = vim.system(cmd, { cwd = project, text = true }):wait(60000)
  if not keep_handle then
    h.release()
  end
  return (r.stdout or "") .. (r.stderr or ""), h
end

describe("absent project files", function()
  it(".envrc and .vscode/tasks.json cannot be created, .mise.toml and .mcp.json neither", function()
    local project = H.tmpdir()
    local out = inside(project, table.concat({
      'echo "export EVIL=1" > .envrc 2>/dev/null && echo PLANTED-ENVRC',
      'mkdir -p .vscode 2>/dev/null; echo "{}" > .vscode/tasks.json 2>/dev/null && echo PLANTED-TASKS',
      'echo x > .mise.toml 2>/dev/null && echo PLANTED-MISE',
      'echo x > .mcp.json 2>/dev/null && echo PLANTED-MCP',
      "echo done",
    }, "\n"))
    H.match(out, "done", true, out)
    for _, w in ipairs({ "PLANTED-ENVRC", "PLANTED-TASKS", "PLANTED-MISE", "PLANTED-MCP" }) do
      H.no_match(out, w, true, out)
    end
  end)

  it("after the run no placeholder is left behind, and ordinary files still work", function()
    local project = H.tmpdir()
    inside(project, "echo ok > normal.txt")
    H.eq(1, vim.fn.filereadable(project .. "/normal.txt"))
    for _, rel in ipairs({ ".envrc", ".mise.toml", ".mcp.json", ".nvim.lua", ".exrc", ".nvimrc", ".vscode", ".cargo", ".git", ".claude" }) do
      H.eq(nil, vim.uv.fs_stat(project .. "/" .. rel), rel .. " should not be left behind")
    end
  end)

  it("a real .envrc of the project is only locked, never emptied or removed", function()
    local project = H.tmpdir()
    vim.fn.writefile({ "export A=1" }, project .. "/.envrc")
    local out = inside(project, 'cat .envrc; echo x >> .envrc 2>/dev/null && echo WRITABLE; echo done')
    H.match(out, "export A=1", true)
    H.no_match(out, "WRITABLE", true)
    H.eq({ "export A=1" }, vim.fn.readfile(project .. "/.envrc"))
  end)

  it("a placeholder stays while another sandbox of the same project still runs, then goes", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local _, _, h1 = sb.wrap({ "true" }, project, tmp)
    local _, _, h2 = sb.wrap({ "true" }, project, tmp)
    -- simulate the bind mount points bwrap creates
    vim.fn.writefile({}, project .. "/.envrc")
    vim.uv.fs_chmod(project .. "/.envrc", tonumber("444", 8))
    mkdir(project .. "/.vscode")
    h1.release()
    H.ok(vim.uv.fs_stat(project .. "/.envrc"), "kept while the second sandbox lives")
    h2.release()
    H.eq(nil, vim.uv.fs_stat(project .. "/.envrc"))
    H.eq(nil, vim.uv.fs_stat(project .. "/.vscode"))
  end)

  it("release() is idempotent and never removes a file with content or a non-empty dir", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local _, _, h = sb.wrap({ "true" }, project, tmp)
    vim.fn.writefile({ "real" }, project .. "/.envrc")
    mkdir(project .. "/.vscode")
    vim.fn.writefile({ "{}" }, project .. "/.vscode/tasks.json")
    h.release()
    h.release()
    H.eq({ "real" }, vim.fn.readfile(project .. "/.envrc"))
    H.eq(1, vim.fn.filereadable(project .. "/.vscode/tasks.json"))
  end)
end)

describe("deeper nesting", function()
  it("a .git 6 levels down is read-only inside the sandbox", function()
    local project = H.tmpdir()
    local deep = project .. "/a/b/c/d/e/f"
    mkdir(deep .. "/.git")
    local out = inside(project, 'cd a/b/c/d/e/f && echo x > .git/config 2>/dev/null && echo WRITABLE; echo done')
    H.match(out, "done", true)
    H.no_match(out, "WRITABLE", true, out)
  end)

  it("a workspace member 5 levels down: its .cargo is locked, or masked when absent", function()
    local project = H.tmpdir()
    local m = project .. "/crates/x/y/z/member"
    mkdir(m)
    vim.fn.writefile({ "[package]" }, m .. "/Cargo.toml")
    local out = inside(project, 'cd crates/x/y/z/member && mkdir -p .cargo 2>/dev/null; echo "[build]" > .cargo/config.toml 2>/dev/null && echo PLANTED; echo done')
    H.match(out, "done", true)
    H.no_match(out, "PLANTED", true, out)
    H.eq(nil, vim.uv.fs_stat(m .. "/.cargo"), "the mask is removed afterwards")
  end)
end)

describe("temp files", function()
  it("the private copy of ~/.claude.json is deleted on release", function()
    H.need_sandbox()
    if not vim.uv.fs_stat(vim.uv.os_homedir() .. "/.claude.json") then
      return require("xynotest.harness").skip("no ~/.claude.json on this machine")
    end
    local project, tmp = H.tmpdir(), H.tmpdir()
    local _, _, h = sb.wrap({ "true" }, project, tmp)
    local copy = h.plan.claude_json and h.plan.claude_json.copy
    H.ok(copy and vim.uv.fs_stat(copy), "copy exists while running")
    h.release()
    H.eq(nil, vim.uv.fs_stat(copy))
  end)

  it("cleanup() releases every live sandbox", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    sb.wrap({ "true" }, project, tmp)
    sb.wrap({ "true" }, project, tmp)
    H.eq(2, sb.running())
    sb.cleanup()
    H.eq(0, sb.running())
  end)
end)

describe("known limits, kept visible", function()
  xfail("a .git the agent creates itself in a NEW deep directory is read-only",
    "only what exists at launch is locked: a fresh nested repository (git init in a new directory) can still be planted", function()
      local project = H.tmpdir()
      local out = inside(project, "mkdir -p fresh/sub && cd fresh/sub && git init -q . 2>/dev/null && echo 'x' >> .git/config && echo PLANTED")
      H.no_match(out, "PLANTED", true, out)
    end)
end)
