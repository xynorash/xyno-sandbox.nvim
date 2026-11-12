-- Git write mode (policy.git_write): the agent can git add / git commit, hooks, config and info stay read-only.
-- Default stays locked. Real bubblewrap runs.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local harness = require("xynotest.harness")

local saved = vim.deepcopy(sb.config)
after_each(function()
  sb.config = vim.deepcopy(saved)
end)

local function inside(script, project, policy)
  H.need_sandbox()
  sb.config.network = "open"
  sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, policy or {})
  local tmp = H.tmpdir()
  local wrapped, err, h = sb.wrap({ "bash", "-c", script }, project, tmp)
  H.ok(wrapped, err)
  local r = vim.system(wrapped, { text = true, cwd = project }):wait(120000)
  h.release()
  return (r.stdout or "") .. (r.stderr or ""), r
end

local COMMIT =
  'cd "$P" && echo change >> README.md && git add README.md && git -c user.name=agent -c user.email=a@example.invalid commit -q -m "by agent" 2>&1 && git log --oneline | head -3'

describe("git write mode", function()
  before_each(function()
    if vim.fn.executable("git") ~= 1 then
      harness.skip("git not installed")
    end
  end)

  it(
    "default: the project's .git is read-only, so a commit from inside the sandbox fails (documented, safe)",
    function()
      local project = H.fixture("basic", { git = true })
      local out, r = inside("P=" .. project .. "; " .. COMMIT, project)
      H.not_ok(r.code == 0, "a commit must not succeed with the locked .git: " .. out)
      H.match(out:lower(), "read%-only", false)
      H.no_match(out, "by agent", true)
      local log = vim.system({ "git", "-C", project, "log", "--oneline" }, { text = true }):wait().stdout
      H.no_match(log, "by agent", true)
    end
  )

  it("git_write = true: add and commit work, the commit is in the real repository", function()
    local project = H.fixture("basic", { git = true })
    local out, r = inside(
      "P=" .. project .. "; git config user.name >/dev/null 2>&1 || true; " .. COMMIT,
      project,
      { git_write = true }
    )
    H.eq(0, r.code, out)
    local log = vim.system({ "git", "-C", project, "log", "--oneline" }, { text = true }):wait().stdout
    H.match(log, "by agent", true)
  end)

  it(
    "git_write = true: hooks, config and info stay locked (nothing the next unsandboxed git would run can be planted)",
    function()
      local project = H.fixture("basic", { git = true })
      local config_before = table.concat(vim.fn.readfile(project .. "/.git/config"), "\n")
      local script = table.concat({
        "P=" .. project .. "; cd $P",
        "echo 'echo pwned' > .git/hooks/pre-commit 2>&1; echo hook=$?",
        "echo '[core]' >> .git/config 2>&1; echo config=$?",
        "echo 'x' >> .git/info/exclude 2>&1; echo info=$?",
        "echo 'x' > .git/info/attributes 2>&1; echo attrs=$?",
        "git config core.fsmonitor 'touch /tmp/x' 2>&1; echo gitconfig=$?",
        "rm -rf .git/hooks 2>&1; echo rmhooks=$?",
        "mv .git/config .git/config.old 2>&1; echo mvconfig=$?",
        "ls .git/hooks >/dev/null 2>&1; echo hooks_still=$?",
      }, "\n")
      local out = inside(script, project, { git_write = true })
      for _, k in ipairs({ "hook", "config", "info", "attrs", "gitconfig", "rmhooks", "mvconfig" }) do
        H.no_match(out, "\n" .. k .. "=0", true, k .. " must be refused:\n" .. out)
        H.match(out, k .. "=", true, out)
      end
      H.match(out, "hooks_still=0", true, out)
      H.eq(
        config_before,
        table.concat(vim.fn.readfile(project .. "/.git/config"), "\n"),
        "config untouched on the host"
      )
      H.eq(0, vim.fn.filereadable(project .. "/.git/hooks/pre-commit"), "no planted hook")
    end
  )

  describe("what git write mode must not let the agent plant (the .git directory is rebuilt or redirected)", function()
    -- the host's own check: an UNSANDBOXED git in the project must run nothing of the agent's
    local function host_git_runs_nothing(project, canary)
      vim.system({ "git", "-C", project, "status" }, { text = true }):wait()
      H.eq(0, vim.fn.filereadable(canary), "an unsandboxed git status ran the agent's command")
    end

    it(".git itself is a mount point: it cannot be renamed and rebuilt with a hook and a config", function()
      local project = H.fixture("basic", { git = true })
      local canary = H.tmpdir() .. "/FSRAN"
      local ino = vim.uv.fs_stat(project .. "/.git").ino
      local script = table.concat({
        "P=" .. project .. "; cd $P",
        "mv .git .git.old 2>&1; echo mv=$?",
        "mkdir .git 2>&1; echo mkdir=$?",
        "cp -a .git.old/. .git/ 2>&1; echo cp=$?",
        "printf '#!/bin/sh\\ntouch " .. canary .. "\\n' > .git/hooks/pre-commit 2>&1; echo hook=$?",
        "git config core.fsmonitor 'touch " .. canary .. "' 2>&1; echo gitconfig=$?",
        "rmdir .git 2>&1; echo rmdir=$?",
      }, "\n")
      local out = inside(script, project, { git_write = true })
      H.no_match(out, "\nmv=0", true, "mv .git must be refused:\n" .. out)
      H.eq(ino, vim.uv.fs_stat(project .. "/.git").ino, "the same .git directory is still there")
      H.eq(0, vim.fn.isdirectory(project .. "/.git.old"), "no renamed copy on the host")
      H.eq(0, vim.fn.filereadable(project .. "/.git/hooks/pre-commit"), "no planted hook")
      H.no_match(table.concat(vim.fn.readfile(project .. "/.git/config"), "\n"), "fsmonitor", true)
      host_git_runs_nothing(project, canary)
    end)

    it("commondir cannot be written: no other common directory (with its own config) can be pointed to", function()
      local project = H.fixture("basic", { git = true })
      local canary = H.tmpdir() .. "/FSRAN2"
      local script = table.concat({
        "P=" .. project .. "; cd $P",
        "mkdir evilcommon && cp -a .git/objects .git/refs .git/HEAD evilcommon/",
        "printf '[core]\\n\\tfsmonitor = touch " .. canary .. "\\n' > evilcommon/config",
        "echo ../evilcommon > .git/commondir 2>&1; echo commondir=$?",
        "rm -f .git/commondir 2>&1; echo rm=$?",
        "git status >/dev/null 2>&1; echo gitstatus=$?",
      }, "\n")
      local out = inside(script, project, { git_write = true })
      H.no_match(out, "\ncommondir=0", true, out)
      H.no_match(out, "\nrm=0", true, out)
      H.match(out, "gitstatus=0", true, "git still works inside the sandbox:\n" .. out)
      H.eq(0, vim.fn.filereadable(project .. "/.git/commondir"), "no commondir on the host")
      host_git_runs_nothing(project, canary)
    end)

    it("the state a later `git rebase --continue` would run cannot be created or entered", function()
      local project = H.fixture("basic", { git = true })
      local script = table.concat({
        "P=" .. project .. "; cd $P",
        "mkdir .git/rebase-merge 2>&1; echo rebase_merge=$?",
        "mkdir .git/rebase-apply 2>&1; echo rebase_apply=$?",
        "mkdir .git/sequencer 2>&1; echo sequencer=$?",
        "mkdir .git/remotes 2>&1; echo remotes=$?",
        "mkdir .git/branches 2>&1; echo branches=$?",
        "mkdir .git/worktrees 2>&1; echo worktrees=$?",
        "mkdir .git/modules 2>&1; echo modules=$?",
        "mkdir .git/hooks.new && mv .git/hooks .git/hooks.old 2>&1; echo mvhooks=$?",
      }, "\n")
      local out = inside(script, project, { git_write = true })
      for _, k in ipairs({
        "rebase_merge",
        "rebase_apply",
        "sequencer",
        "remotes",
        "branches",
        "worktrees",
        "modules",
        "mvhooks",
      }) do
        H.no_match(out, "\n" .. k .. "=0", true, k .. " must be refused:\n" .. out)
      end
      for _, d in ipairs({ "rebase-merge", "rebase-apply", "sequencer", "remotes", "branches", "worktrees", "modules" }) do
        H.eq(0, vim.fn.isdirectory(project .. "/.git/" .. d), "nothing left behind on the host: " .. d)
      end
    end)

    it("a submodule git directory is as locked as the main one, nested ones too, and cannot be renamed", function()
      local project = H.fixture("basic", { git = true })
      for _, d in ipairs({ "modules/a", "modules/a/modules/b" }) do
        vim.fn.mkdir(project .. "/.git/" .. d .. "/hooks", "p")
        vim.fn.mkdir(project .. "/.git/" .. d .. "/info", "p")
        vim.fn.writefile({ "[core]" }, project .. "/.git/" .. d .. "/config")
      end
      local script = table.concat({
        "P=" .. project .. "; cd $P/.git",
        "mv modules modules.old 2>&1; echo mvmodules=$?",
        "mv modules/a modules/a.old 2>&1; echo mva=$?",
        "mv modules/a/modules modules/a/modules.old 2>&1; echo mvnested=$?",
        "echo x > modules/a/hooks/pre-commit 2>&1; echo hooka=$?",
        "echo x > modules/a/modules/b/hooks/pre-commit 2>&1; echo hookb=$?",
        "echo x >> modules/a/modules/b/config 2>&1; echo configb=$?",
        "echo ok > modules/a/HEAD 2>&1; echo headwrite=$?",
      }, "\n")
      local out = inside(script, project, { git_write = true })
      for _, k in ipairs({ "mvmodules", "mva", "mvnested", "hooka", "hookb", "configb" }) do
        H.no_match(out, "\n" .. k .. "=0", true, k .. " must be refused:\n" .. out)
      end
      H.match(out, "headwrite=0", true, "the rest of a submodule git dir stays writable:\n" .. out)
    end)

    it(
      "the argv: every git directory is bound on its own, before the read-only parts, and commondir is pinned",
      function()
        local project = H.fixture("basic", { git = true })
        H.need_sandbox()
        sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, { git_write = true })
        local p = sb.plan({ "true" }, project, H.tmpdir())
        H.ok(p, "a plan")
        local argv = table.concat(sb.argv(p), " ")
        local bind = argv:find("--bind " .. project .. "/.git " .. project .. "/.git", 1, true)
        local ro = argv:find("--ro-bind " .. project .. "/.git/hooks", 1, true)
        H.ok(bind and ro and bind < ro, "the .git bind comes before the read-only hooks")
        H.match(argv, project .. "/.git/commondir", true)
        sb.config.policy.git_write = nil
        p = sb.plan({ "true" }, project, H.tmpdir())
        H.no_match(table.concat(sb.argv(p), " "), "--bind " .. project .. "/.git ", true)
      end
    )
  end)

  it("the preview says so: a Git write mode section naming what stays read-only; absent by default", function()
    local project = H.fixture("basic", { git = true })
    H.need_sandbox()
    sb.config.policy = vim.tbl_extend("force", sb.config.policy or {}, { git_write = true })
    local ui = require("xyno_sandbox.ui")
    local p = sb.plan({ "true" }, project, H.tmpdir())
    H.ok(p, "a plan")
    local txt = table.concat(ui.lines(p), "\n")
    H.match(txt, "Git write mode", true)
    H.match(txt, "hooks/, config, info/", true)
    -- the argv carries the locks (preview == argv is checked by preview_spec for every plan)
    local argv = table.concat(sb.argv and sb.argv(p) or {}, " ")
    if argv ~= "" then
      H.match(argv, "--ro-bind " .. project .. "/.git/hooks", true)
      H.match(argv, "--ro-bind " .. project .. "/.git/config", true)
      H.no_match(argv, "--ro-bind " .. project .. "/.git " .. project .. "/.git", true)
    end
    sb.config.policy.git_write = nil
    p = sb.plan({ "true" }, project, H.tmpdir())
    txt = table.concat(ui.lines(p), "\n")
    H.no_match(txt, "Git write mode", true)
  end)

  it("policy.git_write must be a boolean", function()
    local errs = sb.validate_opts({ policy = { git_write = "yes" } })
    H.match(table.concat(errs, "\n"), "git_write", true)
    H.eq({}, sb.validate_opts({ policy = { git_write = true } }))
  end)
end)
