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
