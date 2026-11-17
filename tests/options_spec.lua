-- setup() options: the policy lists are validated, invalid options change nothing, functions are
-- accepted for the two switches.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")

local saved = vim.deepcopy(sb.config)
after_each(function()
  sb.config = vim.deepcopy(saved)
  for _, c in ipairs({ "XynoSandboxStatus", "XynoSandboxRun", "XynoSandboxPolicy", "XynoSandboxApprovals" }) do
    pcall(vim.api.nvim_del_user_command, c)
  end
end)

describe("defaults", function()
  it("the new options default to the conservative values", function()
    H.eq("once", sb.config.preview)
    H.eq(false, sb.config.strip_skip_permissions)
    H.eq({}, sb.config.policy)
  end)
end)

describe("validate_opts", function()
  local function bad(opts, pat)
    local errs = sb.validate_opts(opts)
    H.ok(#errs > 0, "expected an error for " .. vim.inspect(opts))
    H.match(table.concat(errs, "; "), pat, true)
    H.throws(function()
      sb.setup(opts)
    end, vim.pesc(pat))
  end

  it("accepts a full valid policy", function()
    H.eq(
      {},
      sb.validate_opts({
        preview = "always",
        strip_skip_permissions = true,
        agent_cmd = { "claude" },
        policy = {
          readonly = { "deploy.sh", "/etc/x", "~/.toolrc" },
          writable = { "/data/out", "~/work/out" },
          hidden = { "~/.secrets" },
          guard_dirs = { ".idea" },
          guard_files = { "run.sh" },
          scrub = { contains = { "CORP" }, prefix = { "INT_" }, exact = { "ZED" } },
          scan_depth = 10,
        },
      })
    )
  end)

  it("rejects unknown options and policy keys (typos)", function()
    bad({ sandbx = false }, "unknown option sandbx")
    bad({ policy = { writeable = {} } }, "unknown policy key writeable")
    bad({ policy = { scrub = { regex = {} } } }, "unknown policy.scrub key regex")
  end)

  it("rejects a bad preview mode and non-booleans", function()
    bad({ preview = "sometimes" }, "preview must be")
    bad({ strip_skip_permissions = "yes" }, "strip_skip_permissions must be a boolean")
    bad({ commands = 1 }, "commands must be a boolean")
  end)

  it("rejects wrong types and empty strings in the lists", function()
    bad({ policy = { readonly = "x" } }, "policy.readonly must be a list")
    bad({ policy = { hidden = { "" } } }, "must be a non-empty string")
    bad({ policy = { writable = { 5 } } }, "must be a non-empty string")
  end)

  it("rejects relative writable/hidden paths, '..' and paths that expose / or $HOME", function()
    bad({ policy = { writable = { "relative/dir" } } }, "must be absolute or start with ~/")
    bad({ policy = { hidden = { "x" } } }, "must be absolute")
    bad({ policy = { writable = { "/" } } }, "would expose all of / or $HOME")
    bad({ policy = { writable = { "~/" } } }, "would expose")
    bad({ policy = { writable = { vim.uv.os_homedir() } } }, "would expose")
    bad({ policy = { readonly = { "../escape" } } }, "'..' is not allowed")
    bad({ policy = { readonly = { "a/../b" } } }, "'..' is not allowed")
  end)

  it("rejects bad scrub names and scan depths", function()
    bad({ policy = { scrub = { contains = { "BAD-NAME" } } } }, "environment variable names")
    bad({ policy = { scan_depth = 0 } }, "scan_depth")
    bad({ policy = { scan_depth = 99 } }, "scan_depth")
    bad({ policy = { scan_depth = 2.5 } }, "scan_depth")
  end)

  it("an invalid setup() raises and changes nothing", function()
    local before = vim.deepcopy(sb.config)
    H.throws(function()
      sb.setup({ preview = "always", policy = { writable = { "/" } } })
    end)
    H.eq(before, sb.config)
  end)
end)

describe("policy reaches the plan", function()
  it("scrub, readonly, hidden and writable options show up in the plan and the argv", function()
    if sb.status_blocking().mode ~= "bwrap" then
      return require("xynotest.harness").skip("needs a working bwrap")
    end
    local project, tmp, extra, hid = H.tmpdir(), H.tmpdir(), H.tmpdir(), H.tmpdir()
    vim.fn.writefile({ "x" }, project .. "/deploy.sh")
    vim.uv.os_setenv("CORP_THING", "v")
    sb.setup({
      policy = {
        readonly = { "deploy.sh" },
        writable = { extra },
        hidden = { hid },
        scrub = { contains = { "CORP_" } },
      },
    })
    local p = sb.plan({ "agent" }, project, tmp)
    local function has(list, path)
      for _, e in ipairs(list) do
        if (e.path or e) == path then
          return true
        end
      end
    end
    H.ok(has(p.readonly, project .. "/deploy.sh"))
    H.ok(has(p.writable, extra))
    H.ok(has(p.hidden, hid))
    H.has(p.env_strip, "CORP_THING")
    local a = table.concat(sb.argv(p), "\0")
    H.has(a, "--bind\0" .. extra .. "\0" .. extra)
    H.has(a, "--unsetenv\0CORP_THING")
    vim.uv.os_unsetenv("CORP_THING")
    sb.config.policy = {}
  end)

  it("the built-in policy cannot be reduced: lists only add", function()
    local before = #sb.scrub_names({ GITHUB_TOKEN = "x" })
    sb.setup({ policy = { scrub = { contains = {} } } })
    H.eq(before, #sb.scrub_names({ GITHUB_TOKEN = "x" }))
  end)
end)

describe("switches may be functions", function()
  it("sandbox / allow_unsandboxed given as functions are evaluated at every call", function()
    local v = true
    sb.setup({
      sandbox = function()
        return v
      end,
    })
    H.ok(sb.status().mode ~= "unsandboxed")
    v = false
    H.eq("sandbox=false", sb.status().via)
  end)
end)

describe("documentation", function()
  it("README and help document every option, command and the permission line", function()
    local text = H.docs_text()
    for _, w in ipairs({
      "preview",
      "strip_skip_permissions",
      "agent_cmd",
      "guard_files",
      "guard_dirs",
      "scan_depth",
      ":XynoSandboxPolicy",
      ":XynoSandboxApprovals",
      "exceptions.log",
      "Agent permission prompts",
      "statusline",
      "handle.release",
      "xfail",
      "unprivileged_userns_clone",
      "home_allow",
      "keep_run",
      "project_secrets",
      "secret_files",
      "secret_allow",
      "expert_exceptions",
      "env -i",
      "symlinks",
    }) do
      H.has(text, w)
    end
  end)
end)
