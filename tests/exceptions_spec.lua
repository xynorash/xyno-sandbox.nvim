-- The logged approval flow: approve, refuse, remember, list, revoke, and the log contents.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local store = require("xyno_sandbox.store")
local plan = require("xyno_sandbox.plan")

local saved = vim.deepcopy(sb.config)
local project, data

before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
  project = H.tmpdir()
  data = H.tmpdir()
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local function plan_for(excs)
  return sb.plan({ "agent" }, project, data, {
    exceptions = excs,
    aux = { empty = "/aux/empty", claude_json = "/aux/cj" },
  })
end

local function skip_no_backend()
  if sb.status_blocking().mode ~= "bwrap" then
    require("xynotest.harness").skip("needs a working bwrap to build a bwrap plan")
  end
end

describe("approve", function()
  it("an env approval for this launch is logged with timestamp, project, kind and NAME", function()
    local e = sb.approve(project, "env", "MY_API_KEY", "once")
    H.eq({ kind = "env", value = "MY_API_KEY", scope = "once" }, e)
    local log = store.read_log()
    H.eq(1, #log)
    H.eq("approved", log[1].decision)
    H.eq("env", log[1].kind)
    H.eq("MY_API_KEY", log[1].name)
    H.eq(project, log[1].project)
    H.eq("once", log[1].scope)
    H.match(log[1].ts, "^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%dZ$")
    H.eq(nil, log[1].path)
  end)

  it("a path approval is logged with the path, and a 'once' approval is not remembered", function()
    sb.approve(project, "writable", data, "once")
    local log = store.read_log()
    H.eq(data, log[1].path)
    H.eq(nil, log[1].name)
    H.eq({}, sb.approvals(project))
  end)

  it("a 'project' approval is remembered, listed, applied to the next plan, and survives a reload", function()
    skip_no_backend()
    H.eq("function", type(sb.approve))
    vim.uv.os_setenv("MY_API_KEY", "v")
    sb.approve(project, "env", "MY_API_KEY", "project")
    local list = sb.approvals(project)
    H.eq(1, #list)
    H.eq("MY_API_KEY", list[1].value)
    H.ok(list[1].id and list[1].ts)
    local p = plan_for()
    H.has(p.env_kept, "MY_API_KEY")
    H.not_ok(vim.tbl_contains(p.env_strip, "MY_API_KEY"))
    H.eq(1, #sb.approvals(project), "read back from the state file")
    vim.uv.os_unsetenv("MY_API_KEY")
  end)

  it("approvals are per project", function()
    sb.approve(project, "env", "MY_API_KEY", "project")
    H.eq({}, sb.approvals(H.tmpdir()))
    H.eq(1, vim.tbl_count(sb.approvals()))
  end)

  it("an invalid approval is turned into a logged refusal with the reason and changes nothing", function()
    local e, why = sb.approve(project, "writable", "/", "project")
    H.eq(nil, e)
    H.match(why, "refusing", true)
    local e2 = sb.approve(project, "writable", data .. "/missing", "project")
    H.eq(nil, e2)
    local log = store.read_log()
    H.eq(2, #log)
    H.eq("refused", log[1].decision)
    H.ok(log[1].reason)
    H.eq({}, sb.approvals(project))
  end)
end)

describe("refuse", function()
  it("is logged and leaves the plan exactly as it was", function()
    skip_no_backend()
    local before = plan_for()
    H.eq(nil, sb.refuse(project, "env", "MY_API_KEY"))
    H.eq(nil, sb.refuse(project, "writable", data))
    local after = plan_for()
    H.eq(before, after)
    H.eq({}, sb.approvals(project))
    local log = store.read_log()
    H.eq(2, #log)
    H.eq("refused", log[1].decision)
    H.eq("refused", log[2].decision)
    H.eq(data, log[2].path)
  end)

  it("the log only ever grows (append-only)", function()
    sb.refuse(project, "env", "A_TOKEN")
    local first = vim.fn.readfile(store.log_path())
    sb.approve(project, "env", "B_TOKEN", "once")
    local all = vim.fn.readfile(store.log_path())
    H.eq(2, #all)
    H.eq(first[1], all[1])
  end)
end)

describe("revoke", function()
  it("removes a remembered approval, logs it, and the next plan strips the variable again", function()
    skip_no_backend()
    vim.uv.os_setenv("MY_API_KEY", "v")
    sb.approve(project, "env", "MY_API_KEY", "project")
    local id = sb.approvals(project)[1].id
    H.eq(true, sb.revoke(project, id))
    H.eq({}, sb.approvals(project))
    H.eq(false, sb.revoke(project, id), "already gone")
    H.has(plan_for().env_strip, "MY_API_KEY")
    local log = store.read_log()
    H.eq("revoked", log[#log].decision)
    H.eq("MY_API_KEY", log[#log].name)
    vim.uv.os_unsetenv("MY_API_KEY")
  end)
end)

describe("state files", function()
  it("are private (0600) and live outside every writable path of the policy", function()
    sb.approve(project, "env", "A_TOKEN", "project")
    H.eq(tonumber("600", 8), bit.band(vim.uv.fs_stat(store.log_path()).mode, tonumber("777", 8)))
    H.eq(tonumber("600", 8), bit.band(vim.uv.fs_stat(store.dir() .. "/state.json").mode, tonumber("777", 8)))
    store.dir_override = nil
    local home = vim.uv.os_homedir()
    for _, rel in ipairs(plan.WRITABLE) do
      H.not_ok(plan.inside(store.dir(), home .. rel), "state dir inside writable " .. rel)
    end
  end)

  it("a corrupt state file reads as empty instead of failing", function()
    vim.fn.mkdir(store.dir(), "p")
    vim.fn.writefile({ "{not json" }, store.dir() .. "/state.json")
    H.eq({}, sb.approvals(project))
    sb.approve(project, "env", "A_TOKEN", "project")
    H.eq(1, #sb.approvals(project))
  end)
end)

-- ------------------------------------------------- never approved, never ineffective

describe("approvals that cannot take effect", function()
  local function last_log()
    local log = store.read_log()
    return log[#log], #log
  end

  it("a writable <project>/.git is refused: the later --ro-bind of .git would override it", function()
    skip_no_backend()
    vim.fn.mkdir(project .. "/.git", "p")
    local e, why = sb.approve(project, "writable", project .. "/.git", "project")
    H.eq(nil, e)
    H.match(why, "no effect", true)
    H.match(why, project .. "/.git", true)
    local rec = last_log()
    H.eq("refused", rec.decision, "never logged as approved")
    H.eq(project .. "/.git", rec.path)
    H.ok(rec.reason)
    H.eq({}, sb.approvals(project), "and not remembered")
    -- also files and sub-paths below a read-only lock
    vim.fn.writefile({}, project .. "/.git/config")
    local e2, why2 = sb.approve(project, "writable", project .. "/.git/config", "once")
    H.eq(nil, e2)
    H.match(why2, "no effect", true)
  end)

  it("the build refuses it too, whatever called it: IGNORED in the plan, not writable, not an exception", function()
    skip_no_backend()
    vim.fn.mkdir(project .. "/.git", "p")
    local p = plan_for({ { kind = "writable", value = project .. "/.git", scope = "once" } })
    H.eq(0, #p.exceptions)
    H.eq(1, #p.rejected)
    H.match(p.rejected[1].reason, "no effect", true)
    for _, w in ipairs(p.writable) do
      H.not_ok(w.path == project .. "/.git" and w.exception, "writable exception applied")
    end
    local text = table.concat(require("xyno_sandbox.ui").lines(p), "\n")
    H.match(text, "IGNORED writable", true)
  end)

  it("a hidden path other than the exact one cannot be 'shown' (a child of a hidden dir, an unhidden path)", function()
    skip_no_backend()
    local home = vim.uv.os_homedir()
    local e, why = sb.approve(project, "unhide", home .. "/.ssh/id_ed25519", "once")
    H.eq(nil, e)
    H.match(why, "does not hide", true)
    local e2, why2 = sb.approve(project, "unhide", project, "once")
    H.eq(nil, e2)
    H.match(why2, "does not hide", true)
  end)

  it("an env approval for a variable the policy does not strip is refused", function()
    local e, why = sb.approve(project, "env", "XYNO_HARMLESS_VAR", "once")
    H.eq(nil, e)
    H.match(why, "not stripped", true)
  end)
end)

describe("approve() validation", function()
  local function refused(kind, value, pat)
    local e, why = sb.approve(project, kind, value, "project")
    H.eq(nil, e, kind .. " " .. value .. " must be refused")
    H.match(why, pat, false, kind .. " " .. value)
    local log = store.read_log()
    H.eq("refused", log[#log].decision)
    H.eq(value, log[#log].path or log[#log].name)
    H.ok(log[#log].reason, "the reason is logged")
    H.eq({}, sb.approvals(project))
  end

  it("refuses writable shell startup files, /etc, /proc, /run/user, $HOME's autostart and bin dirs", function()
    local home = vim.uv.os_homedir()
    refused("writable", "/etc", "system path")
    refused("writable", "/proc/self", "system path")
    refused("writable", "/proc", "system path")
    refused("writable", "/usr/bin", "system path")
    refused("writable", "/run", "system path")
    refused("writable", "/home", "contains %$HOME")
    for _, rel in ipairs({
      "/.bashrc",
      "/.zshrc",
      "/.profile",
      "/.ssh",
      "/.local/bin",
      "/.config/autostart",
      "/.config/nvim",
      "/.gitconfig",
    }) do
      local p = home .. rel
      -- the check is on the path, so it also holds when the file does not exist (then "does not exist" comes first)
      local ok, why = plan.validate_exception({ kind = "writable", value = p }, {
        home = home,
        probes = {
          exists = function()
            return true
          end,
          realpath = function(x)
            return x
          end,
        },
      })
      H.not_ok(ok, rel)
      H.match(why, "would run, or steer tools, outside the sandbox later", true, rel)
    end
    local uid = vim.uv.os_get_passwd().uid
    if vim.uv.fs_stat("/run/user/" .. uid) then
      refused("writable", "/run/user/" .. uid, "system path")
    end
  end)

  it("refuses a symlink that resolves into a forbidden place, and says where it leads", function()
    local link = data .. "/innocent"
    vim.uv.fs_symlink("/etc", link)
    local e, why = sb.approve(project, "writable", link, "project")
    H.eq(nil, e)
    H.match(why, "resolves to /etc", true)
    local link2 = data .. "/proc-link"
    vim.uv.fs_symlink("/proc/self", link2)
    local e2, why2 = sb.approve(project, "writable", link2, "once")
    H.eq(nil, e2)
    H.match(why2, "resolves to", true)
    local log = store.read_log()
    H.eq(2, #log)
    H.eq("refused", log[1].decision)
    H.eq("refused", log[2].decision)
  end)

  it("never reveals /etc/shadow & co. (unhide)", function()
    for _, p in ipairs({
      "/etc/shadow",
      "/etc/gshadow",
      "/etc/sudoers",
      "/etc/sudoers.d",
      "/etc/ssh/ssh_host_ed25519_key",
    }) do
      refused("unhide", p, "never revealed")
    end
    local link = data .. "/shadow-link"
    vim.uv.fs_symlink("/etc/shadow", link)
    local e, why = sb.approve(project, "unhide", link, "once")
    H.eq(nil, e)
    H.ok(why)
  end)

  it("refuses LD_PRELOAD, PATH, LD_LIBRARY_PATH & co. unless the expert flag is set, and logs it either way", function()
    for _, name in ipairs({
      "LD_PRELOAD",
      "PATH",
      "LD_LIBRARY_PATH",
      "LD_AUDIT",
      "BASH_ENV",
      "PYTHONPATH",
      "NODE_OPTIONS",
      "RUSTC_WRAPPER",
    }) do
      local e, why = sb.approve(project, "env", name, "project")
      H.eq(nil, e, name)
      H.match(why, "decides which code runs", true, name)
    end
    local log = store.read_log()
    H.eq(8, #log, "every decision is logged")
    for _, rec in ipairs(log) do
      H.eq("refused", rec.decision)
      H.ok(rec.reason)
    end
    H.eq({}, sb.approvals(project))
  end)

  it("the expert flag lifts the code-selection refusal, but only for a variable the policy actually strips", function()
    sb.config.expert_exceptions = true
    sb.config.policy = { scrub = { exact = { "LD_PRELOAD" } } }
    local e = sb.approve(project, "env", "LD_PRELOAD", "once")
    H.eq({ kind = "env", value = "LD_PRELOAD", scope = "once" }, e)
    local e2, why2 = sb.approve(project, "env", "PATH", "once")
    H.eq(nil, e2)
    H.match(why2, "not stripped", true, "PATH is not scrubbed, so there is nothing to let through")
    local log = store.read_log()
    H.eq("approved", log[1].decision)
    H.eq("refused", log[2].decision)
    sb.config.expert_exceptions = false
    local e3, why3 = sb.approve(project, "env", "LD_PRELOAD", "once")
    H.eq(nil, e3)
    H.match(why3, "decides which code runs", true)
  end)

  it("a valid exception still works and is logged as approved with its scope", function()
    local e = sb.approve(project, "writable", data, "once")
    H.ok(e)
    local log = store.read_log()
    H.eq("approved", log[#log].decision)
    H.eq(data, log[#log].path)
    H.eq(nil, log[#log].reason)
  end)

  it("setup() takes expert_exceptions as a boolean only", function()
    H.throws(function()
      sb.setup({ expert_exceptions = "yes" })
    end, "expert_exceptions")
    sb.setup({ preview = "never", expert_exceptions = true })
    H.eq(true, sb.config.expert_exceptions)
  end)
end)
