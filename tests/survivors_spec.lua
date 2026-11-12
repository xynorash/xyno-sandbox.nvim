-- Specs for the behaviours that mutation testing showed to be unpinned: submodule git configs, every
-- branch of the git-config sanitizer, the false-positive guard of the URL pattern, secret key names,
-- the /var/run and /run/current-system handling, the editor-RPC socket variable, the relay's
-- SIGHUP and bind address, a second release(), the front-door checks of approvals, and capabilities
-- inside a real sandbox.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local sanitize = require("xyno_sandbox.sanitize")
local scan = require("xyno_sandbox.scan")
local store = require("xyno_sandbox.store")
local uv = vim.uv

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

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
    glob = function(pat)
      local out = {}
      local lp = "^" .. pat:gsub("[%-%.%+%[%]%(%)%$%^%%]", "%%%0"):gsub("%*", "[^/]*") .. "$"
      for x in pairs(entries) do
        if x:match(lp) then
          out[#out + 1] = x
        end
      end
      table.sort(out)
      return out
    end,
    read_line = function() return nil end,
    realpath = function(x) return entries[x] and x or nil end,
  }
end

local function build(extra, over)
  local entries = vim.tbl_extend("force", {
    [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra or {})
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = fakefs(entries),
    env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj", git_dir = "/aux/git" },
    config = { network = "open", home = "denylist" },
  }, over or {}))
end

describe("git configs of submodules", function()
  it("are sanitized too: <gitdir>/modules/*/config gets a copy", function()
    local p = build({
      [PROJECT .. "/.git/config"] = "file", [PROJECT .. "/.git/modules"] = "directory",
      [PROJECT .. "/.git/modules/sub"] = "directory", [PROJECT .. "/.git/modules/sub/config"] = "file",
    })
    local srcs = {}
    for _, g in ipairs(p.git_configs) do
      srcs[#srcs + 1] = g.src
    end
    H.has(srcs, PROJECT .. "/.git/config")
    H.has(srcs, PROJECT .. "/.git/modules/sub/config")
  end)
end)

describe("sanitize.git_config, every branch", function()
  local function clean(text)
    return (sanitize.git_config(text))
  end
  it("drops token = and password = keys in any section", function()
    local out = clean('[remote "o"]\n\ttoken = TOPSECRET1\n\tpassword = TOPSECRET2\n\turl = https://h/x\n')
    H.no_match(out, "TOPSECRET", true)
    H.match(out, "url = https://h/x", true)
  end)
  it("drops all continuation lines of a dropped value, not only the first", function()
    local out = clean('[http]\n\textraHeader = Authorization: a \\\n\t  second-secret \\\n\t  third-secret\n\tproxy = http://p\n')
    H.no_match(out, "second-secret", true)
    H.no_match(out, "third-secret", true)
    H.match(out, "proxy = http://p", true)
  end)
  it("matches section names case-insensitively", function()
    local out = clean('[CREDENTIAL "https://h"]\n\tHelper = store --file=/home/u/.secret\n\tusername = bob\n')
    H.no_match(out, ".secret", true)
    H.match(out, "username = bob", true)
    local out2 = clean('[HTTP]\n\tExtraHeader = Authorization: Bearer x\n')
    H.no_match(out2, "Bearer", true)
  end)
end)

describe("secret key names", function()
  it("the private-key file names are secret by name, the public keys are not", function()
    for _, n in ipairs({ "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519" }) do
      H.ok(plan.is_secret_name(n, plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT), n)
      H.not_ok(plan.is_secret_name(n .. ".pub", plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT), n .. ".pub")
    end
  end)
end)

describe("host directories that hold sockets", function()
  it("/var/run is masked when it is a real directory, not when it is the usual symlink", function()
    local function masked(t)
      local p = build({ ["/var/run"] = t, ["/run"] = "directory" })
      for _, m in ipairs(p.masked) do
        if m.path == "/var/run" then
          return true
        end
      end
      return false
    end
    H.eq(true, masked("directory"))
    H.eq(false, masked("link"))
  end)

  it("/run/current-system and friends are bound back read-only below the masked /run", function()
    local p = build({ ["/run"] = "directory", ["/run/current-system"] = "directory", ["/run/user"] = "directory" })
    local keep = {}
    for _, k in ipairs(p.run_keep) do
      keep[k.path] = true
    end
    H.ok(keep["/run/current-system"], vim.inspect(p.run_keep))
    H.not_ok(keep["/run/user"], "sockets live there")
  end)

  it("a socket named by $NVIM / $NVIM_LISTEN_ADDRESS outside the masked directories is hidden", function()
    for _, var in ipairs({ "NVIM", "NVIM_LISTEN_ADDRESS" }) do
      local p = build({ ["/srv-x"] = "directory", ["/srv-x/nvim.sock"] = "socket" }, { env = { PATH = "/usr/bin", [var] = "/srv-x/nvim.sock" } })
      local found
      for _, h in ipairs(p.hidden) do
        if h.path == "/srv-x/nvim.sock" then
          found = h.why
        end
      end
      H.eq("socket named by $" .. var, found)
    end
  end)
end)

describe("the relay", function()
  local RELAY = H.repo .. "/lua/xyno_sandbox/relay.lua"
  local function start()
    local dir = H.tmpdir()
    vim.fn.mkdir(dir .. "/net", "p")
    vim.fn.writefile({}, dir .. "/net/proxy.sock")
    local port = 20000 + (uv.hrtime() % 20000)
    local ready = dir .. "/ready"
    local script = ('"%s" -u NONE -i NONE --headless -l "%s" "%s" %d "%s" </dev/null >/dev/null 2>&1 & wait'):format(
      vim.v.progpath, RELAY, dir .. "/net/proxy.sock", port, ready)
    local sh = vim.system({ "sh", "-c", script, "xyno-r3-parent" })
    H.ok(vim.wait(10000, function() return uv.fs_stat(ready) ~= nil end, 50), "the relay did not come up")
    return { sh = sh, marker = dir .. "/net/proxy.sock", port = port }
  end

  it("exits on SIGHUP", function()
    local r = start()
    local ps = vim.tbl_filter(function(p) return not p[2]:match("^sh ") end, H.procs(r.marker))
    H.eq(1, #ps)
    uv.kill(ps[1][1], 1)
    H.eq({}, H.wait_gone(r.marker, 4000), "the relay ignored SIGHUP")
    r.sh:kill(9)
  end)

  it("listens on 127.0.0.1 only, never on every interface", function()
    local r = start()
    local hexport = ("%04X"):format(r.port)
    local listening = {}
    for line in io.lines("/proc/net/tcp") do
      local addr, port, st = line:match("^%s*%d+:%s+(%x+):(%x+)%s+%x+:%x+%s+(%x+)")
      if port == hexport and st == "0A" then
        listening[#listening + 1] = addr
      end
    end
    H.wait_gone(r.marker, 100)
    r.sh:kill(9)
    for _, ps in ipairs(H.procs(r.marker)) do
      uv.kill(ps[1], 9)
    end
    H.eq({ "0100007F" }, listening)
  end)
end)

describe("release", function()
  it("is idempotent: a second call does not close the proxy again or touch anything", function()
    H.need_sandbox()
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd, err)
    local closes = 0
    local close = h.proxy.close
    h.proxy.close = function(...)
      closes = closes + 1
      return close(...)
    end
    h.release()
    h.release()
    H.eq(1, closes)
  end)
end)

describe("exception front door", function()
  local ctx = { home = HOME, probes = fakefs({}) }
  it("refuses an unknown kind, an empty or non-string value, and an env value that is not a name", function()
    local ok, why = plan.validate_exception({ kind = "bogus", value = "x" }, ctx)
    H.eq(false, ok)
    H.match(why, "unknown exception kind", true)
    for _, v in ipairs({ "", 12, false }) do
      local ok2, why2 = plan.validate_exception({ kind = "env", value = v }, ctx)
      H.eq(false, ok2, vim.inspect(v))
      H.match(why2, "empty value", true)
    end
    local ok3, why3 = plan.validate_exception({ kind = "env", value = "NOT A NAME" }, ctx)
    H.eq(false, ok3)
    H.match(why3, "not an environment variable name", true)
    H.eq(true, (plan.validate_exception({ kind = "env", value = "MY_TOKEN" }, ctx)))
  end)
end)

describe("a real sandbox", function()
  it("has no capabilities at all (CapEff, CapBnd, CapPrm, CapInh, CapAmb all zero)", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project = H.tmpdir()
    local cmd, err, h = sb.wrap({ "sh", "-c", "grep '^Cap' /proc/self/status" }, project, H.tmpdir())
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = r.stdout or ""
    for _, k in ipairs({ "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb" }) do
      H.match(out, k .. ":\t0000000000000000", true, out .. (r.stderr or ""))
    end
  end)
end)
