-- Scrubbed secrets never exist inside the sandbox: bwrap itself is started with an empty
-- environment (`env -i`) plus the allowed variables, so /proc/1/environ (bwrap's own, the original
-- environment) holds no scrubbed value either. Red-team finding 1: reading /proc/1/environ gave back
-- GITHUB_TOKEN & co.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")

local saved = vim.deepcopy(sb.config)
local set = {}
local function setenv(name, value)
  set[#set + 1] = { name, vim.uv.os_getenv(name) }
  vim.uv.os_setenv(name, value)
end
after_each(function()
  sb.config = vim.deepcopy(saved)
  for i = #set, 1, -1 do
    local e = set[i]
    if e[2] == nil then
      vim.uv.os_unsetenv(e[1])
    else
      vim.uv.os_setenv(e[1], e[2])
    end
  end
  set = {}
end)

local rnd = tostring(vim.uv.hrtime()):sub(-8)
local SECRETS = {
  GITHUB_TOKEN = "canary-github-" .. rnd,
  AWS_SECRET_ACCESS_KEY = "canary-aws-" .. rnd,
  OPENAI_API_KEY = "canary-openai-" .. rnd,
  XYNO_DB_PASSWORD = "canary-db-" .. rnd,
  NPM_TOKEN = "canary-npm-" .. rnd,
  SSH_AUTH_SOCK = "/nonexistent/canary-ssh-" .. rnd,
  ANTHROPIC_API_KEY = "canary-anthropic-" .. rnd, -- stripped when the login is file based (it is on a logged-in machine)
}

--- stdout of `script` run in the sandbox of a fresh project
local function inside(script, project)
  H.need_sandbox()
  local tmp = H.tmpdir()
  local cmd, err, h = sb.wrap({ "bash", "-c", script }, project or H.tmpdir(), tmp)
  H.ok(cmd, err)
  local r = vim.system(cmd, { text = true }):wait(60000)
  h.release()
  return (r.stdout or "") .. (r.stderr or ""), r
end

local function with_secrets()
  for k, v in pairs(SECRETS) do
    setenv(k, v)
  end
  setenv("XYNO_ALLOWED_CONTROL", "control-" .. rnd)
end

local SCAN = table.concat({
  'for p in /proc/[0-9]*/environ; do echo "== $p"; tr "\\0" "\\n" < "$p" 2>/dev/null; done',
  'for p in /proc/[0-9]*/cmdline; do echo "== $p"; tr "\\0" "\\n" < "$p" 2>/dev/null; done',
}, "\n")

describe("the environment of the sandbox", function()
  for _, net in ipairs({ "open", "filtered" }) do
    it(("network = %s: no scrubbed value in the environ or cmdline of ANY process (/proc/*/environ, /proc/1/environ)"):format(net), function()
      with_secrets()
      sb.config.network = net
      local out = inside(SCAN)
      H.match(out, "== /proc/1/environ", true, "pid 1 (bwrap) must be visible to this check")
      for name, value in pairs(SECRETS) do
        if not (name == "ANTHROPIC_API_KEY" and vim.uv.fs_stat(vim.uv.os_homedir() .. "/.claude/.credentials.json") == nil) then
          H.no_match(out, value, true, name .. " leaked into the sandbox")
        end
      end
    end)
  end

  it("the control: an allowed variable IS in /proc/1/environ, so the scan really reads bwrap's environment", function()
    with_secrets()
    local out = inside('tr "\\0" "\\n" < /proc/1/environ')
    H.match(out, "XYNO_ALLOWED_CONTROL=control-" .. rnd, true)
    H.match(out, "PATH=", true, "PATH is kept")
  end)

  it("the stripped names are neither set nor listed anywhere in the sandbox", function()
    with_secrets()
    local out = inside('env | sort; echo ---; tr "\\0" "\\n" < /proc/1/environ | sort')
    for name in pairs(SECRETS) do
      if name ~= "ANTHROPIC_API_KEY" then
        H.no_match(out, "\n" .. name .. "=", true, name)
        H.no_match(out, "^" .. name .. "=", false, name)
      end
    end
  end)

  it("an approved exception lets exactly that variable through, in the environ too", function()
    setenv("XYNO_PROJECT_TOKEN", "canary-allowed-" .. rnd)
    setenv("XYNO_OTHER_TOKEN", "canary-other-" .. rnd)
    H.need_sandbox()
    local tmp = H.tmpdir()
    local project = H.tmpdir()
    local p = sb.plan({ "bash", "-c", 'tr "\\0" "\\n" < /proc/1/environ' }, project, tmp, {
      exceptions = { { kind = "env", value = "XYNO_PROJECT_TOKEN", scope = "once" } },
    })
    H.has(p.env_kept, "XYNO_PROJECT_TOKEN")
    local cmd, err, h = sb.wrap(p.agent.cmd, project, tmp, { plan = p })
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true }):wait(60000)
    h.release()
    H.match(r.stdout, "canary-allowed-" .. rnd, true)
    H.no_match(r.stdout, "canary-other-" .. rnd, true)
  end)

  it("the command line starts with `env -i` and carries no stripped value (also what the preview is built from)", function()
    with_secrets()
    local p = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    local a = plan.argv(p)
    H.eq({ "env", "-i" }, { vim.fs.basename(a[1]), a[2] })
    local joined = table.concat(a, "\0")
    for _, value in pairs(SECRETS) do
      H.no_match(joined, value, true)
    end
    for _, n in ipairs(p.env_pass) do
      H.not_ok(vim.tbl_contains(p.env_strip, n[1]), n[1] .. " is both passed and stripped")
    end
  end)

  it("the editor's RPC address ($NVIM) is stripped: it is full control of the editor", function()
    setenv("NVIM", "/run/user/1000/nvim.canary." .. rnd)
    setenv("NVIM_LISTEN_ADDRESS", "/run/user/1000/nvim.canary2." .. rnd)
    local p = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    H.has(p.env_strip, "NVIM")
    H.has(p.env_strip, "NVIM_LISTEN_ADDRESS")
  end)
end)
