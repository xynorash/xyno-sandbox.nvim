-- Project secrets (.env, .env.*, *.pem, *.key, .npmrc, .netrc, credentials.json, secrets.*, ...) are
-- hidden with empty read-only overlays, like the credentials in $HOME; templates stay readable.
-- Symlinks that leave the project are detected and listed. Red-team findings 3 and 4.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local ui = require("xyno_sandbox.ui")
local store = require("xyno_sandbox.store")

local saved = vim.deepcopy(sb.config)
before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
  sb.config = vim.deepcopy(saved)
end)

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

local function fakefs(entries, real)
  local probes = {
    stat_type = function(p)
      local t = entries[p]
      if t == "link" then
        return "file"
      end
      return t
    end,
    lstat_type = function(p) return entries[p] end,
    exists = function(p) return entries[p] ~= nil end,
    list = function(dir)
      local out, prefix = {}, dir .. "/"
      for p, t in pairs(entries) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), t }
        end
      end
      table.sort(out, function(a, b) return a[1] < b[1] end)
      return out
    end,
    glob = function() return {} end,
    read_line = function() return nil end,
    realpath = function(p) return (real or {})[p] or (entries[p] and p) or nil end,
  }
  return probes
end

local function build(extra_entries, over, real)
  local entries = vim.tbl_extend("force", {
    [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
    [PROJECT .. "/.git"] = "directory",
  }, extra_entries or {})
  over = over or {}
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = fakefs(entries, real),
    env = { PATH = "/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty" },
    config = { network = "open", home = "denylist" },
  }, over))
end

local function hidden_by_path(p)
  local out = {}
  for _, h in ipairs(p.hidden) do
    out[h.path] = h
  end
  return out
end

describe("project secrets in the plan", function()
  it("hides .env, .env.*, keys, certificates and token files anywhere in the project, as empty files", function()
    local files = {
      ".env", ".env.local", ".env.production", "app/.env", "svc/config/.env.staging", "server.pem", "deploy.key",
      ".npmrc", ".netrc", "credentials.json", "secrets.yaml", "secrets.toml", "id_ed25519", "gcp-service-account-prod.json",
      "terraform.tfvars", ".pypirc", ".git-credentials", ".htpasswd", "kubeconfig", "ci/.ENV", "keys/SERVER.KEY",
    }
    local e = {}
    for _, f in ipairs(files) do
      e[PROJECT .. "/" .. f] = "file"
      local d = vim.fs.dirname(PROJECT .. "/" .. f)
      while d ~= PROJECT do
        e[d] = "directory"
        d = vim.fs.dirname(d)
      end
    end
    local h = hidden_by_path(build(e))
    for _, f in ipairs(files) do
      local hit = h[PROJECT .. "/" .. f]
      H.ok(hit, f .. " is not hidden")
      H.eq("file", hit.kind)
      H.eq("project secret", hit.why)
    end
  end)

  it("leaves templates and ordinary files alone", function()
    local files = {
      ".env.example", ".env.sample", ".env.template", ".env.dist", "README.md", "Cargo.toml", "src/main.rs",
      "environment.rs", "keyboard.rs", "monkey.txt", "id_rsa.pub", "secrets_test.go.txt.bak.md",
    }
    local e = { [PROJECT .. "/src"] = "directory" }
    for _, f in ipairs(files) do
      e[PROJECT .. "/" .. f] = "file"
    end
    local h = hidden_by_path(build(e))
    for _, f in ipairs(files) do
      H.eq(nil, h[PROJECT .. "/" .. f], f .. " must stay readable")
    end
  end)

  it("hides credential directories and sockets of the project", function()
    local h = hidden_by_path(build({
      [PROJECT .. "/.aws"] = "directory", [PROJECT .. "/ops/.ssh"] = "directory", [PROJECT .. "/ops"] = "directory",
      [PROJECT .. "/dev.sock"] = "socket",
    }))
    H.eq("dir", h[PROJECT .. "/.aws"].kind)
    H.eq("dir", h[PROJECT .. "/ops/.ssh"].kind)
    H.eq("file", h[PROJECT .. "/dev.sock"].kind)
    H.eq("project socket", h[PROJECT .. "/dev.sock"].why)
  end)

  it("is configurable: off, more globs, never-hide names and paths", function()
    local e = {
      [PROJECT .. "/.env"] = "file", [PROJECT .. "/.env.test"] = "file", [PROJECT .. "/x.token"] = "file",
      [PROJECT .. "/cfg"] = "directory", [PROJECT .. "/cfg/.env"] = "file",
    }
    local off = hidden_by_path(build(e, { config = { network = "open", home = "denylist", policy = { project_secrets = false } } }))
    H.eq(nil, off[PROJECT .. "/.env"])
    local more = hidden_by_path(build(e, { config = { network = "open", home = "denylist", policy = { secret_files = { "*.token" } } } }))
    H.ok(more[PROJECT .. "/x.token"])
    local allow = hidden_by_path(build(e, { config = { network = "open", home = "denylist",
      policy = { secret_allow = { ".env.test", "cfg/.env" } } } }))
    H.eq(nil, allow[PROJECT .. "/.env.test"])
    H.eq(nil, allow[PROJECT .. "/cfg/.env"])
    H.ok(allow[PROJECT .. "/.env"], "only the named ones are let through")
  end)

  it("an unhide exception shows one secret again; the rest stay hidden", function()
    local e = { [PROJECT .. "/.env"] = "file", [PROJECT .. "/.env.local"] = "file" }
    local p = build(e, { exceptions = { { kind = "unhide", value = PROJECT .. "/.env", scope = "once" } } })
    local h = hidden_by_path(p)
    H.eq(nil, h[PROJECT .. "/.env"])
    H.ok(h[PROJECT .. "/.env.local"])
    H.eq({}, p.rejected)
    H.eq(1, #p.exceptions)
  end)

  it("the secret overlay is applied after the writable project bind (the later mount wins)", function()
    local p = build({ [PROJECT .. "/.env"] = "file" })
    local a = plan.argv(p)
    local w, hid
    for i = 1, #a - 2 do
      if a[i] == "--bind" and a[i + 2] == PROJECT then w = i end
      if a[i] == "--ro-bind" and a[i + 2] == PROJECT .. "/.env" then hid = i end
    end
    H.ok(w and hid and hid > w, "ro-bind of .env must come after --bind of the project")
  end)

  it("the preview lists project secrets with their reason", function()
    local text = table.concat(ui.lines(build({ [PROJECT .. "/.env"] = "file" }), { home = "/none" }), "\n")
    H.match(text, "Hidden project secrets and sockets", true)
    H.match(text, "/h/proj/.env", true)
    H.match(text, "project secret", true)
  end)
end)

describe("project secrets inside a real sandbox", function()
  local function populate(project)
    vim.fn.writefile({ "API_KEY=hunter2" }, project .. "/.env")
    vim.fn.writefile({ "API_KEY=sample" }, project .. "/.env.example")
    vim.fn.writefile({ "PRIVATE" }, project .. "/server.pem")
    vim.fn.writefile({ "//registry/:_authToken=abc" }, project .. "/.npmrc")
    vim.fn.mkdir(project .. "/sub", "p")
    vim.fn.writefile({ "{}" }, project .. "/sub/credentials.json")
    vim.fn.writefile({ "visible" }, project .. "/notes.txt")
  end

  local function inside(project, script, exceptions)
    H.need_sandbox()
    sb.config.network = "open"
    local tmp = H.tmpdir()
    local p = sb.plan({ "bash", "-c", script }, project, tmp, { exceptions = exceptions })
    local cmd, err, h = sb.wrap(p.agent.cmd, project, tmp, { plan = p })
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    return (r.stdout or "") .. (r.stderr or "")
  end

  it("reads of .env, *.pem, .npmrc, credentials.json give nothing; templates and notes are readable", function()
    local project = H.tmpdir()
    populate(project)
    local out = inside(project, table.concat({
      'echo "env=[$(cat .env)]"', 'echo "pem=[$(cat server.pem)]"', 'echo "npmrc=[$(cat .npmrc)]"',
      'echo "cred=[$(cat sub/credentials.json)]"', 'echo "example=[$(cat .env.example)]"', 'echo "notes=[$(cat notes.txt)]"',
      'grep -r hunter2 . 2>/dev/null && echo FOUND-HUNTER2', "echo done",
    }, "\n"))
    H.match(out, "env=[]", true, out)
    H.match(out, "pem=[]", true)
    H.match(out, "npmrc=[]", true)
    H.match(out, "cred=[]", true)
    H.match(out, "example=[API_KEY=sample]", true)
    H.match(out, "notes=[visible]", true)
    H.no_match(out, "FOUND-HUNTER2", true)
    H.no_match(out, "hunter2", true)
  end)

  it("the agent can neither write to, replace, move nor delete a hidden secret", function()
    local project = H.tmpdir()
    populate(project)
    local out = inside(project, table.concat({
      'echo planted >> .env 2>/dev/null && echo WROTE',
      'mv .env .env.moved 2>/dev/null && echo MOVED',
      'rm -f .env 2>/dev/null; [ -e .env ] && echo STILL-THERE',
      'echo "len=$(wc -c < .env)"', "echo done",
    }, "\n"))
    H.no_match(out, "WROTE", true, out)
    H.no_match(out, "MOVED", true, out)
    H.match(out, "STILL-THERE", true, out)
    H.match(out, "len=0", true, out)
    H.eq({ "API_KEY=hunter2" }, vim.fn.readfile(project .. "/.env"), "the real file is untouched")
  end)

  it("an approved unhide exception (the existing flow) shows exactly that file, and the approval is logged", function()
    local project = H.tmpdir()
    populate(project)
    local e = sb.approve(project, "unhide", project .. "/.env", "once")
    H.ok(e, "approved")
    local out = inside(project, 'echo "env=[$(cat .env)]"; echo "pem=[$(cat server.pem)]"', { e })
    H.match(out, "env=[API_KEY=hunter2]", true, out)
    H.match(out, "pem=[]", true, out)
    local log = store.read_log()
    H.eq("approved", log[#log].decision)
    H.eq(project .. "/.env", log[#log].path)
  end)

  it("with project_secrets = false nothing is hidden", function()
    local project = H.tmpdir()
    populate(project)
    sb.config.policy = { project_secrets = false }
    local out = inside(project, 'echo "env=[$(cat .env)]"')
    H.match(out, "env=[API_KEY=hunter2]", true, out)
  end)

  it("the empty mount points are not left behind as new files and the real ones keep their content", function()
    local project = H.tmpdir()
    populate(project)
    inside(project, "true")
    H.eq({ "API_KEY=hunter2" }, vim.fn.readfile(project .. "/.env"))
    H.eq({ "PRIVATE" }, vim.fn.readfile(project .. "/server.pem"))
  end)
end)

describe("symlinks that leave the project", function()
  local function links(entries, real, cfg)
    local e = { [PROJECT .. "/src"] = "directory" }
    for k, v in pairs(entries) do
      e[k] = v
    end
    return build(e, { config = vim.tbl_extend("force", { network = "open", home = "denylist" }, cfg or {}) }, real)
  end

  it("lists each link whose target is outside the project, with whether the target is readable inside", function()
    local p = links({
      [PROJECT .. "/etc-link"] = "link", [PROJECT .. "/src/home-link"] = "link", [PROJECT .. "/inside"] = "link",
      [PROJECT .. "/src/real.rs"] = "file", [PROJECT .. "/tmp-link"] = "link", [HOME .. "/notes"] = "file",
    }, {
      [PROJECT .. "/etc-link"] = "/etc/hostname", [PROJECT .. "/src/home-link"] = HOME .. "/notes",
      [PROJECT .. "/inside"] = PROJECT .. "/src/real.rs", [PROJECT .. "/tmp-link"] = "/tmp/elsewhere",
    })
    local by = {}
    for _, l in ipairs(p.symlinks) do
      by[l.path] = l
    end
    H.eq("/etc/hostname", by[PROJECT .. "/etc-link"].target)
    H.eq(true, by[PROJECT .. "/etc-link"].readable)
    H.eq(true, by[PROJECT .. "/src/home-link"].readable, "denylist view: $HOME is readable")
    H.eq(false, by[PROJECT .. "/tmp-link"].readable, "the host's /tmp is not visible inside")
    H.eq(nil, by[PROJECT .. "/inside"], "a link inside the project is not an escape")
  end)

  it("in the allowlist view a link into $HOME is listed as not visible", function()
    local p = links({ [PROJECT .. "/notes"] = "link", [HOME .. "/notes.txt"] = "file" }, { [PROJECT .. "/notes"] = HOME .. "/notes.txt" },
      { home = "allowlist" })
    H.eq(false, p.symlinks[1].readable)
  end)

  it("the preview lists them", function()
    local p = links({ [PROJECT .. "/etc-link"] = "link" }, { [PROJECT .. "/etc-link"] = "/etc/hostname" })
    local text = table.concat(ui.lines(p, { home = "/none" }), "\n")
    H.match(text, "Project symlinks that leave the project (1)", true)
    H.match(text, "/h/proj/etc-link -> /etc/hostname", true)
    H.match(text, "READABLE", true)
  end)

  it('policy.symlinks = "refuse" blocks the launch while a readable escaping link exists; "warn" only lists', function()
    local e = { [PROJECT .. "/etc-link"] = "link" }
    local r = { [PROJECT .. "/etc-link"] = "/etc/hostname" }
    local warn = links(e, r, { policy = { symlinks = "warn" } })
    H.eq(nil, warn.blocked)
    local refuse = links(e, r, { policy = { symlinks = "refuse" } })
    H.match(refuse.blocked, "etc-link", true)
    local text = table.concat(ui.lines(refuse, { home = HOME }), "\n")
    H.match(text, "BLOCKED", true)
    -- an unreadable target does not block
    local ok = links({ [PROJECT .. "/t"] = "link" }, { [PROJECT .. "/t"] = "/tmp/x" }, { policy = { symlinks = "refuse" } })
    H.eq(nil, ok.blocked)
  end)

  it("wrap() refuses to start while the plan is blocked, and starts when the link is gone", function()
    H.need_sandbox()
    sb.config.network = "open"
    sb.config.policy = { symlinks = "refuse" }
    local project, tmp = H.tmpdir(), H.tmpdir()
    vim.uv.fs_symlink("/etc/hostname", project .. "/leak")
    local cmd, why = sb.wrap({ "true" }, project, tmp)
    H.eq(nil, cmd)
    H.match(why, "leak", true)
    H.match(why, "policy.symlinks", true)
    vim.uv.fs_unlink(project .. "/leak")
    local cmd2, _, h = sb.wrap({ "true" }, project, tmp)
    H.ok(cmd2)
    h.release()
  end)

  it("a real project: the link is found, listed, and its readable target is the one the sandbox shows", function()
    H.need_sandbox()
    sb.config.network = "open"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local outside = H.tmpdir() .. "/outside.txt" -- under the host's /tmp: invisible inside
    vim.fn.writefile({ "outside-content" }, outside)
    vim.uv.fs_symlink(outside, project .. "/to-tmp")
    vim.uv.fs_symlink("/etc/hostname", project .. "/to-etc")
    vim.fn.writefile({ "in" }, project .. "/plain.txt")
    vim.uv.fs_symlink("plain.txt", project .. "/to-plain")
    local p = sb.plan({ "bash", "-c", 'echo "tmp=[$(cat to-tmp 2>&1)]"; echo "etc=[$(cat to-etc | wc -c)]"; echo "plain=[$(cat to-plain)]"' }, project, tmp)
    local by = {}
    for _, l in ipairs(p.symlinks) do
      by[vim.fs.basename(l.path)] = l
    end
    H.ok(by["to-tmp"] and by["to-etc"], "both escaping links are listed")
    H.eq(nil, by["to-plain"])
    H.eq(false, by["to-tmp"].readable)
    H.eq(true, by["to-etc"].readable)
    local cmd, err, h = sb.wrap(p.agent.cmd, project, tmp, { plan = p })
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    H.no_match(r.stdout, "outside-content", true)
    H.match(r.stdout, "plain=[in]", true)
    H.no_match(r.stdout, "etc=[0]", true)
  end)
end)
