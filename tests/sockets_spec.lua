-- Host pathname unix sockets must not be connectable from inside the sandbox: ssh-agent, systemd
-- varlink, polkit, journal, the user session, tmux, a project's own sockets. A connectable host
-- socket bypasses the network filter and leaks credentials (ssh-agent signs for the agent).
-- Red-team finding 2. The only connectable socket is the proxy's.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local harness = require("xynotest.harness")

if vim.fn.executable("python3") ~= 1 then
  H.skip_file("python3 is needed for the connect() sweep")
end

local saved = vim.deepcopy(sb.config)
local cleanup = {}
local set = {}
local uid = vim.uv.os_get_passwd().uid
local rnd = tostring(vim.uv.hrtime()):sub(-8)

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
  for i = #cleanup, 1, -1 do
    pcall(cleanup[i])
  end
  cleanup = {}
end)

--- A listening unix socket at `path` (the kernel completes connect() on the backlog, no accept needed).
local function listen(path)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local pipe = vim.uv.new_pipe(false)
  local ok, err = pipe:bind(path)
  if ok and not vim.uv.fs_stat(path) then
    ok, err = nil, "bind succeeded but no socket file exists (path over the sockaddr_un limit)"
  end
  if not ok then
    pipe:close()
    return nil, err
  end
  pipe:listen(8, function() end)
  cleanup[#cleanup + 1] = function()
    pipe:close()
    vim.uv.fs_unlink(path)
  end
  return path
end

-- walks the roots, tries connect() on every socket file, prints the connectable ones
local PY = [[
import os, socket, stat, sys
skip = {"/proc", "/sys", "/dev", "/usr", "/nix", "/var/cache", "/var/log", "/var/lib/pacman", "/var/lib/flatpak", "/var/lib/docker"}
found, n = [], 0
for root in sys.argv[1:]:
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = [d for d in dns if os.path.join(dp, d) not in skip]
        for name in dns + fns:
            p = os.path.join(dp, name)
            n += 1
            try:
                if stat.S_ISSOCK(os.lstat(p).st_mode):
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(1)
                    try:
                        s.connect(p)
                        found.append(p)
                    except OSError:
                        pass
                    finally:
                        s.close()
            except OSError:
                pass
print("SCANNED", n)
for p in found:
    print("CONNECTABLE", p)
]]

--- Connectable socket paths found inside the sandbox of `project`, scanning `roots`.
local function sweep(project, roots)
  H.need_sandbox()
  local tmp = H.tmpdir()
  local cmd, err, h = sb.wrap(vim.list_extend({ "python3", "-I", "-c", PY }, roots), project, tmp)
  H.ok(cmd, err)
  local r = vim.system(cmd, { text = true, cwd = project }):wait(120000)
  local plan = h.plan
  h.release()
  local found = {}
  for p in (r.stdout or ""):gmatch("CONNECTABLE ([^\n]+)") do
    found[#found + 1] = p
  end
  H.match(r.stdout or "", "SCANNED", true, "the sweep ran: " .. (r.stderr or ""))
  return found, plan
end

--- Host canary sockets in every place a credential or a service socket lives.
local function canaries(project)
  local c = {}
  c.project = listen(project .. "/xyno-canary-project.sock") -- control: INSIDE the project and not hidden would be found
  c.tmp = listen(vim.fn.tempname() .. "-canary.sock")
  c.vartmp = listen("/var/tmp/xyno-canary-" .. rnd .. ".sock")
  local run = "/run/user/" .. uid
  if vim.uv.fs_stat(run) then
    c.run = listen(run .. "/xyno-canary-" .. rnd .. ".sock")
  end
  return c
end

describe("host sockets", function()
  for _, mode in ipairs({ "allowlist", "denylist" }) do
    it(("home = %s: a connect() sweep of /run, /var, /etc, /tmp, /mnt, /srv, /opt and the ssh-agent canary dir finds only the proxy socket"):format(mode), function()
      sb.config.home = mode
      sb.config.network = "filtered"
      local project = H.tmpdir()
      local c = canaries(project)
      -- an ssh-agent style socket in a place no directory rule covers: found through $SSH_AUTH_SOCK
      local home = vim.uv.os_homedir()
      local agent_dir = home .. "/.cache/xc-a-" .. rnd
      cleanup[#cleanup + 1] = function()
        vim.fn.delete(agent_dir, "rf")
      end
      local agent = listen(agent_dir .. "/a.sock")
      if not agent then
        return require("xynotest.harness").skip("$HOME is so deep that a unix socket path below it exceeds 107 bytes")
      end
      setenv("SSH_AUTH_SOCK", agent)
      local roots = { "/run", "/var", "/etc", "/tmp", "/mnt", "/srv", "/opt", "/media", agent_dir, vim.fs.dirname(c.tmp) }
      local found, plan = sweep(project, roots)
      local allowed = { [plan.net.sock] = true }
      for _, p in ipairs(found) do
        H.ok(allowed[p], "a host socket is connectable inside the sandbox: " .. p)
      end
      H.ok(vim.tbl_contains(found, plan.net.sock), "the sweep does see the one socket that must work (the proxy's)")
      -- the project socket is a project file: hidden by the plan (project socket), so not connectable either
      local seen = {}
      for _, h in ipairs(plan.hidden) do
        seen[h.path] = h.why
      end
      H.eq("project socket", seen[c.project])
    end)
  end

  it("the detector works: a socket the policy does not cover IS found (a socket in a writable scratch dir)", function()
    sb.config.network = "open"
    local project = H.tmpdir()
    local tmp = H.tmpdir() -- bound writable into the sandbox: the policy cannot hide what lives in it
    local s = listen(tmp .. "/open.sock")
    H.need_sandbox()
    local cmd, err, h = sb.wrap({ "python3", "-I", "-c", PY, tmp }, project, tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    H.match(r.stdout or "", "CONNECTABLE " .. s, true, (r.stdout or "") .. (r.stderr or ""))
  end)

  it("the masked directories are the empty tmpfs the plan lists (/run, /var/tmp, /tmp), nothing of the host is under them", function()
    sb.config.network = "open"
    H.need_sandbox()
    local project = H.tmpdir()
    local c = canaries(project)
    local tmp = H.tmpdir()
    local script = 'ls -A /run | head -20; echo ---; ls -A /var/tmp | head; echo ---; ls -A /tmp | head -3; echo ---; '
      .. '[ -e /run/user/' .. uid .. ' ] && echo RUN-USER-VISIBLE; [ -e "' .. (c.vartmp or "") .. '" ] && echo VARTMP-VISIBLE; '
      .. '[ -e "' .. (c.tmp or "") .. '" ] && echo TMP-VISIBLE; echo done'
    local cmd, err, h = sb.wrap({ "bash", "-c", script }, project, tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    local out = (r.stdout or "") .. (r.stderr or "")
    H.match(out, "done", true, out)
    for _, bad in ipairs({ "RUN-USER-VISIBLE", "VARTMP-VISIBLE", "TMP-VISIBLE" }) do
      H.no_match(out, bad, true, out)
    end
  end)

  it("a socket named by $SSH_AUTH_SOCK / $XDG_RUNTIME_DIR outside the masked directories is hidden (denylist view)", function()
    sb.config.home = "denylist"
    local home = vim.uv.os_homedir()
    local dir = home .. "/.cache/xc-e-" .. rnd
    cleanup[#cleanup + 1] = function()
      vim.fn.delete(dir, "rf")
    end
    local agent = listen(dir .. "/a.sock")
    if not agent then
      return require("xynotest.harness").skip("$HOME is so deep that a unix socket path below it exceeds 107 bytes")
    end
    setenv("SSH_AUTH_SOCK", agent or "")
    setenv("XDG_RUNTIME_DIR", dir)
    local p = sb.plan({ "agent" }, H.tmpdir(), H.tmpdir())
    local by = {}
    for _, h in ipairs(p.hidden) do
      by[h.path] = h.why
    end
    H.eq("socket named by $SSH_AUTH_SOCK", by[agent])
    H.eq("socket named by $XDG_RUNTIME_DIR", by[dir])
    H.has(p.env_strip, "SSH_AUTH_SOCK")
  end)

  it("a project that is /tmp (or another shared system directory) is not mounted writable and gets no placeholders", function()
    for _, shared in ipairs({ "/tmp", "/var/tmp", "/run", "/", vim.uv.os_homedir() .. "/.." }) do
      local p = sb.plan({ "agent" }, vim.fs.normalize(shared), H.tmpdir())
      for _, w in ipairs(p.writable) do
        H.not_ok(w.path == vim.fs.normalize(shared) and w.why == "project", "mounted writable: " .. shared)
      end
      H.eq({}, p.guard_files, shared)
      for _, m in ipairs(p.masks) do
        H.not_ok(m.cleanup, "placeholder mask in " .. shared .. ": " .. m.path)
      end
    end
  end)
end)
