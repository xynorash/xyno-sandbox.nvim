-- Eighth round, the proxy: the address check at both sides of every boundary and the pump (survivors of the mutation run).
local H = require("xynotest.helpers")
if H.os ~= "linux" then
  H.skip_file("needs linux")
end
local net = require("xyno_sandbox.net")
local uv = vim.uv

-- ------------------------------------------------------------------ (8) the address check, both sides of every edge
describe("is_public_ip: both sides of every boundary", function()
  local net = require("xyno_sandbox.net")
  local function pub(ip)
    return net.is_public_ip(ip)
  end
  local function edges(list)
    for _, e in ipairs(list) do
      H.eq(e[2], pub(e[1]), e[1])
    end
  end

  it("IPv4 ranges: first/last address inside and the neighbour outside", function()
    edges({
      { "0.0.0.0", false },
      { "0.255.255.255", false },
      { "1.0.0.0", true },
      { "9.255.255.255", true },
      { "10.0.0.0", false },
      { "10.255.255.255", false },
      { "11.0.0.0", true },
      { "100.63.255.255", true },
      { "100.64.0.0", false },
      { "100.127.255.255", false },
      { "100.128.0.0", true },
      { "126.255.255.255", true },
      { "127.0.0.0", false },
      { "127.255.255.255", false },
      { "128.0.0.0", true },
      { "169.253.255.255", true },
      { "169.254.0.0", false },
      { "169.254.255.255", false },
      { "169.255.0.0", true },
      { "172.15.255.255", true },
      { "172.16.0.0", false },
      { "172.31.255.255", false },
      { "172.32.0.0", true },
      { "192.0.0.0", false },
      { "192.0.0.255", false },
      { "192.0.1.0", true },
      { "192.0.2.0", false },
      { "192.0.2.255", false },
      { "192.0.3.0", true },
      { "192.1.0.0", true },
      { "192.167.255.255", true },
      { "192.168.0.0", false },
      { "192.168.255.255", false },
      { "192.169.0.0", true },
      { "198.17.255.255", true },
      { "198.18.0.0", false },
      { "198.19.255.255", false },
      { "198.20.0.0", true },
      { "198.51.99.255", true },
      { "198.51.100.0", false },
      { "198.51.100.255", false },
      { "198.51.101.0", true },
      { "203.0.112.255", true },
      { "203.0.113.0", false },
      { "203.0.113.255", false },
      { "203.0.114.0", true },
      { "223.255.255.255", true },
      { "224.0.0.0", false },
      { "239.255.255.255", false },
      { "255.255.255.255", false },
      { "93.184.216.34", true },
    })
  end)

  it("octets: 255 parses, 256 does not; shapes that are not an address are refused", function()
    edges({
      { "8.8.8.255", true },
      { "8.8.8.256", false },
      { "8.8.256.8", false },
      { "8.256.8.8", false },
      { "256.8.8.8", false },
      { "8.8.8", false },
      { "8.8.8.8.8", false },
      { "8.8.8.", false },
      { ".8.8.8", false },
      { "8.8.8.8x", false },
      { " 8.8.8.8", false },
      { "", false },
      { "8.8.8.-1", false },
      { "08.8.8.8", true },
    })
  end)

  it("IPv6: loopback / unspecified / mapped / v4-compatible / NAT64", function()
    edges({
      { "::", false },
      { "::1", false },
      { "::2", false },
      { "::ffff:0:0", false },
      { "::ffff:8.8.8.8", true },
      { "::ffff:127.0.0.1", false },
      { "::ffff:808:808", true },
      { "::8.8.8.8", true },
      { "::7f00:1", false },
      { "64:ff9b::808:808", true },
      { "64:ff9b::7f00:1", false },
      { "64:ff9b::a00:1", false },
      { "64:ff9b:1::808:808", false },
      { "0:0:0:0:1:ffff:7f00:1", false },
      { "0:0:0:0:1:ffff:808:808", false },
      { "1:0:0:0:0:ffff:808:808", false },
      { "65:ff9b::808:808", false },
    })
  end)

  it("IPv6: link-local, unique local, multicast, documentation, 6to4 edges", function()
    edges({
      { "fe7f:ffff::1", true },
      { "fe80::", false },
      { "febf:ffff::1", false },
      { "fec0::1", true },
      { "fbff::1", true },
      { "fc00::", false },
      { "fdff:ffff::1", false },
      { "fe00::1", true },
      { "feff::1", true },
      { "ff00::", false },
      { "ffff::1", false },
      { "2001:db7::1", true },
      { "2001:db8::", false },
      { "2001:db8:ffff::1", false },
      { "2001:db9::1", true },
      { "2000:db8::1", true },
      { "2002:808:808::1", true },
      { "2002:7f00:1::1", false },
      { "2002:a00:1::1", false },
      { "2003:808:808::1", true },
      { "2606:4700:4700::1111", true },
    })
  end)

  it("IPv6 parsing: eight groups, :: anywhere once, too long, bad groups, zone ids, mixed tails", function()
    edges({
      { "2606:4700:4700:0:0:0:0:1111", true },
      { "2606:4700:4700:0:0:0:0:0:1111", false },
      { "2606:4700:4700:0:0:0:1111", false },
      { "2606::4700::1111", false },
      { "2606:4700:4700:0:0:0:0::", true },
      { "2606:4700:4700:0:0:0::1", true },
      { "2606:4700:4700:0:0:0:0::1", false },
      { "2606::2:3:4:5:6:7", true },
      { "2606:2:3:4:5:6:7::", true },
      { "2606:2:3:4:5:6:7:8:9::", false },
      { "2606:4700:4700::11111", false },
      { "2606:4700:4700::zzzz", false },
      { "2606:4700:4700::1111%eth0", true },
      { "fe80::1%eth0", false },
      { "::ffff:8.8.8.256", false },
      { "::ffff:8.8.8", false },
      { "2606:4700:4700::0001", true },
      { ":", false },
      { ":::", false },
      { "1:2:3:4:5:6:7", false },
    })
  end)
end)

describe("is_public_ip: an IPv4 address inside an IPv6 one is judged by the same rules, byte for byte", function()
  local net = require("xyno_sandbox.net")
  local SAMPLES = {
    "8.8.8.8",
    "1.2.3.4",
    "10.9.8.7",
    "11.9.8.7",
    "100.64.5.6",
    "100.128.5.6",
    "127.9.8.7",
    "169.254.5.6",
    "172.16.5.4",
    "172.31.5.4",
    "172.32.5.4",
    "192.0.2.7",
    "192.0.3.7",
    "192.168.5.4",
    "198.18.5.6",
    "198.51.100.7",
    "198.51.101.7",
    "203.0.113.9",
    "203.0.114.9",
    "224.5.6.7",
    "223.5.6.7",
    "0.5.6.7",
    "93.184.216.34",
    -- the last byte decides nothing for the verdict but moves the third one when the arithmetic is off by one
    "192.0.2.0",
    "192.0.2.255",
    "192.0.3.0",
    "198.51.100.0",
    "198.51.100.255",
    "198.51.101.255",
    "203.0.113.0",
    "203.0.113.255",
    "203.0.112.255",
    "172.16.0.0",
    "172.31.255.255",
    "100.64.0.0",
    "100.127.255.255",
    "192.168.255.255",
    "192.0.0.255",
    "169.254.255.255",
    "198.19.255.255",
    "223.255.255.255",
    "1.255.255.255",
  }
  local function hex(ip)
    local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return ("%x"):format(a * 256 + b), ("%x"):format(c * 256 + d)
  end
  for _, ip in ipairs(SAMPLES) do
    it(ip .. " in mapped, compatible, NAT64, 6to4 and dotted forms", function()
      local want = net.is_public_ip(ip)
      local hi, lo = hex(ip)
      H.eq(want, net.is_public_ip("::ffff:" .. hi .. ":" .. lo), "mapped")
      H.eq(want, net.is_public_ip("::ffff:" .. ip), "mapped dotted")
      H.eq(want, net.is_public_ip("::" .. hi .. ":" .. lo), "compatible")
      H.eq(want, net.is_public_ip("64:ff9b::" .. hi .. ":" .. lo), "NAT64")
      H.eq(want, net.is_public_ip("64:ff9b::" .. ip), "NAT64 dotted")
      H.eq(want, net.is_public_ip("2002:" .. hi .. ":" .. lo .. "::1"), "6to4")
    end)
  end
end)

-- ------------------------------------------------------------------ the pumps and the connection state
local servers = {}
after_each(function()
  for _, srv in ipairs(servers) do
    if not srv:is_closing() then
      srv:close()
    end
  end
  servers = {}
  net.resolver = nil
  net.allow_private = nil
end)

local function wait_for(pred, ms)
  return vim.wait(ms or 8000, pred, 10)
end

--- A host-side TCP server. `on_conn(c)` gets each accepted socket; `on_data(c, chunk)` each chunk.
local function listen(on_conn, on_data)
  local srv = uv.new_tcp()
  assert(srv:bind("127.0.0.1", 0))
  srv:listen(8, function()
    local c = uv.new_tcp()
    srv:accept(c)
    if on_conn then
      on_conn(c)
    end
    c:read_start(function(err, chunk)
      if err or not chunk then
        return
      end
      if on_data then
        on_data(c, chunk)
      end
    end)
  end)
  servers[#servers + 1] = srv
  return srv:getsockname().port
end

local function start_proxy(hosts, opts)
  local dir = H.tmpdir()
  local p, err = net.start(vim.tbl_extend("force", { sock = dir .. "/p.sock", hosts = hosts }, opts or {}))
  assert(p, err)
  return p
end

--- Connect to the proxy socket and send a CONNECT line; returns { pipe, got = function() ... }.
local function client(p, host, port, extra)
  local pipe = uv.new_pipe(false)
  local c = { pipe = pipe, buf = "", eof = false }
  pipe:connect(p.sock, function(err)
    assert(not err, err)
    pipe:read_start(function(_, chunk)
      if chunk then
        c.buf = c.buf .. chunk
      else
        c.eof = true
      end
    end)
    pipe:write(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"):format(host, port, host, port) .. (extra or ""))
  end)
  return c
end

local function tunnel_ready(c)
  return c.buf:find("\r\n\r\n", 1, true) ~= nil
end

describe("the proxy closes what it refuses and counts what it holds", function()
  it("a refused request is answered AND the connection is closed (EOF reaches the client)", function()
    local p = start_proxy({ "allowed.test" })
    local pipe = uv.new_pipe(false)
    local buf, eof = "", false
    pipe:connect(p.sock, function(err)
      assert(not err, err)
      pipe:read_start(function(_, chunk)
        if chunk then
          buf = buf .. chunk
        else
          eof = true
        end
      end)
      pipe:write("GET http://allowed.test/ HTTP/1.1\r\n\r\n")
    end)
    H.ok(
      wait_for(function()
        return eof
      end),
      "the proxy never closed the connection: " .. buf
    )
    H.match(buf, "405", true)
    pipe:close()
    p.close()
  end)

  it("a client that leaves before it sent anything is dropped from the count", function()
    local p = start_proxy({ "allowed.test" })
    local pipe = uv.new_pipe(false)
    local connected = false
    pipe:connect(p.sock, function()
      connected = true
    end)
    H.ok(wait_for(function()
      return connected and p.conns == 1
    end))
    pipe:close()
    H.ok(
      wait_for(function()
        return p.conns == 0
      end),
      "conns stays at " .. p.conns
    )
    p.close()
  end)

  it("over max_conns the next connection is refused with 503 and the count is not inflated", function()
    local p = start_proxy({ "allowed.test" }, { max_conns = 1 })
    local first = uv.new_pipe(false)
    local ok1 = false
    first:connect(p.sock, function()
      ok1 = true
    end)
    H.ok(wait_for(function()
      return ok1 and p.conns == 1
    end))
    local pipe = uv.new_pipe(false)
    local buf = ""
    pipe:connect(p.sock, function(err)
      assert(not err, err)
      pipe:read_start(function(_, chunk)
        buf = buf .. (chunk or "")
      end)
    end)
    H.ok(
      wait_for(function()
        return buf:find("503", 1, true) ~= nil
      end),
      buf
    )
    H.ok(
      wait_for(function()
        return p.conns == 1
      end),
      "conns " .. p.conns
    )
    first:close()
    pipe:close()
    p.close()
  end)

  it("a connection is released when both directions ended, not when one did", function()
    local upstream_sock
    local port = listen(function(c)
      upstream_sock = c
    end, function(c, chunk)
      c:write("echo:" .. chunk)
    end)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local c = client(p, "allowed.test", port)
    H.ok(
      wait_for(function()
        return tunnel_ready(c)
      end),
      c.buf
    )
    H.eq(1, p.conns)
    -- the client stops sending (half-close) but the upstream still answers
    c.pipe:shutdown()
    uv.sleep(100)
    vim.wait(100)
    H.eq(1, p.conns, "one direction ended: the tunnel is still open")
    upstream_sock:close()
    H.ok(
      wait_for(function()
        return p.conns == 0
      end),
      "both ended but conns is " .. p.conns
    )
    c.pipe:close()
    p.close()
  end)
end)

describe("the pumps move everything, in order, with back pressure", function()
  it("3 MB client -> upstream and 3 MB upstream -> client arrive complete", function()
    local N = 3 * 1024 * 1024
    local blob = {}
    for i = 1, 64 do
      blob[i] = string.char((i * 7) % 251 + 1):rep(1024)
    end
    local chunk64k = table.concat(blob)
    local data = {}
    for i = 1, N / #chunk64k do
      data[i] = chunk64k:sub(i % 7 + 1) .. chunk64k:sub(1, i % 7)
    end
    local payload = table.concat(data)
    local got_up, sent_down = 0, false
    local up_hash = vim.fn.sha256("")
    local recv = {}
    local port = listen(nil, function(c, chunk)
      got_up = got_up + #chunk
      recv[#recv + 1] = chunk
      if got_up >= #payload and not sent_down then
        sent_down = true
        c:write(payload)
      end
    end)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local c = client(p, "allowed.test", port)
    H.ok(wait_for(function()
      return tunnel_ready(c)
    end))
    local head_end = select(2, c.buf:find("\r\n\r\n", 1, true))
    c.buf = c.buf:sub(head_end + 1)
    c.pipe:write(payload)
    H.ok(
      wait_for(function()
        return #c.buf >= #payload
      end, 30000),
      "client got " .. #c.buf .. " of " .. #payload
    )
    H.eq(#payload, got_up)
    H.ok(table.concat(recv) == payload, "upstream got the bytes in order")
    H.ok(c.buf == payload, "client got the bytes in order")
    c.pipe:close()
    p.close()
  end)

  it("bytes sent in the same packet as the CONNECT head reach the upstream first", function()
    local seen = ""
    local port = listen(nil, function(_, chunk)
      seen = seen .. chunk
    end)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local c = client(p, "allowed.test", port, "EARLY-BYTES")
    H.ok(
      wait_for(function()
        return seen == "EARLY-BYTES"
      end),
      seen
    )
    c.pipe:write("-LATE")
    H.ok(
      wait_for(function()
        return seen == "EARLY-BYTES-LATE"
      end),
      seen
    )
    c.pipe:close()
    p.close()
  end)

  it("an upstream that resets the connection ends the tunnel (the client sees EOF)", function()
    local port = listen(function(c)
      vim.defer_fn(function()
        c:close()
      end, 50)
    end)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local c = client(p, "allowed.test", port)
    H.ok(
      wait_for(function()
        return c.eof
      end),
      "the client never saw the end"
    )
    c.pipe:close()
    p.close()
  end)
end)

describe("is_public_ip: the reserved ::/8 is refused except the embedded IPv4 forms", function()
  local net = require("xyno_sandbox.net")
  it("each group after the NAT64 prefix must be zero for the prefix to count", function()
    for _, ip in ipairs({
      "64:ff9b:1::808:808",
      "64:ff9b:0:1::808:808",
      "64:ff9b:0:0:1:0:808:808",
      "64:ff9b::1:808:808",
      "64:ff9b:0:0:0:1:808:808",
      "64:ff9a::808:808",
    }) do
      H.not_ok(net.is_public_ip(ip), ip)
    end
    H.ok(net.is_public_ip("64:ff9b::808:808"))
    H.ok(net.is_public_ip("64:ff9b:0:0:0:0:808:808"))
  end)
  it("::a:b:c with a group before the last two that is neither 0 nor ffff is not an embedded address", function()
    for _, ip in ipairs({ "::1:808:808", "::fffe:808:808", "::2:808:808", "0:0:0:0:2:0:808:808", "0:0:0:1::808:808" }) do
      H.not_ok(net.is_public_ip(ip), ip)
    end
    H.ok(net.is_public_ip("::ffff:808:808"))
    H.ok(net.is_public_ip("::808:808"))
  end)
  it("::/8 ends at 00ff: ff::1 is refused, 100::1 is not in it", function()
    H.not_ok(net.is_public_ip("ff::1"))
    H.not_ok(net.is_public_ip("fe::1"))
    H.ok(net.is_public_ip("100::1"))
  end)
end)

-- ------------------------------------------------------------------ request parsing and limits
local function raw(p, data, until_)
  local pipe = uv.new_pipe(false)
  local r = { buf = "", eof = false }
  pipe:connect(p.sock, function(err)
    assert(not err, err)
    pipe:read_start(function(_, chunk)
      if chunk then
        r.buf = r.buf .. chunk
      else
        r.eof = true
      end
    end)
    if data then
      pipe:write(data)
    end
  end)
  r.pipe = pipe
  return r
end

describe("the CONNECT target is validated", function()
  local function refused(target)
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT " .. target .. " HTTP/1.1\r\n\r\n")
    H.ok(
      wait_for(function()
        return r.eof
      end),
      target .. ": " .. r.buf
    )
    r.pipe:close()
    p.close()
    return r.buf, p.decisions
  end

  it("no port, a port of 0, 65536, letters or a raw IP: 403 and a refusal in the log", function()
    for _, t in ipairs({
      "allowed.test",
      "allowed.test:0",
      "allowed.test:65536",
      "allowed.test:99999",
      "allowed.test:x",
      "127.0.0.1:443",
      "[::1]:443",
      ":443",
      "a:443",
    }) do
      local buf, decisions = refused(t)
      H.match(buf, "HTTP/1.1 403", true, t .. ": " .. buf)
      H.eq(false, decisions[1].allowed, t)
      H.eq("not a DNS host name", decisions[1].reason, t)
      H.match(buf, "is not an allowed DNS host name", true, t)
    end
  end)

  it("the ports 1 and 65535 are valid ports (refused only for the allowlist)", function()
    for _, port in ipairs({ 1, 65535 }) do
      local buf, decisions = refused("other.test:" .. port)
      H.match(buf, "not on the network allowlist", true, buf)
      H.eq(port, decisions[1].port)
    end
  end)

  it("a name that is not on the list is 403, with the host and port in the log", function()
    local buf, decisions = refused("other.test:443")
    H.match(buf, "HTTP/1.1 403", true)
    H.eq("other.test", decisions[1].host)
    H.eq(443, decisions[1].port)
    H.match(decisions[1].reason, "allowlist", true)
  end)

  it("a method other than CONNECT is 405", function()
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "GET http://allowed.test/ HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(r.buf, "HTTP/1.1 405", true)
    H.eq("not CONNECT", p.decisions[1].reason)
    H.eq(0, p.decisions[1].port)
    r.pipe:close()
    p.close()
  end)

  it("a target of more than 80 characters is cut in the log and in the answer", function()
    local long = ("a"):rep(90) .. ".test:99999"
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT " .. long .. " HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.eq(80, #p.decisions[1].host)
    H.match(r.buf, ("a"):rep(80) .. " is not", true, r.buf)
    H.no_match(r.buf, ("a"):rep(81), true, r.buf)
    r.pipe:close()
    p.close()
  end)
end)

describe("resolution failures are told apart in the log", function()
  it("a name that only resolves to a private address: 502 'resolves only to non-public addresses'", function()
    net.resolver = function(_, cb)
      cb({ "10.0.0.5" })
    end
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(r.buf, "HTTP/1.1 502", true)
    H.match(p.decisions[1].reason, "non-public", true)
    r.pipe:close()
    p.close()
  end)

  it("a name that does not resolve: 502 'cannot resolve: <why>'", function()
    net.resolver = function(_, cb)
      cb(nil, "NXDOMAIN")
    end
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(r.buf, "HTTP/1.1 502", true)
    H.eq("cannot resolve: NXDOMAIN", p.decisions[1].reason)
    r.pipe:close()
    p.close()
  end)

  it("an empty answer is 'cannot resolve', not 'non-public'", function()
    net.resolver = function(_, cb)
      cb({}, "no address")
    end
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT allowed.test:443 HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(p.decisions[1].reason, "cannot resolve", true)
    r.pipe:close()
    p.close()
  end)

  it("every address refused to connect: 502 'cannot connect'", function()
    local srv = uv.new_tcp()
    assert(srv:bind("127.0.0.1", 0))
    local port = srv:getsockname().port
    srv:close() -- (nothing listens there any more)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local r = raw(p, "CONNECT allowed.test:" .. port .. " HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(r.buf, "HTTP/1.1 502", true)
    H.match(r.buf, "cannot connect to allowed.test", true)
    H.eq("connect failed", p.decisions[1].reason)
    r.pipe:close()
    p.close()
  end)

  it("the system resolver reports a name that does not exist as a refusal, not a crash", function()
    local p = start_proxy({ "nonexistent-host.invalid" })
    local r = raw(p, "CONNECT nonexistent-host.invalid:443 HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end, 20000))
    H.match(r.buf, "HTTP/1.1 502", true)
    H.match(p.decisions[1].reason, "cannot resolve", true)
    r.pipe:close()
    p.close()
  end)
end)

describe("the proxy's own limits", function()
  it("a socket path of 100 bytes binds, 101 is refused with the length in the message", function()
    local dir = H.tmpdir()
    local pad = 100 - #dir - 1
    if pad < 1 then
      return
    end
    local ok100, err100 = net.start({ sock = dir .. "/" .. ("s"):rep(pad), hosts = { "allowed.test" } })
    H.ok(ok100, err100)
    ok100.close()
    local no, err = net.start({ sock = dir .. "/" .. ("s"):rep(pad + 1), hosts = { "allowed.test" } })
    H.eq(nil, no)
    H.match(err, "too long (101 bytes)", true)
  end)

  it("the socket is 0600", function()
    local p = start_proxy({ "allowed.test" })
    H.eq(tonumber("600", 8), bit.band(uv.fs_stat(p.sock).mode, tonumber("777", 8)))
    p.close()
  end)

  it("the log keeps the last 200 decisions, oldest dropped first", function()
    local p = start_proxy({ "allowed.test" })
    for i = 1, 203 do
      local r = raw(p, ("CONNECT h%d.test:443 HTTP/1.1\r\n\r\n"):format(i))
      H.ok(
        wait_for(function()
          return r.eof
        end),
        "request " .. i
      )
      r.pipe:close()
    end
    H.eq(200, #p.decisions)
    H.eq("h4.test", p.decisions[1].host)
    H.eq("h203.test", p.decisions[200].host)
    p.close()
  end)

  it("a head of exactly 8192 bytes is waited for, 8193 is 431", function()
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, ("A"):rep(8192))
    vim.wait(400)
    H.eq("", r.buf, "8192 bytes: still waiting")
    r.pipe:write("A")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.match(r.buf, "HTTP/1.1 431", true)
    r.pipe:close()
    p.close()
  end)

  it("a head that never completes is answered with 408 after the head timeout", function()
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT allowed.test:443 HTTP/1.1\r\n")
    H.ok(
      wait_for(function()
        return r.eof
      end, 16000),
      "no timeout answer: " .. r.buf
    )
    H.match(r.buf, "HTTP/1.1 408", true)
    r.pipe:close()
    p.close()
  end)

  it("a request in two packets is put together", function()
    local port = listen(nil, nil)
    net.allow_private = true
    net.resolver = function(_, cb)
      cb({ "127.0.0.1" })
    end
    local p = start_proxy({ "allowed.test:" .. port })
    local r = raw(p, ("CONNECT allowed.test:%d HTTP/1.1\r\nHost: x"):format(port))
    vim.wait(200)
    H.eq("", r.buf)
    r.pipe:write("\r\n\r\n")
    H.ok(
      wait_for(function()
        return r.buf:find("HTTP/1.1 200", 1, true) ~= nil
      end),
      r.buf
    )
    r.pipe:close()
    p.close()
  end)
end)

describe("the head and what follows it", function()
  it("an empty head ('\\r\\n\\r\\n' alone) is a request that is not CONNECT: 405, not a wait", function()
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "\r\n\r\n")
    H.ok(
      wait_for(function()
        return r.eof
      end, 3000),
      "the proxy waited: " .. r.buf
    )
    H.match(r.buf, "HTTP/1.1 405", true)
    r.pipe:close()
    p.close()
  end)

  it("a target without a port is logged with the whole target, port 0", function()
    local p = start_proxy({ "allowed.test" })
    local r = raw(p, "CONNECT noport.test HTTP/1.1\r\n\r\n")
    H.ok(wait_for(function()
      return r.eof
    end))
    H.eq("noport.test", p.decisions[1].host)
    H.eq(0, p.decisions[1].port)
    r.pipe:close()
    p.close()
  end)

  it("ONE byte sent with the CONNECT head reaches the upstream, and so do two", function()
    for _, extra in ipairs({ "Z", "ZZ" }) do
      local seen = ""
      local port = listen(nil, function(_, chunk)
        seen = seen .. chunk
      end)
      net.allow_private = true
      net.resolver = function(_, cb)
        cb({ "127.0.0.1" })
      end
      local p = start_proxy({ "allowed.test:" .. port })
      local c = client(p, "allowed.test", port, extra)
      H.ok(
        wait_for(function()
          return seen == extra
        end),
        "upstream saw " .. vim.inspect(seen)
      )
      c.pipe:close()
      p.close()
    end
  end)
end)
