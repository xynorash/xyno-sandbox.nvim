-- Network egress control: the allowlist (pure) and the filtering forward proxy (vim.uv).
--
-- Design (the same shape as Anthropic's sandbox-runtime): the sandbox has NO network namespace
-- of its own beyond a private loopback (bwrap --unshare-net). The only way out is a unix socket
-- bind-mounted into the sandbox; a tiny relay inside (relay.lua) listens on 127.0.0.1:3128 and
-- pipes into it, and the proxy in this file runs in Neovim, outside the sandbox. HTTPS_PROXY in
-- the sandbox points at the relay.
--
-- The proxy speaks only HTTP CONNECT (HTTPS). The decision uses the hostname in the CONNECT line
-- and the port; there is no TLS interception, so the content is never seen and the TLS SNI is not
-- compared with the CONNECT host (see the README). It refuses
--   * raw IP literals and anything that is not a DNS name,
--   * hosts and ports that are not on the allowlist,
--   * allowed names that RESOLVE to loopback, private, link-local, multicast or documentation
--     addresses (so an allowed name cannot be pointed at the machine's own services),
-- and it connects to the address that passed the check (no second lookup).
--
-- Why pure Lua on vim.uv: it adds no dependency (no socat, no python, no Go binary), it runs in
-- the editor that already has to outlive the agent, and a few hundred lines of CONNECT handling
-- are easier to audit than a packaged proxy. The cost is that the proxy shares Neovim's event
-- loop: it is only as available as the editor is, which is also when the agent should run.
local uv = vim.uv
local M = {}

M.resolver = nil -- replaceable in specs: fun(host, cb(addrs, err)) instead of the system resolver
M.allow_private = false -- replaceable in specs: let a stub resolver answer with loopback

M.PORT = 3128 -- loopback port of the relay INSIDE the sandbox (its own network namespace)

--- Hosts allowed by default: the agent's API and token endpoints, and the crate registries.
--- github.com is not on it (git over https for dependencies is opt-in).
M.DEFAULT_HOSTS = { "api.anthropic.com", "platform.claude.com", "crates.io", "static.crates.io", "index.crates.io" }

local MAX_HEAD = 8192
local HEAD_TIMEOUT_MS = 10000
local IDLE_MS = 30 * 60 * 1000
local MAX_CONNS = 256

-- --------------------------------------------------------------- allowlist

--- Is `s` a DNS host name (not an IP literal)? Returns the lowercased name without a trailing dot.
--- Needs at least two labels and a last label with a letter, which also excludes 1.2.3.4, 0x7f.1,
--- 2130706433 and "localhost".
--- @return string? name, string? err
function M.hostname(s)
  if type(s) ~= "string" then
    return nil, "not a string"
  end
  s = s:lower():gsub("%.$", "")
  if s == "" or #s > 253 then
    return nil, "empty or too long"
  end
  local labels = {}
  for l in (s .. "."):gmatch("([^.]*)%.") do
    labels[#labels + 1] = l
    if #l == 0 or #l > 63 or not l:match("^[a-z0-9][a-z0-9%-]*$") or l:sub(-1) == "-" then
      return nil, "not a DNS host name (raw IPs and unusual forms are refused)"
    end
  end
  if #labels < 2 or not labels[#labels]:match("%a") then
    return nil, "not a DNS host name (raw IPs and unusual forms are refused)"
  end
  return s
end

--- Parse one allowlist entry: "host", "host:port", "*.suffix" or "*.suffix:port" (default port 443).
--- A wildcard matches any name below the suffix, not the suffix itself, and needs a suffix of at
--- least two labels ("*.com" is refused).
--- @return table? entry { host, port, wildcard, text }, string? err
function M.parse_entry(s)
  if type(s) ~= "string" or s == "" then
    return nil, "must be a non-empty string"
  end
  local body, port = s, 443
  local b, p = s:match("^(.-):(%d+)$")
  if b then
    body, port = b, tonumber(p)
    if port < 1 or port > 65535 then
      return nil, "port out of range"
    end
  elseif s:find(":", 1, true) then
    return nil, "use host or host:port (IPv6 literals are not allowed)"
  end
  local wildcard = false
  if body:sub(1, 2) == "*." then
    wildcard, body = true, body:sub(3)
  end
  local name, err = M.hostname(body)
  if not name then
    return nil, err
  end
  if wildcard and not name:find(".", 1, true) then
    return nil, "a wildcard needs a suffix of at least two labels"
  end
  return {
    host = name,
    port = port,
    wildcard = wildcard,
    text = (wildcard and "*." or "") .. name .. (port ~= 443 and (":" .. port) or ""),
  }
end

--- Normalize a list of entries (strings or parsed) and drop duplicates. Raises on a bad entry.
function M.parse_list(list)
  local out, seen = {}, {}
  for _, e in ipairs(list or {}) do
    local ent = e
    if type(e) == "string" then
      local err
      ent, err = M.parse_entry(e)
      if not ent then
        error(("bad network allowlist entry %q: %s"):format(e, err), 2)
      end
    end
    if not seen[ent.text] then
      seen[ent.text] = true
      out[#out + 1] = ent
    end
  end
  return out
end

--- The first entry that allows host:port, or nil. `host` must be a normalized name.
function M.match(entries, host, port)
  for _, e in ipairs(entries) do
    if e.port == port then
      if e.wildcard then
        if #host > #e.host + 1 and host:sub(-(#e.host + 1)) == "." .. e.host then
          return e
        end
      elseif host == e.host then
        return e
      end
    end
  end
end

-- ------------------------------------------------------------ address check

local function v4_bytes(ip)
  local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then
    return nil
  end
  local t = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
  for _, n in ipairs(t) do
    if n > 255 then
      return nil
    end
  end
  return t
end

local function public_v4(t)
  local a, b, c = t[1], t[2], t[3]
  if a == 0 or a == 10 or a == 127 or a >= 224 then
    return false
  end
  if a == 100 and b >= 64 and b <= 127 then
    return false
  end
  if a == 169 and b == 254 then
    return false
  end
  if a == 172 and b >= 16 and b <= 31 then
    return false
  end
  if a == 192 and b == 0 and (c == 0 or c == 2) then
    return false
  end
  if a == 192 and b == 168 then
    return false
  end
  if a == 198 and (b == 18 or b == 19) then
    return false
  end
  if a == 198 and b == 51 and c == 100 then
    return false
  end
  if a == 203 and b == 0 and c == 113 then
    return false
  end
  return true
end

local function v6_groups(ip)
  ip = ip:gsub("%%.*$", "")
  local tail = ip:match(":(%d+%.%d+%.%d+%.%d+)$")
  if tail then
    local t = v4_bytes(tail)
    if not t then
      return nil
    end
    ip = ip:sub(1, #ip - #tail) .. ("%x:%x"):format(t[1] * 256 + t[2], t[3] * 256 + t[4])
  end
  local head, rest = ip, nil
  local dc = ip:find("::", 1, true)
  if dc then
    head, rest = ip:sub(1, dc - 1), ip:sub(dc + 2)
    if rest:find("::", 1, true) then
      return nil
    end
  end
  local function split(s)
    local g = {}
    if s ~= "" then
      for p in (s .. ":"):gmatch("([^:]*):") do
        if not p:match("^%x%x?%x?%x?$") then
          return nil
        end
        g[#g + 1] = tonumber(p, 16)
      end
    end
    return g
  end
  local h = split(head)
  if not h then
    return nil
  end
  if not rest then
    return #h == 8 and h or nil
  end
  local r = split(rest)
  if not r or #h + #r > 7 then
    return nil
  end
  local out = {}
  for _, v in ipairs(h) do
    out[#out + 1] = v
  end
  for _ = 1, 8 - #h - #r do
    out[#out + 1] = 0
  end
  for _, v in ipairs(r) do
    out[#out + 1] = v
  end
  return out
end

--- May the proxy connect to this address? Only globally routable unicast addresses pass.
--- Unparseable input is refused.
function M.is_public_ip(ip)
  local t = v4_bytes(ip)
  if t then
    return public_v4(t)
  end
  local g = v6_groups(ip)
  if not g then
    return false
  end
  local zero_to = function(n)
    for i = 1, n do
      if g[i] ~= 0 then
        return false
      end
    end
    return true
  end
  if zero_to(5) and (g[6] == 0xffff or g[6] == 0) then -- ::, ::1, ::ffff:a.b.c.d, ::a.b.c.d
    if g[6] == 0 and g[7] == 0 and g[8] <= 1 then
      return false
    end
    return public_v4({ math.floor(g[7] / 256), g[7] % 256, math.floor(g[8] / 256), g[8] % 256 })
  end
  if g[1] == 0x64 and g[2] == 0xff9b and g[3] == 0 and g[4] == 0 and g[5] == 0 and g[6] == 0 then -- NAT64
    return public_v4({ math.floor(g[7] / 256), g[7] % 256, math.floor(g[8] / 256), g[8] % 256 })
  end
  if g[1] >= 0xfe80 and g[1] <= 0xfebf then
    return false
  end -- link-local
  if g[1] >= 0xfc00 and g[1] <= 0xfdff then
    return false
  end -- unique local
  if g[1] >= 0xff00 then
    return false
  end -- multicast
  if g[1] == 0x2001 and g[2] == 0x0db8 then
    return false
  end -- documentation
  if g[1] == 0x2002 then -- 6to4 embeds an IPv4 address
    return public_v4({ math.floor(g[2] / 256), g[2] % 256, math.floor(g[3] / 256), g[3] % 256 })
  end
  return true
end

-- ------------------------------------------------------------------- proxy

local function safe_close(h)
  if h and not h:is_closing() then
    h:close()
  end
end

--- Copy a -> b with back pressure. `done()` runs once when a ended (EOF, after b was half-closed)
--- and `abort()` on any error.
local function pump(a, b, touch, done, abort)
  local function on_read(err, chunk)
    if err then
      return abort()
    end
    if not chunk then
      a:read_stop()
      return b:shutdown(function()
        done()
      end)
    end
    touch()
    a:read_stop()
    b:write(chunk, function(werr)
      if werr then
        return abort()
      end
      if not a:is_closing() then
        a:read_start(on_read)
      end
    end)
  end
  a:read_start(on_read)
end

local function default_resolve(host, cb)
  local req, err = uv.getaddrinfo(host, nil, { socktype = "stream" }, function(e, res)
    if e or not res then
      return cb(nil, tostring(e or "no address"))
    end
    local out, seen = {}, {}
    for _, r in ipairs(res) do
      if r.addr and not seen[r.addr] then
        seen[r.addr] = true
        out[#out + 1] = r.addr
      end
    end
    cb(out)
  end)
  if not req then
    cb(nil, tostring(err))
  end
end

--- Start the filtering proxy on a unix socket.
--- @param opts { sock: string, hosts: (string|table)[], resolve?: fun(host: string, cb: fun(addrs?: string[], err?: string)),
---   allow_private?: boolean, on_decision?: fun(d: table), max_conns?: integer }
---   hosts: the allowlist; allow_private and resolve exist for specs (a stub resolver).
--- @return table? proxy { sock, hosts, decisions, close() }, string? err
function M.start(opts)
  local entries = M.parse_list(opts.hosts)
  local resolve = opts.resolve or M.resolver or default_resolve
  local max_conns = opts.max_conns or MAX_CONNS
  local proxy = { sock = opts.sock, hosts = entries, decisions = {}, conns = 0 }
  if #opts.sock > 100 then -- sun_path holds 107 bytes; libuv would silently bind a truncated name
    return nil, "socket path too long (" .. #opts.sock .. " bytes): " .. opts.sock
  end
  local server = uv.new_pipe(false)
  local ok, err = server:bind(opts.sock)
  if not ok then
    safe_close(server)
    return nil, "cannot bind " .. opts.sock .. ": " .. tostring(err)
  end
  uv.fs_chmod(opts.sock, tonumber("600", 8))
  local active = {}

  local function decide(d)
    d.ts = os.time()
    if #proxy.decisions >= 200 then
      table.remove(proxy.decisions, 1)
    end
    proxy.decisions[#proxy.decisions + 1] = d
    if opts.on_decision then
      pcall(opts.on_decision, d)
    end
  end

  local function on_connection(client)
    proxy.conns = proxy.conns + 1
    local closed = false
    local upstream
    local timer = uv.new_timer()
    local last = uv.now()
    local function close_all()
      if closed then
        return
      end
      closed = true
      proxy.conns = proxy.conns - 1
      active[client] = nil
      if timer then
        timer:stop()
        safe_close(timer)
      end
      safe_close(upstream)
      safe_close(client)
    end
    active[client] = close_all
    local function reply(code, text, msg)
      if closed or client:is_closing() then
        return
      end
      client:read_stop()
      local body = "xyno-sandbox: " .. msg .. "\n"
      client:write(
        ("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"):format(
          code,
          text,
          #body,
          body
        ),
        function()
          close_all()
        end
      )
    end
    if proxy.conns > max_conns then
      return reply(503, "Service Unavailable", "too many connections")
    end
    timer:start(HEAD_TIMEOUT_MS, 0, function()
      reply(408, "Request Timeout", "no complete request")
    end)

    local buf = ""
    client:read_start(function(rerr, chunk)
      if rerr or not chunk then
        return close_all()
      end
      buf = buf .. chunk
      local e = buf:find("\r\n\r\n", 1, true)
      if not e then
        if #buf > MAX_HEAD then
          reply(431, "Request Header Fields Too Large", "request too large")
        end
        return
      end
      client:read_stop()
      timer:stop()
      local first = buf:sub(1, e - 1):match("^[^\r\n]*")
      local rest = buf:sub(e + 4)
      local target = first:match("^CONNECT%s+(%S+)%s+HTTP/1%.[01]$")
      if not target then
        decide({ allowed = false, host = "?", port = 0, reason = "not CONNECT" })
        return reply(405, "Method Not Allowed", "only HTTPS through CONNECT is supported; plain HTTP is not proxied")
      end
      local h, p = target:match("^(.+):(%d+)$")
      local port = tonumber(p)
      local host = h and M.hostname(h)
      if not host or not port or port < 1 or port > 65535 then
        decide({ allowed = false, host = (h or target):sub(1, 80), port = port or 0, reason = "not a DNS host name" })
        return reply(
          403,
          "Forbidden",
          "blocked: " .. target:sub(1, 80) .. " is not an allowed DNS host name (raw IPs are refused)"
        )
      end
      if not M.match(entries, host, port) then
        decide({ allowed = false, host = host, port = port, reason = "not on the allowlist" })
        return reply(403, "Forbidden", ("blocked: %s:%d is not on the network allowlist"):format(host, port))
      end

      resolve(host, function(addrs, rerr2)
        if closed then
          return
        end
        local usable = {}
        for _, a in ipairs(addrs or {}) do
          if opts.allow_private or M.allow_private or M.is_public_ip(a) then
            usable[#usable + 1] = a
          end
        end
        if #usable == 0 then
          local why = (addrs and #addrs > 0) and "resolves only to non-public addresses"
            or ("cannot resolve: " .. tostring(rerr2))
          decide({ allowed = false, host = host, port = port, reason = why })
          return reply(502, "Bad Gateway", ("blocked: %s %s"):format(host, why))
        end
        local i = 0
        local function try()
          i = i + 1
          if closed then
            return
          end
          if i > #usable then
            decide({ allowed = false, host = host, port = port, reason = "connect failed" })
            return reply(502, "Bad Gateway", "cannot connect to " .. host)
          end
          local tcp = uv.new_tcp()
          local cancelled = false
          local ct = uv.new_timer()
          ct:start(15000, 0, function()
            cancelled = true
            safe_close(tcp)
            safe_close(ct)
            try()
          end)
          tcp:connect(usable[i], port, function(cerr)
            if cancelled then
              return
            end
            ct:stop()
            safe_close(ct)
            if cerr then
              safe_close(tcp)
              return try()
            end
            if closed then
              return safe_close(tcp)
            end
            upstream = tcp
            decide({ allowed = true, host = host, port = port })
            client:write("HTTP/1.1 200 Connection Established\r\n\r\n", function(werr)
              if werr then
                return close_all()
              end
              local function touch()
                last = uv.now()
              end
              local ended = 0
              local function one_done()
                ended = ended + 1
                if ended == 2 then
                  close_all()
                end
              end
              timer:start(60000, 60000, function()
                if uv.now() - last > IDLE_MS then
                  close_all()
                end
              end)
              local function start_pumps()
                pump(client, upstream, touch, one_done, close_all)
                pump(upstream, client, touch, one_done, close_all)
              end
              if #rest > 0 then
                upstream:write(rest, function(w2)
                  if w2 then
                    return close_all()
                  end
                  start_pumps()
                end)
              else
                start_pumps()
              end
            end)
          end)
        end
        try()
      end)
    end)
  end

  local lok, lerr = server:listen(128, function(e)
    if e then
      return
    end
    local c = uv.new_pipe(false)
    if server:accept(c) then
      on_connection(c)
    else
      safe_close(c)
    end
  end)
  if not lok then
    safe_close(server)
    return nil, "cannot listen on " .. opts.sock .. ": " .. tostring(lerr)
  end

  function proxy.close()
    if proxy.closed then
      return
    end
    proxy.closed = true
    safe_close(server)
    for _, f in pairs(vim.tbl_values(active)) do
      f()
    end
    uv.fs_unlink(opts.sock)
  end
  return proxy
end

return M
