-- Runs INSIDE the sandbox (`nvim -l relay.lua SOCK PORT READY`): listens on 127.0.0.1:PORT of the
-- sandbox's private loopback and pipes every connection into the unix socket SOCK of the
-- filtering proxy outside. It decides nothing. It is copied next to the socket at launch, so it
-- must not require any plugin module. READY is created once the listener is up.
local uv = vim.uv
local sock, port, ready = arg[1], tonumber(arg[2]), arg[3]
if not sock or not port or not ready then
  io.stderr:write("usage: relay.lua SOCK PORT READY\n")
  os.exit(2)
end

local function safe_close(h)
  if h and not h:is_closing() then
    h:close()
  end
end

local function pump(a, b, done, abort)
  local function on_read(err, chunk)
    if err then
      return abort()
    end
    if not chunk then
      a:read_stop()
      return b:shutdown(done)
    end
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

local server = uv.new_tcp()
local ok, err = server:bind("127.0.0.1", port)
if not ok then
  io.stderr:write("relay: cannot bind 127.0.0.1:" .. port .. ": " .. tostring(err) .. "\n")
  os.exit(1)
end
local lok, lerr = server:listen(128, function(e)
  if e then
    return
  end
  local client = uv.new_tcp()
  server:accept(client)
  local up = uv.new_pipe(false)
  up:connect(sock, function(cerr)
    if cerr then
      safe_close(up)
      return safe_close(client)
    end
    local n = 0
    local function close_all()
      safe_close(up)
      safe_close(client)
    end
    local function done()
      n = n + 1
      if n == 2 then
        close_all()
      end
    end
    pump(client, up, done, close_all)
    pump(up, client, done, close_all)
  end)
end)
if not lok then
  io.stderr:write("relay: cannot listen: " .. tostring(lerr) .. "\n")
  os.exit(1)
end
local f = io.open(ready, "w")
if not f then
  io.stderr:write("relay: cannot write " .. ready .. "\n")
  os.exit(1)
end
f:write("ok\n")
f:close()
uv.run()
