-- Other users' homes, and the account's real home when it is not $HOME, are not visible inside
-- the sandbox (an empty tmpfs over /home); what the sandbox needs from them is shown again
-- read-only, narrowly. Plan specs use a table-backed filesystem; one spec runs a real sandbox.
local H = require("xynotest.helpers")
local plan = require("xyno_sandbox.plan")
local ui = require("xyno_sandbox.ui")

local HOME = "/home/bob"

local function fakefs(entries, links)
  local fs = entries
  return {
    stat_type = function(p)
      return fs[p]
    end,
    lstat_type = function(p)
      return (links or {})[p] and "link" or fs[p]
    end,
    exists = function(p)
      return fs[p] ~= nil
    end,
    list = function(dir)
      local out, prefix = {}, dir .. "/"
      for p, t in pairs(fs) do
        if p:sub(1, #prefix) == prefix and not p:sub(#prefix + 1):find("/", 1, true) then
          out[#out + 1] = { p:sub(#prefix + 1), (links or {})[p] and "link" or t }
        end
      end
      table.sort(out, function(a, b)
        return a[1] < b[1]
      end)
      return out
    end,
    glob = function()
      return {}
    end,
    read_line = function()
      return nil
    end,
    realpath = function(p)
      return (links or {})[p] or (fs[p] and p) or nil
    end,
  }
end

local function build(over, fs, links)
  local entries = vim.tbl_extend("force", {
    ["/home"] = "directory",
    [HOME] = "directory",
    [HOME .. "/.claude"] = "directory",
    [HOME .. "/proj"] = "directory",
    ["/home/alice"] = "directory",
    ["/srv/acct"] = "directory",
  }, fs or {})
  for k, v in pairs(entries) do
    if v == false then
      entries[k] = nil
    end
  end
  return plan.build(vim.tbl_extend("force", {
    project = HOME .. "/proj",
    tmp_dir = HOME .. "/scratch",
    home = HOME,
    uid = 1000,
    env = { PATH = "/usr/bin" },
    cmd = { "agent" },
    aux = { empty = "/aux/e" },
    config = { network = "open" },
    probes = fakefs(entries, links),
  }, over or {}))
end

local function ops_text(p)
  local out = {}
  for _, o in ipairs(plan.ops(p)) do
    out[#out + 1] = o.section .. ": " .. table.concat(o.args, " ")
  end
  return table.concat(out, "\n")
end

local function index_of(p, section, needle)
  for i, o in ipairs(plan.ops(p)) do
    if o.section == section and table.concat(o.args, " "):find(needle, 1, true) then
      return i
    end
  end
end

describe("/home is an empty tmpfs", function()
  it("is masked before $HOME is rebuilt and before the project is bound back", function()
    local p = build()
    local h = index_of(p, "homes", "--tmpfs /home")
    H.ok(h, ops_text(p))
    H.ok(h < index_of(p, "home", "--tmpfs " .. HOME), "the home view is built on top")
    H.ok(h < index_of(p, "writable", "--bind " .. HOME .. "/proj"), "the project is writable again on top")
    H.eq(
      { "/home" },
      vim.tbl_map(function(m)
        return m.path
      end, p.homes.masked)
    )
  end)

  it("also in the denylist view: $HOME is bound back read-only after the tmpfs", function()
    local p = build({ config = { network = "open", home = "denylist" } })
    local text = ops_text(p)
    H.match(text, "homes: --tmpfs /home", true)
    local a, b = index_of(p, "homes", "--tmpfs /home"), index_of(p, "homes", "--ro-bind " .. HOME .. " " .. HOME)
    H.ok(b and a < b, text)
  end)

  it("nothing is added when there is no /home on the machine", function()
    local p = build(nil, { ["/home"] = false, ["/home/alice"] = false })
    H.eq({}, p.homes.masked)
    H.no_match(ops_text(p), "homes:", true)
  end)

  it("a /home that is a symlink masks what it points to", function()
    local p = build(nil, { ["/var/home"] = "directory" }, { ["/home"] = "/var/home" })
    H.eq(
      { "/var/home" },
      vim.tbl_map(function(m)
        return m.path
      end, p.homes.masked)
    )
  end)

  it("the preview lists it", function()
    local text = table.concat(ui.lines(build()), "\n")
    H.match(text, "Other users' homes hidden", true)
    H.match(text, "--tmpfs /home", true)
  end)
end)

describe("the account's real home when it differs from $HOME", function()
  it("is masked too, when it is not below /home", function()
    local p = build({ passwd_home = "/srv/acct" })
    H.eq(
      { "/home", "/srv/acct" },
      vim.tbl_map(function(m)
        return m.path
      end, p.homes.masked)
    )
    H.match(ops_text(p), "homes: --tmpfs /srv/acct", true)
  end)

  it("equal to $HOME there is nothing extra; below /home it is covered by the /home mask", function()
    H.eq(1, #build({ passwd_home = HOME }).homes.masked)
    H.eq(1, #build({ passwd_home = "/home/carol" }).homes.masked)
  end)
end)

describe("what is shown again from a hidden home", function()
  local fs = {
    ["/home/alice/.cargo"] = "directory",
    ["/home/alice/.cargo/bin"] = "directory",
    ["/home/alice/.cargo/bin/cargo"] = "file",
    ["/home/alice/.cargo/credentials.toml"] = "file",
    ["/home/alice/.ssh"] = "directory",
    ["/home/alice/.local"] = "directory",
    ["/home/alice/.local/bin"] = "directory",
    ["/home/alice/.local/share/tool/bin/tool"] = "file",
    ["/home/alice/.local/share/tool"] = "directory",
    ["/home/alice/secret-notes"] = "directory",
  }

  it("a $PATH directory and the toolchain around it are read-only, the owner's credentials stay hidden", function()
    local p = build({ env = { PATH = "/home/alice/.cargo/bin:/usr/bin" } }, fs)
    local shown = vim.tbl_map(function(a)
      return a.path
    end, p.homes.allow)
    H.eq({ "/home/alice/.cargo/bin" }, vim.list_slice(shown, 1, 1))
    H.has(shown, "/home/alice/.cargo")
    local hidden = vim.tbl_map(function(h)
      return h.path
    end, p.hidden)
    H.has(hidden, "/home/alice/.cargo/credentials.toml")
    H.not_ok(vim.tbl_contains(shown, "/home/alice/.ssh") or vim.tbl_contains(shown, "/home/alice/secret-notes"))
    H.match(ops_text(p), "homes: --ro-bind /home/alice/.cargo/bin /home/alice/.cargo/bin", true)
  end)

  it("never the owner's whole home, ~/.local or ~/.config", function()
    local p = build(
      { env = { PATH = "/home/alice/.local/bin:/home/alice/bin:/usr/bin" } },
      vim.tbl_extend("force", fs, { ["/home/alice/bin"] = "directory" })
    )
    for _, a in ipairs(p.homes.allow) do
      H.not_ok(a.path == "/home/alice" or a.path == "/home/alice/.local" or a.path == "/home/alice/.config", a.path)
    end
  end)

  it("a link in a $PATH directory shows its target file only", function()
    local p = build(
      { env = { PATH = "/home/alice/.local/bin:/usr/bin" } },
      vim.tbl_extend("force", fs, { ["/home/alice/.local/bin/tool"] = "file" }),
      { ["/home/alice/.local/bin/tool"] = "/home/alice/.local/share/tool/bin/tool" }
    )
    local shown = vim.tbl_map(function(a)
      return a.path
    end, p.homes.allow)
    H.has(shown, "/home/alice/.local/share/tool/bin/tool")
    H.not_ok(vim.tbl_contains(shown, "/home/alice/.local/share/tool"))
  end)

  it("toolchain variables and the agent command are shown, read-only, and nothing else of that home", function()
    local p = build({
      env = { PATH = "/usr/bin", CARGO_HOME = "/home/alice/.cargo" },
      cmd = { "/home/alice/.local/share/tool/bin/tool" },
    }, fs)
    local shown = vim.tbl_map(function(a)
      return a.path
    end, p.homes.allow)
    H.has(shown, "/home/alice/.cargo")
    H.has(shown, "/home/alice/.local/share/tool/bin/tool")
    H.not_ok(vim.tbl_contains(shown, "/home/alice/secret-notes"))
  end)

  it("a project in another home is still writable (bound after the tmpfs)", function()
    local p = build(
      { project = "/home/alice/work", tmp_dir = HOME .. "/scratch" },
      { ["/home/alice/work"] = "directory" }
    )
    local h = index_of(p, "homes", "--tmpfs /home")
    local w = index_of(p, "writable", "--bind /home/alice/work /home/alice/work")
    H.ok(h and w and h < w, ops_text(p))
  end)

  it("a symlink in the project that points into a hidden home is not readable", function()
    local p = build(
      {},
      { [HOME .. "/proj/notes"] = "file", ["/home/alice/secret-notes/a"] = "file" },
      { [HOME .. "/proj/notes"] = "/home/alice/secret-notes/a" }
    )
    local l = p.symlinks[1]
    H.ok(l, "the symlink is listed")
    H.eq(false, l.readable)
  end)
end)

describe("a real sandbox", function()
  it("cannot see the account's real home when $HOME is somewhere else (the suite's fake home)", function()
    H.need_sandbox()
    local sb = require("xyno_sandbox")
    local real = vim.uv.os_get_passwd().homedir
    if real == vim.uv.os_homedir() then
      return require("xynotest.harness").skip("$HOME is the account's home here")
    end
    local canary = real .. "/xyno-homes-canary-" .. tostring(vim.uv.hrtime())
    local f = io.open(canary, "w")
    if not f then
      return require("xynotest.harness").skip("cannot write a canary into " .. real)
    end
    f:write("OTHER-HOME-SECRET\n")
    f:close()
    sb.config.network = "open"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h = sb.wrap(
      { "bash", "-c", 'cat "$1" 2>&1; ls -A "$(dirname "$1")" 2>&1 | head -5; echo end', "x", canary },
      project,
      tmp
    )
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    vim.uv.fs_unlink(canary)
    local out = (r.stdout or "") .. (r.stderr or "")
    H.no_match(out, "OTHER-HOME-SECRET", true, out)
    H.match(out, "end", true, out)
  end)

  it("the sandbox's own $HOME is still usable (writable cache, project writable)", function()
    H.need_sandbox()
    local sb = require("xyno_sandbox")
    sb.config.network = "open"
    local project, tmp = H.tmpdir(), H.tmpdir()
    local cmd, err, h =
      sb.wrap({ "bash", "-c", 'echo hi > made.txt && ls "$HOME/.claude" >/dev/null && echo fine' }, project, tmp)
    H.ok(cmd, err)
    local r = vim.system(cmd, { text = true, cwd = project }):wait(60000)
    h.release()
    H.match(r.stdout or "", "fine", true, (r.stdout or "") .. (r.stderr or ""))
    H.eq(1, vim.fn.filereadable(project .. "/made.txt"))
  end)
end)
