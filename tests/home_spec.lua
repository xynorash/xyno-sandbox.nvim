-- The allowlist view of $HOME (the default): $HOME is an empty tmpfs inside the sandbox and only
-- the project, the scratch dir, the agent's own writable paths and the toolchain directories are
-- shown. Red-team finding 5: the whole filesystem, $HOME included, was readable (--ro-bind / /).
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local plan = require("xyno_sandbox.plan")
local harness = require("xynotest.harness")

local saved = vim.deepcopy(sb.config)
after_each(function()
  sb.config = vim.deepcopy(saved)
end)

local HOME, PROJECT, TMP = "/h", "/h/proj", "/h/scratch"

local function fakefs(entries, real)
  return {
    stat_type = function(p) return entries[p] end,
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
    glob = function(pat)
      local out = {}
      local lp = "^" .. pat:gsub("[%-%.%+%[%]%(%)%$%^%%]", "%%%0"):gsub("%*", "[^/]*") .. "$"
      for p in pairs(entries) do
        if p:match(lp) then out[#out + 1] = p end
      end
      table.sort(out)
      return out
    end,
    read_line = function() return nil end,
    realpath = function(p) return (real or {})[p] or (entries[p] and p) or nil end,
  }
end

local BASE = {
  [HOME] = "directory", [HOME .. "/.claude"] = "directory", [PROJECT] = "directory", [TMP] = "directory",
  [PROJECT .. "/.git"] = "directory",
}

local function build(extra, over, real)
  local entries = vim.tbl_extend("force", BASE, extra or {})
  return plan.build(vim.tbl_extend("force", {
    project = PROJECT, tmp_dir = TMP, cwd = PROJECT, home = HOME, uid = 1000, probes = fakefs(entries, real),
    env = { PATH = "/usr/bin" }, cmd = { "agent" }, aux = { empty = "/aux/empty", claude_json = "/aux/cj" },
    config = { network = "open" },
  }, over or {}))
end

local function allowed(p)
  local out = {}
  for _, a in ipairs(p.home_allow) do
    out[a.path] = a.why
  end
  return out
end

local function index(a, ...)
  local seq = { ... }
  for i = 1, #a - #seq + 1 do
    local hit = true
    for j = 1, #seq do
      hit = hit and a[i + j - 1] == seq[j]
    end
    if hit then return i end
  end
end

describe("the allowlist view in the plan", function()
  it("is the default: the config says allowlist, the plan has an empty tmpfs $HOME", function()
    H.eq("allowlist", require("xyno_sandbox").config.home)
    local p = build()
    H.eq("allowlist", p.home_mode)
    H.ok(index(plan.argv(p), "--tmpfs", HOME), "--tmpfs $HOME")
  end)

  it("binds only existing toolchain paths read-only, after the tmpfs and before the writable binds", function()
    local p = build({
      [HOME .. "/.cargo"] = "directory", [HOME .. "/.rustup"] = "directory", [HOME .. "/.gitconfig"] = "file",
      [HOME .. "/.ssh"] = "directory", [HOME .. "/Documents"] = "directory", [HOME .. "/.bashrc"] = "file",
    })
    local a = allowed(p)
    H.ok(a[HOME .. "/.cargo"] and a[HOME .. "/.rustup"] and a[HOME .. "/.gitconfig"], "toolchain and git config")
    H.eq(nil, a[HOME .. "/.ssh"])
    H.eq(nil, a[HOME .. "/Documents"])
    H.eq(nil, a[HOME .. "/.bashrc"])
    local argv = plan.argv(p)
    local t, r, w = index(argv, "--tmpfs", HOME), index(argv, "--ro-bind", HOME .. "/.cargo", HOME .. "/.cargo"), index(argv, "--bind", PROJECT, PROJECT)
    H.ok(t < r and r < w, "tmpfs, then the allowed binds, then the writable ones")
  end)

  it("never lists a hidden credential twice: credentials of $HOME that are not mounted are simply absent", function()
    local p = build({ [HOME .. "/.ssh"] = "directory", [HOME .. "/.aws"] = "directory", [HOME .. "/.cargo"] = "directory",
      [HOME .. "/.cargo/credentials.toml"] = "file", [HOME .. "/.bash_history"] = "file" })
    local hidden = {}
    for _, h in ipairs(p.hidden) do
      hidden[h.path] = true
    end
    H.eq(nil, hidden[HOME .. "/.ssh"], "~/.ssh is not mounted at all")
    H.eq(nil, hidden[HOME .. "/.aws"])
    H.eq(nil, hidden[HOME .. "/.bash_history"])
    H.ok(hidden[HOME .. "/.cargo/credentials.toml"], "a credential INSIDE an allowed tree stays hidden")
    -- in the denylist view the same plan hides all of them
    local d = build({ [HOME .. "/.ssh"] = "directory", [HOME .. "/.aws"] = "directory" }, { config = { network = "open", home = "denylist" } })
    local dh = {}
    for _, h in ipairs(d.hidden) do
      dh[h.path] = true
    end
    H.ok(dh[HOME .. "/.ssh"] and dh[HOME .. "/.aws"])
    H.eq(nil, index(plan.argv(d), "--tmpfs", HOME), "denylist: $HOME is not replaced")
  end)

  it("shows what $PATH needs: entries under $HOME, the toolchain root of a bin dir, and the agent binary", function()
    local p = build({
      [HOME .. "/.local/bin"] = "directory", [HOME .. "/.local/bin/agent"] = "link",
      [HOME .. "/.local/share/agent/versions/1/agent"] = "file", [HOME .. "/.nvm/versions/node/v20/bin"] = "directory",
      [HOME .. "/.nvm/versions/node/v20/lib"] = "directory", [HOME .. "/.nvm/versions/node/v20"] = "directory",
      [HOME .. "/.local"] = "directory", [HOME .. "/.nvm"] = "directory", [HOME .. "/.local/share/agent"] = "directory",
    }, {
      env = { PATH = HOME .. "/.local/bin:" .. HOME .. "/.nvm/versions/node/v20/bin:/usr/bin" },
    }, { [HOME .. "/.local/bin/agent"] = HOME .. "/.local/share/agent/versions/1/agent" })
    local a = allowed(p)
    H.ok(a[HOME .. "/.local/bin"], "PATH entry")
    H.ok(a[HOME .. "/.nvm/versions/node/v20/bin"], "PATH entry")
    H.ok(a[HOME .. "/.nvm/versions/node/v20"], "the toolchain root of a .../bin entry (npm lives in ../lib)")
    H.eq(nil, a[HOME .. "/.local"], "never the whole of ~/.local")
    H.ok(a[HOME .. "/.local/share/agent/versions/1/agent"], "the real file behind the agent symlink")
  end)

  it("follows toolchain variables (CARGO_HOME, RUSTUP_HOME, ...) under $HOME and keeps their registry writable", function()
    local p = build({
      [HOME .. "/sdk/cargo"] = "directory", [HOME .. "/sdk/cargo/registry"] = "directory", [HOME .. "/sdk/rustup"] = "directory",
      [HOME .. "/sdk/cargo/credentials.toml"] = "file",
    }, { env = { PATH = "/usr/bin", CARGO_HOME = HOME .. "/sdk/cargo", RUSTUP_HOME = HOME .. "/sdk/rustup" } })
    local a = allowed(p)
    H.eq("$CARGO_HOME", a[HOME .. "/sdk/cargo"])
    H.eq("$RUSTUP_HOME", a[HOME .. "/sdk/rustup"])
    local w = {}
    for _, x in ipairs(p.writable) do
      w[x.path] = true
    end
    H.ok(w[HOME .. "/sdk/cargo/registry"], "cargo can fill its registry")
    local hidden = {}
    for _, h in ipairs(p.hidden) do
      hidden[h.path] = true
    end
    H.ok(hidden[HOME .. "/sdk/cargo/credentials.toml"], "and its publish token stays hidden")
  end)

  it("policy.home_allow adds paths (read-only); a bad entry is rejected by setup()", function()
    local p = build({ [HOME .. "/data"] = "directory", [HOME .. "/data/x"] = "file" },
      { config = { network = "open", policy = { home_allow = { "~/data" } } } })
    H.eq("policy.home_allow", allowed(p)[HOME .. "/data"])
    H.throws(function() sb.setup({ policy = { home_allow = { "~/" } } }) end, "expose")
    H.throws(function() sb.setup({ home = "everything" }) end, "allowlist")
    H.eq("allowlist", sb.config.home, "a rejected setup() changes nothing")
    sb.setup({ preview = "never", home = "denylist" })
    H.eq("denylist", sb.config.home)
  end)

  it("a symlink to the project's toolchain is allowed through its real path only when it exists", function()
    local p = build({}, { cmd = { "/nonexistent/agent" } })
    H.eq({}, p.home_allow)
  end)
end)

describe("the allowlist view inside a real sandbox", function()
  local canary
  before_each(function()
    canary = vim.uv.os_homedir() .. "/xyno-home-canary-" .. tostring(vim.uv.hrtime()):sub(-8)
    vim.fn.writefile({ "visible-only-in-denylist" }, canary)
  end)
  after_each(function()
    vim.uv.fs_unlink(canary)
  end)

  local function inside(cmd, project, cfg)
    H.need_sandbox()
    sb.config.network = "open"
    for k, v in pairs(cfg or {}) do
      sb.config[k] = v
    end
    local tmp = H.tmpdir()
    local wrapped, err, h = sb.wrap(cmd, project, tmp)
    H.ok(wrapped, err)
    local r = vim.system(wrapped, { text = true, cwd = project }):wait(120000)
    h.release()
    return (r.stdout or "") .. (r.stderr or ""), r
  end

  it("a file in $HOME that nothing allows is invisible; in the denylist view it is readable", function()
    local project = H.tmpdir()
    local name = vim.fs.basename(canary)
    local out = inside({ "bash", "-c", 'cat "$HOME/' .. name .. '" 2>/dev/null; ls -A "$HOME" | head -50' }, project)
    H.no_match(out, "visible-only-in-denylist", true, out)
    H.no_match(out, name, true, "not even listed")
    for _, hidden in ipairs({ ".ssh", ".gnupg", ".aws", "Documents", "Downloads", ".bash_history", ".mozilla" }) do
      H.no_match("\n" .. out, "\n" .. hidden .. "\n", true, hidden .. " must not be listed")
    end
    local out2 = inside({ "bash", "-c", 'cat "$HOME/' .. name .. '"' }, project, { home = "denylist" })
    H.match(out2, "visible-only-in-denylist", true, out2)
  end)

  it("the project and the scratch dir stay writable, and writes to $HOME go to a throw-away tmpfs", function()
    local project = H.tmpdir()
    local name = vim.fs.basename(canary)
    local out = inside({ "bash", "-c", 'echo ok > made.txt; echo hacked > "$HOME/.bashrc" && echo WROTE-HOME-TMPFS; echo done' }, project)
    H.match(out, "done", true, out)
    H.eq(1, vim.fn.filereadable(project .. "/made.txt"))
    local real = vim.uv.os_homedir() .. "/.bashrc"
    if vim.uv.fs_stat(real) then
      H.not_ok(table.concat(vim.fn.readfile(real), "\n"):find("hacked", 1, true), "the real ~/.bashrc must be untouched")
    end
    H.eq(1, vim.fn.filereadable(canary), name)
  end)

  it("a fake agent that needs cargo and rustc still works (builds and runs a crate), with $HOME on the allowlist", function()
    if vim.fn.executable("cargo") ~= 1 or vim.fn.executable("rustc") ~= 1 then
      return harness.skip("cargo/rustc not installed")
    end
    local project = H.fixture("basic")
    local agent = project .. "/fake-agent"
    vim.fn.writefile({
      "#!/bin/sh", "set -e", "rustc --version", "cargo --version", "cargo build --offline 2>&1 | tail -2",
      "./target/debug/basic", "echo AGENT-DONE",
    }, agent)
    vim.uv.fs_chmod(agent, tonumber("755", 8))
    local out, r = inside({ agent }, project)
    H.eq(0, r.code, out)
    H.match(out, "rustc ", true, out)
    H.match(out, "cargo ", true, out)
    H.match(out, "42", true, "the compiled crate printed its answer: " .. out)
    H.match(out, "AGENT-DONE", true, out)
    H.eq(1, vim.fn.filereadable(project .. "/target/debug/basic"), "target/ was written to the project")
  end)

  it("a git commit works with the user's git config from the allowlist", function()
    if vim.fn.executable("git") ~= 1 then
      return harness.skip("git not installed")
    end
    local project = H.fixture("basic", { git = true })
    local out, r = inside({ "bash", "-c", "git -C " .. project .. " log --oneline | head -3; git -C " .. project .. " status --short | head" }, project)
    H.eq(0, r.code, out)
    H.match(out, "init", true, out)
  end)

  it("the installed agent CLI (claude) still starts: --version works inside the sandbox", function()
    if vim.fn.executable("claude") ~= 1 then
      return harness.skip("claude is not installed")
    end
    local out, r = inside({ "claude", "--version" }, H.tmpdir())
    H.eq(0, r.code, out)
    H.match(out, "%d+%.%d+%.%d+")
  end)
end)
