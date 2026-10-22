-- Utilities for spec files. `local H = require("xynotest.helpers")`.
local harness = require("xynotest.harness")

local H = {}
H.repo = vim.fs.dirname(vim.fs.dirname(debug.getinfo(1, "S").source:sub(2)))

local function fail(msg, level)
  error(msg, (level or 1) + 1)
end

function H.eq(expected, actual, msg)
  if not vim.deep_equal(expected, actual) then
    fail(
      ("%sexpected %s\n  actual   %s"):format(msg and (msg .. ": ") or "", vim.inspect(expected), vim.inspect(actual)),
      2
    )
  end
end

function H.ok(v, msg)
  if not v then
    fail(msg or ("expected a truthy value, got " .. vim.inspect(v)), 2)
  end
  return v
end

function H.not_ok(v, msg)
  if v then
    fail(msg or ("expected a falsy value, got " .. vim.inspect(v)), 2)
  end
end

--- Lua pattern match (plain = true for a literal substring).
function H.match(str, pat, plain, msg)
  if type(str) ~= "string" or not str:find(pat, 1, plain) then
    fail((msg and (msg .. ": ") or "") .. ("%s does not match %q"):format(vim.inspect(str), pat), 2)
  end
end

function H.no_match(str, pat, plain, msg)
  if type(str) == "string" and str:find(pat, 1, plain) then
    fail((msg and (msg .. ": ") or "") .. ("%s unexpectedly matches %q"):format(vim.inspect(str), pat), 2)
  end
end

--- A list contains `item` (deep compare), or a string contains the substring.
function H.has(container, item, msg)
  local found = false
  if type(container) == "string" then
    found = container:find(item, 1, true) ~= nil
  else
    for _, v in ipairs(container) do
      if vim.deep_equal(v, item) then
        found = true
        break
      end
    end
  end
  if not found then
    fail(
      (msg and (msg .. ": ") or "") .. ("%s does not contain %s"):format(vim.inspect(container), vim.inspect(item)),
      2
    )
  end
end

--- fn must raise an error (matching `pat`, a Lua pattern, when given).
function H.throws(fn, pat)
  local ok, e = pcall(fn)
  if ok then
    fail("expected an error, none raised", 2)
  end
  if pat and not tostring(e):find(pat) then
    fail(("error %q does not match %q"):format(tostring(e), pat), 2)
  end
end

--- Calls to vim.notify during fn: { { msg, level }, ... }.
function H.capture_notify(fn)
  local got, orig = {}, vim.notify
  vim.notify = function(msg, level)
    got[#got + 1] = { msg, level }
  end
  local ok, err = pcall(fn)
  vim.notify = orig
  assert(ok, err)
  return got
end

H.os = vim.fn.has("win32") == 1 and "windows" or vim.fn.has("mac") == 1 and "macos" or "linux"

H._dirs = {}

--- A fresh empty directory, removed by cleanup().
function H.tmpdir()
  local base = vim.env.XYNO_TEST_TMP
  if not base or base == "" then
    base = vim.fs.dirname(vim.fn.tempname())
  end
  local dir = assert(vim.uv.fs_mkdtemp(base .. "/spec-XXXXXX"))
  H._dirs[#H._dirs + 1] = dir
  return dir
end

function H.sandbox_available()
  if vim.fn.executable("bwrap") ~= 1 then
    return false, "bwrap not found"
  end
  local dir = H.tmpdir()
  local prev = vim.fn.chdir(dir)
  local cmd, err = require("xyno_sandbox").wrap({ "true" }, dir, dir)
  vim.fn.chdir(prev)
  if not cmd then
    return false, err
  end
  local r = vim.system(cmd, { cwd = dir }):wait(10000)
  if r.code ~= 0 then
    return false, "bwrap cannot create a sandbox here: " .. vim.trim(r.stderr or "")
  end
  return true
end

--- Skip the test unless bwrap can create a sandbox here.
function H.need_sandbox()
  local ok, why = H.sandbox_available()
  if not ok then
    harness.skip(why)
  end
end

--- Skip the whole file (call at load time).
function H.skip_file(reason)
  harness.skip(reason)
end

local function run(cmd, opts)
  return vim.system(cmd, vim.tbl_extend("force", { text = true }, opts or {})):wait(60000)
end

--- Run git in `dir` with a fixed identity; returns trimmed stdout, raises on failure.
function H.git(dir, ...)
  local cmd = { "git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ... }
  local r = run(cmd, { cwd = dir })
  if r.code ~= 0 then
    error(("git %s failed (%d): %s"):format(table.concat({ ... }, " "), r.code, r.stderr), 2)
  end
  return vim.trim(r.stdout)
end

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text)
  f:close()
end

--- A tiny cargo crate in a fresh temp dir ("basic": a library and a binary).
--- opts.git = true makes it a git repository with one commit.
function H.fixture(name, opts)
  assert(name == "basic", "unknown fixture " .. name)
  local dest = H.tmpdir() .. "/" .. name
  write(dest .. "/Cargo.toml", '[package]\nname = "basic"\nversion = "0.1.0"\nedition = "2021"\n')
  write(dest .. "/src/lib.rs", "pub fn answer() -> i32 {\n    42\n}\n")
  write(dest .. "/src/main.rs", 'fn main() {\n    println!("{}", basic::answer());\n}\n')
  if (opts or {}).git then
    H.git(dest, "init", "-q", "-b", "main")
    H.git(dest, "add", "-A")
    H.git(dest, "commit", "-q", "-m", "init")
  end
  return dest
end

--- README.md followed by the help file (the claims the specs verify live in one of them).
function H.docs_text()
  local parts = {}
  for _, f in ipairs({ "README.md", "doc/xyno-sandbox.txt" }) do
    local fh = io.open(H.repo .. "/" .. f)
    if fh then
      parts[#parts + 1] = fh:read("*a")
      fh:close()
    end
  end
  return table.concat(parts, "\n")
end

--- Delete temp dirs.
function H.cleanup()
  pcall(vim.cmd, "silent! %bwipeout!")
  pcall(vim.cmd, "cd " .. vim.fn.fnameescape(vim.env.HOME or "/"))
  for _, d in ipairs(H._dirs) do
    -- wrap() leaves an empty ~/.claude/projects/<dir>/memory behind (the mask's
    -- mount point): remove what a spec's temp dir caused (rmdir only: a
    -- directory with anything in it stays)
    local name = (vim.uv.fs_realpath(d) or d):gsub("[^%w]", "-")
    local proj = vim.uv.os_homedir() .. "/.claude/projects/" .. name
    for _, p in ipairs(vim.list_extend({ proj }, vim.fn.glob(proj .. "-*", true, true))) do
      vim.uv.fs_rmdir(p .. "/memory")
      vim.uv.fs_rmdir(p)
    end
    vim.fn.delete(d, "rf")
  end
  H._dirs = {}
end

return H
