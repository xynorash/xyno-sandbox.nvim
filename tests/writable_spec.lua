-- Writable approvals that would defeat a mask or expose a shared directory are refused.
-- Pure: plan.validate_exception / plan.writable_forbidden against a table-backed filesystem.
local H = require("xynotest.helpers")
local plan = require("xyno_sandbox.plan")

local HOME = "/home/spec-user"
local function probes()
  return { exists = function() return true end, realpath = function(x) return x end }
end
local function check(path, extra)
  return plan.validate_exception({ kind = "writable", value = path }, vim.tbl_extend("force", { home = HOME, probes = probes() }, extra or {}))
end
local function refused(path, pat, extra)
  local ok, why = check(path, extra)
  H.not_ok(ok, path .. " must be refused")
  H.match(why, pat, true, path)
end

describe("shared system directories", function()
  it("are refused as a whole", function()
    for _, d in ipairs({ "/tmp", "/var", "/var/tmp", "/var/lib", "/mnt", "/media", "/srv", "/opt", "/dev/shm", "/nix" }) do
      refused(d, "refused")
      H.match(select(2, check(d)), " is a ", true)
    end
  end)

  it("/run and everything below it, /dev, /proc, /etc and / are refused", function()
    for _, d in ipairs({ "/run", "/run/user", "/run/user/1000", "/run/media", "/run/docker.sock", "/dev", "/proc", "/etc/ssh" }) do
      refused(d, "system path")
    end
    refused("/", "refusing to expose / as a whole")
  end)

  it("the whole filesystem is refused by the check itself, not only by its caller", function()
    H.match(plan.writable_forbidden("/", HOME), "whole filesystem", true)
  end)

  it("/home and the parents of $HOME are refused (they would show every user's files)", function()
    refused("/home", "contains $HOME")
    refused(HOME, "refusing to expose")
  end)

  it("a project directory BELOW a shared directory is fine", function()
    for _, d in ipairs({ "/tmp/project", "/mnt/data/project", "/var/lib/myapp/work", "/srv/site", "/opt/work", HOME .. "/projects/p" }) do
      local ok, why = check(d)
      H.ok(ok, d .. ": " .. tostring(why))
    end
  end)

  it("a symlink that leads to one is refused, naming the target", function()
    local ok, why = plan.validate_exception({ kind = "writable", value = "/home/spec-user/innocent" },
      { home = HOME, probes = { exists = function() return true end, realpath = function() return "/var/tmp" end } })
    H.not_ok(ok)
    H.match(why, "resolves to /var/tmp", true)
  end)
end)

describe("a parent of a directory the sandbox masks", function()
  it("is refused: the writable bind comes after the tmpfs and would bring the host's content back", function()
    refused("/var", "")
    -- /var/tmp is masked: a parent that is not on the exact list is caught by the masked-path rule
    local why = plan.writable_forbidden("/var/tmp", HOME)
    H.ok(why)
    local ok = plan.writable_forbidden("/var/tmp/sub", HOME)
    H.eq(nil, ok, "below the mask is a different matter (it is empty inside the sandbox anyway)")
  end)

  it("includes the masked paths of the plan that was built (baseline.masked)", function()
    refused("/srv/a", "which the sandbox hides", { baseline = { masked = { { path = "/srv/a/secret-socket-dir" } }, hidden = {}, readonly = {}, masks = {}, guard_files = {}, ephemeral = {} } })
    local ok = check("/srv/b", { baseline = { masked = { { path = "/srv/a/secret-socket-dir" } }, hidden = {}, readonly = {}, masks = {}, guard_files = {}, ephemeral = {} } })
    H.ok(ok, "an unrelated sibling is fine")
  end)

  it("the sandbox's own policy.writable is ignored with a note when it is one", function()
    local p = plan.build({
      project = "/mnt/proj", tmp_dir = "/mnt/scratch", home = HOME, env = {}, cmd = { "agent" },
      config = { network = "open", policy = { writable = { "/var", "/tmp", "/mnt/ok" } } }, aux = { empty = "/e" },
      probes = { stat_type = function() return "directory" end, lstat_type = function() return "directory" end,
        exists = function() return true end, list = function() return {} end, glob = function() return {} end,
        read_line = function() return nil end, realpath = function(x) return x end },
    })
    local text = table.concat(p.notes, "\n")
    H.match(text, "policy.writable /var is ignored", true)
    H.match(text, "policy.writable /tmp is ignored", true)
    local paths = vim.tbl_map(function(w) return w.path end, p.writable)
    H.not_ok(vim.tbl_contains(paths, "/var") or vim.tbl_contains(paths, "/tmp"))
    H.has(paths, "/mnt/ok")
  end)
end)

describe("a writable approval below a place that runs outside the sandbox later", function()
  -- kills the mutant that dropped the "inside(p, f)" half of the check: the CHILD of a forbidden path
  it("is refused for the children, and for the parents, of every forbidden $HOME path", function()
    local children = {
      "/.ssh/known_hosts", "/.ssh/config", "/.config/nvim/init.lua", "/.config/autostart/x.desktop", "/.local/bin/tool",
      "/.cargo/bin/rg", "/.cargo/config.toml/x", "/.config/systemd/user/a.service", "/.config/git/config", "/.vscode/tasks.json",
      "/.config/environment.d/x.conf", "/.gnupg/gpg.conf",
    }
    for _, rel in ipairs(children) do
      refused(HOME .. rel, "outside the sandbox later")
    end
    local parents = { "/.config", "/.local", "/.cargo", "/.config/Code" }
    for _, rel in ipairs(parents) do
      refused(HOME .. rel, "outside the sandbox later")
    end
  end)

  it("the file itself is refused too", function()
    for _, rel in ipairs({ "/.bashrc", "/.zshrc", "/.profile", "/.gitconfig" }) do
      refused(HOME .. rel, "outside the sandbox later")
    end
  end)

  it("but an unrelated directory in $HOME is not", function()
    for _, rel in ipairs({ "/projects/x", "/.cache/thing", "/data", "/.local/share/app" }) do
      local ok, why = check(HOME .. rel)
      H.ok(ok, rel .. ": " .. tostring(why))
    end
  end)
end)
