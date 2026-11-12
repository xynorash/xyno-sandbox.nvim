-- The README and the help file say what the code does: every policy key is documented in both, the
-- file names the README promises to hide are hidden, and the limits are stated.
local H = require("xynotest.helpers")
local plan = require("xyno_sandbox.plan")
local sb = require("xyno_sandbox")

describe("docs match the code", function()
  local KEYS = { "readonly", "writable", "hidden", "guard_dirs", "guard_files", "scrub", "scan_depth", "home_allow", "keep_run",
    "project_secrets", "secret_files", "secret_allow", "symlinks", "content_scan", "claude_share", "tree_secrets" }

  it("every policy key is accepted by setup() and appears in the README and the help file", function()
    local readme = io.open(H.repo .. "/README.md"):read("*a")
    local help = io.open(H.repo .. "/doc/xyno-sandbox.txt"):read("*a")
    for _, k in ipairs(KEYS) do
      H.match(readme, k, true, "README: " .. k)
      H.match(help, k, true, "help: " .. k)
    end
    local errs = sb.validate_opts({ policy = { bogus_key = true } })
    H.match(errs[1], "unknown policy key", true)
    H.eq({}, sb.validate_opts({ policy = { content_scan = false, tree_secrets = false } }))
    H.match(sb.validate_opts({ policy = { tree_secrets = "no" } })[1], "tree_secrets must be a boolean", true)
    H.eq({}, sb.validate_opts({ policy = { claude_share = { "settings.json" } } }))
  end)

  it("the file names the README promises to hide are hidden by the default list", function()
    local readme = io.open(H.repo .. "/README.md"):read("*a")
    for _, n in ipairs({ ".dev.vars", "serviceAccountKey.json", "google-services.json", "wp-config.php", "token.txt", "api_keys.json",
      "application-prod.properties", "master.key", ".pgpass", "GoogleService-Info.plist" }) do
      H.match(readme, n == "application-prod.properties" and "application-prod.*" or n, true, n .. " not documented")
      H.ok(plan.is_secret_name(n, plan.PROJECT_SECRET_GLOBS, plan.PROJECT_SECRET_EXCEPT), n)
    end
  end)

  it("state what the content scan cannot catch, the bounds, and the read-only login", function()
    local text = H.docs_text()
    for _, s in ipairs({ "What it cannot catch", "4000 files", "256 KB", "400 ms", "plain password", "approve-to-unhide",
      "not saved", "hard link", "Other users' homes", "--die-with-parent", "throw-away" }) do
      H.match(text, s, true, s)
    end
  end)

  it("the documented scan bounds are the real ones", function()
    local scan = require("xyno_sandbox.scan")
    H.eq(4000, scan.MAX_FILES)
    H.eq(256 * 1024, scan.MAX_FILE_BYTES)
    H.eq(400, scan.MAX_MS)
    H.eq(24 * 1024 * 1024, scan.MAX_TOTAL_BYTES)
  end)

  it("the documented search budgets (sockets, shown trees) are the real ones", function()
    local text = H.docs_text()
    H.eq(30000, plan.SOCK_MAX_DIRS)
    H.eq(24, plan.SOCK_DEPTH)
    H.eq(600, plan.TREE_DIRS_EACH)
    H.eq(2400, plan.TREE_MAX_DIRS)
    H.eq(4, plan.TREE_DEPTH)
    for _, s in ipairs({ "30000 directories", "24 levels", "600 directories per tree and 2400 in all", "four levels" }) do
      H.match(text, s, true, s)
    end
  end)
end)
