-- Ninth round: the survivors of the independent mutation run that were real gaps (see CHANGELOG): userinfo of git:// and
-- ftp:// URLs, the validators of policy.guard_dirs / guard_files / secret_allow, the base64 private key headers, the
-- minimum length of every token format.
local H = require("xynotest.helpers")
local sb = require("xyno_sandbox")
local scan = require("xyno_sandbox.scan")
local sanitize = require("xyno_sandbox.sanitize")

describe("strip_userinfo", function()
  it("takes the whole user info off http(s), ftp(s) and git:// URLs (a token is often the user name)", function()
    for _, u in ipairs({ "https", "http", "ftp", "ftps", "git", "HTTPS", "Git" }) do
      local out = sanitize.strip_userinfo(u .. "://ghp_SECRETTOKEN@github.com/x")
      H.eq(u .. "://github.com/x", out, u)
      out = sanitize.strip_userinfo(u .. "://user:PASSWORD1@github.com/x")
      H.eq(u .. "://github.com/x", out, u .. " with a password")
    end
  end)
  it("keeps the user of other schemes and drops only their password", function()
    H.eq("ssh://git@host/x", sanitize.strip_userinfo("ssh://git:pw@host/x"))
    H.eq("ssh://git@host/x", sanitize.strip_userinfo("ssh://git@host/x"))
    H.eq("git+ssh://git@host/x", sanitize.strip_userinfo("git+ssh://git:pw@host/x"))
  end)
end)

describe("option validation: the lists the earlier specs did not exercise", function()
  local function errs(policy)
    return table.concat(sb.validate_opts({ policy = policy }), "\n")
  end
  it("policy.guard_dirs entries must be non-empty path strings", function()
    H.match(errs({ guard_dirs = { 5 } }), "guard_dirs", true)
    H.match(errs({ guard_dirs = { "" } }), "guard_dirs", true)
    H.match(errs({ guard_dirs = "x" }), "guard_dirs", true)
    H.eq({}, sb.validate_opts({ policy = { guard_dirs = { ".foo", "~/.bar" } } }))
  end)
  it("policy.guard_files entries must be non-empty path strings", function()
    H.match(errs({ guard_files = { "" } }), "guard_files", true)
    H.match(errs({ guard_files = { 7 } }), "guard_files", true)
    H.match(errs({ guard_files = "x" }), "guard_files", true)
    H.eq({}, sb.validate_opts({ policy = { guard_files = { ".foorc" } } }))
  end)
  it("policy.secret_allow entries must be strings", function()
    H.match(errs({ secret_allow = { 7 } }), "secret_allow", true)
    H.match(errs({ secret_allow = "x" }), "secret_allow", true)
    H.eq({}, sb.validate_opts({ policy = { secret_allow = { ".env.test" } } }))
  end)
  it("all three at once report one error each", function()
    H.eq(3, #sb.validate_opts({ policy = { guard_dirs = { 5 }, guard_files = { "" }, secret_allow = { 7 } } }))
  end)
end)

describe("the content scan: private keys inside base64", function()
  for _, kind in ipairs({
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PGP PRIVATE KEY",
  }) do
    it(kind .. " header is found at each of the three alignments", function()
      for k = 0, 2 do
        local doc = ("x"):rep(k) .. "-----BEGIN " .. kind .. "-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " .. kind .. "-----\n"
        local line = "data: " .. vim.base64.encode(doc)
        H.ok(#scan.text(line) > 0, kind .. " alignment " .. k)
      end
    end)
  end
  it("ordinary base64 is not a hit", function()
    H.eq(0, #scan.text("data: " .. vim.base64.encode(("hello world "):rep(20))))
  end)
end)

-- Each format with a minimum length: found at the minimum, not one character below it, found above it.
describe("the content scan: the length of each token format", function()
  local FILL = "aB3dE5gH7jK9mN2pQ4rS6tU8vW1yZ0"
  local function body(n)
    return (FILL:rep(math.ceil(n / #FILL) + 1)):sub(1, n)
  end
  local FORMATS = {
    { "GitHub token", "ghp_", 40 },
    { "GitHub token", "gho_", 40 },
    { "GitHub fine-grained token", "github_pat_", 60 },
    { "GitLab token", "glpat-", 26 },
    { "Slack token", "xoxb-", 24 },
    { "Slack app token", "xapp-", 30 },
    { "Stripe live key", "sk_live_", 32 },
    { "Stripe test key", "rk_test_", 32 },
    { "Anthropic key", "sk-ant-", 40 },
    { "OpenAI key", "sk-proj-", 40 },
    { "npm token", "npm_", 40 },
    { "Hugging Face token", "hf_", 37 },
  }
  for _, f in ipairs(FORMATS) do
    it(f[1] .. " (" .. f[2] .. "...): minimum " .. f[3] .. " characters", function()
      local function hits(total)
        return scan.text("token = " .. f[2] .. body(total - #f[2]))
      end
      H.ok(#hits(f[3]) > 0, "found at " .. f[3])
      H.ok(#hits(f[3] + 1) > 0, "found at " .. f[3] + 1)
      H.ok(#hits(f[3] + 15) > 0, "found well above the minimum")
      H.eq(0, #hits(f[3] - 1), "not found at " .. f[3] - 1)
      H.eq(0, #hits(f[3] - 8), "not found at " .. f[3] - 8)
    end)
  end
  it("an AWS secret access key assignment needs exactly 40 characters", function()
    local function hits(n)
      return scan.text("aws_secret_access_key = " .. body(n))
    end
    H.ok(#hits(40) > 0)
    H.eq(0, #hits(39))
    H.eq(0, #hits(41))
  end)
end)
