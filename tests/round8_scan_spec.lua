-- Eighth round, the content scan: the URL finder (scan.lua url_find) at its edges.
local H = require("xynotest.helpers")
local scan = require("xyno_sandbox.scan")

local PW = "Zq7xK9mPqL2"
local function found(line)
  return vim.tbl_contains(scan.text(line), "credentials in a URL")
end

describe("credentials in a URL: where the scheme starts", function()
  it("at the first column, after other text, and as the second '://' of a line", function()
    H.ok(found("https://u:" .. PW .. "@h"))
    H.ok(found("x https://u:" .. PW .. "@h"))
    H.ok(found("see://nothing and https://u:" .. PW .. "@h"))
    H.ok(found("a://b c://d e://f https://u:" .. PW .. "@h"))
  end)

  it("the scheme starts at its first letter: leading digits, dots, plus and minus are not part of it", function()
    H.ok(found("x9https://u:" .. PW .. "@h"))
    H.ok(found("-https://u:" .. PW .. "@h"))
    H.ok(found("+.-https://u:" .. PW .. "@h"))
    H.ok(found("9.https://u:" .. PW .. "@h"))
    H.ok(found("x9+.-ssh://u:" .. PW .. "@h"))
    H.ok(found("git+ssh://u:" .. PW .. "@h"))
  end)

  it("a '://' with no letter before it is not a scheme", function()
    H.not_ok(found("123://u:" .. PW .. "@h"))
    H.not_ok(found("://u:" .. PW .. "@h"))
    H.not_ok(found("+-.://u:" .. PW .. "@h"))
  end)

  it("a scheme is cut at ':' and '/', so the one before it is another URL", function()
    H.ok(found("a:b//https://u:" .. PW .. "@h"))
    H.ok(found("path/https://u:" .. PW .. "@h"))
  end)

  it("a placeholder password first and a real one later on the same line: the real one is found", function()
    H.ok(found("https://a:changeme123@h https://b:" .. PW .. "@h"))
    H.not_ok(found("https://a:changeme123@h https://b:changeme123@h"))
  end)

  it("a very long run of scheme characters is linear (64 KB under a second)", function()
    local line = ("a"):rep(65536) .. "://x:y@z"
    local t0 = vim.uv.hrtime()
    local r = found(line)
    H.not_ok(r)
    H.ok((vim.uv.hrtime() - t0) / 1e9 < 1)
    local many = ("ab://"):rep(10000)
    t0 = vim.uv.hrtime()
    found(many)
    H.ok((vim.uv.hrtime() - t0) / 1e9 < 1)
  end)

  it("the secret kind is reported once for a line with several", function()
    local kinds = scan.text("https://a:" .. PW .. "@h https://b:" .. PW .. "x@h")
    local n = 0
    for _, k in ipairs(kinds) do
      if k == "credentials in a URL" then
        n = n + 1
      end
    end
    H.eq(1, n)
  end)
end)
