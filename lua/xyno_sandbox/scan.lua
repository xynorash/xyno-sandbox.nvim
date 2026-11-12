-- Project scan for secrets that no file name gives away, and for hard links to hidden files.
--
-- Bounded on every axis: the number of files, the size of a file, the total bytes read, the
-- depth and the wall-clock time. Project files only (no $HOME, nothing outside the project), no
-- symlinks followed, no binary files. It matches KNOWN TOKEN FORMATS only (cloud and forge tokens
-- with a recognisable prefix, private key headers): there is no entropy guessing, so a project
-- full of hashes and ids does not flood the preview.
--
-- What it cannot catch (also in the README): a secret in a format that is not listed (a plain
-- password, a generic API key, a JWT, a database URL), a secret in a file over the size limit, in
-- a binary or compressed file, in a directory it skips (node_modules, target, .git, virtualenvs),
-- beyond the file, byte, depth or time budget (the result then says "truncated"), encoded
-- (base64, split over lines), and anything created after the sandbox started.
local M = {}

M.MAX_FILES = 4000
M.MAX_FILE_BYTES = 256 * 1024
M.MAX_TOTAL_BYTES = 24 * 1024 * 1024
M.MAX_DEPTH = 8
M.MAX_DIRS = 6000 -- directories entered (a tree of 100k empty directories must not cost 100k scandir calls)
M.MAX_MS = 400
M.SKIP_DIRS = {
  target = true, node_modules = true, [".git"] = true, [".cache"] = true, [".venv"] = true, venv = true,
  __pycache__ = true, [".mypy_cache"] = true, [".tox"] = true, [".next"] = true, dist = true, build = true,
  [".gradle"] = true, vendor = true, [".terraform"] = true,
}
-- Files that are never text worth reading.
M.SKIP_EXT = {
  png = true, jpg = true, jpeg = true, gif = true, webp = true, ico = true, bmp = true, pdf = true, zip = true, gz = true,
  xz = true, bz2 = true, zst = true, tar = true, tgz = true, jar = true, war = true, class = true, so = true, o = true,
  a = true, dll = true, exe = true, wasm = true, mp3 = true, mp4 = true, mov = true, ogg = true, woff = true, woff2 = true,
  ttf = true, otf = true, eot = true, lock = true, map = true, rlib = true, rmeta = true, pyc = true, sqlite = true, db = true,
}

local function boundary(s, i, j, prefixed)
  -- the match s[i..j] is not part of a longer token
  local before = i > 1 and s:sub(i - 1, i - 1) or ""
  local after = s:sub(j + 1, j + 1)
  -- A token with a distinctive prefix (ghp_, glpat-, sk-ant-...) is a token wherever it starts: glued to the end
  -- of an identifier (tokenghp_..., 1ghp_...) it is still one. "nonupper": an AWS key id (AKIA...) is
  -- also found after a lower-case letter, digit or "_", not inside an upper-case word (...ASIAPACIFIC...).
  if prefixed == true or (prefixed == "nonupper" and not before:match("%u")) then
    return not after:match("[%w_]")
  end
  if before:match("[%w_]") then
    -- "\nAKIA..." inside a JSON / YAML string: the "n" belongs to an escape, not to a word
    local esc = i > 2 and s:sub(i - 2, i - 2) == "\\" and before:match("[nrt]")
    if not esc then
      return false
    end
  end
  return not after:match("[%w_]")
end

-- Base64 of the private key header at the three alignments it can have in an encoded document
-- (a Kubernetes secret, a CI variable, a JSON field holding a base64 file): only the characters
-- that do not depend on what comes before or after.
local function b64_forms(text)
  local out = {}
  for k = 0, 2 do
    local enc = vim.base64.encode(("x"):rep(k) .. text)
    -- whole 3-byte groups made of header bytes only: the neighbours cannot change them
    local first, last = math.ceil(k / 3), math.floor((k + #text) / 3)
    out[#out + 1] = (enc:sub(4 * first + 1, 4 * last):gsub("%p", "%%%0"))
  end
  return out
end

-- { kind, lua pattern, optional exact length of the whole match }
M.PATTERNS = {
  { "AWS access key id", "A[SK]IA[%u%d]+", 20, nil, nil, "nonupper" },
  { "AWS secret access key", "[Aa][Ww][Ss]_?[Ss][Ee][Cc][Rr][Ee][Tt]_?[Aa][Cc][Cc][Ee][Ss][Ss]_?[Kk][Ee][Yy][\"']?%s*[=:]%s*[\"']?[%w/+]+", nil,
    function(m)
      local v = m:match("[=:]%s*[\"']?([%w/+]+)$")
      return v and #v == 40
    end },
  { "GitHub token", "gh[pousr]_[%w]+", nil, function(m) return #m >= 40 end, nil, true }, -- (longer ones exist: the length is a minimum)
  { "GitHub fine-grained token", "github_pat_[%w_]+", nil, function(m) return #m >= 60 end, nil, true },
  { "GitLab token", "glpat%-[%w_%-]+", nil, function(m) return #m >= 26 end, nil, true },
  { "Slack token", "xox[abprs]%-[%w%-]+", nil, function(m) return #m >= 24 end, nil, true },
  { "Slack app token", "xapp%-[%w%-]+", nil, function(m) return #m >= 30 end, nil, true },
  { "Slack webhook", "hooks%.slack%.com/services/T%w+/B%w+/%w+" },
  { "Stripe live key", "[sr]k_live_[%w]+", nil, function(m) return #m >= 32 end, nil, true },
  { "Stripe test key", "[sr]k_test_[%w]+", nil, function(m) return #m >= 32 end, nil, true },
  { "Anthropic key", "sk%-ant%-[%w_%-]+", nil, function(m) return #m >= 40 end, nil, true },
  { "OpenAI key", "sk%-proj%-[%w_%-]+", nil, function(m) return #m >= 40 end, nil, true },
  { "OpenAI key", "sk%-[%w]+T3BlbkFJ[%w]+", nil, nil, nil, true },
  { "OpenAI key", "sk%-[%w]+", 51, nil, nil, true }, -- the legacy format: sk- and 48 characters
  { "Google API key", "AIza[%w_%-]+", 39, nil, nil, true },
  { "npm token", "npm_[%w]+", nil, function(m) return #m >= 40 end, nil, true },
  { "Hugging Face token", "hf_[%w]+", nil, function(m) return #m >= 37 end, nil, true },
  { "DigitalOcean token", "do[por]_v1_%x+", 71, nil, nil, true },
  { "Shopify token", "shp%l%l_%x+", 38, nil, nil, true },
  { "SendGrid key", "SG%.[%w_%-]+%.[%w_%-]+", nil, function(m) return #m == 69 end, nil, true },
  -- loose: the dashes are distinctive, and a key is often glued to its neighbours (key=-----BEGIN ...-----MIIE...)
  -- (any case, any white space: matched on the lower-cased line)
  { "private key", "%-%-%-%-%-%s*begin%s+[%a%s]*private%s+key[%a%s]*%-%-%-%-%-", nil, nil, "lower" },
  { "credentials in a URL", "%a[%w%+%.%-]*://[^/%s:@\"']*:[^/%s@\"']+@[%w%.%-]+", nil, function(m)
    local pw = m:match("^%a[%w%+%.%-]*://[^:/]*:([^@]+)@")
    if not pw or #pw < 8 or pw:find("[%$%{%}<>%%]") then
      return false
    end
    local low = pw:lower()
    for _, ph in ipairs({ "password", "passw0rd", "changeme", "secret", "example", "xxxxxxxx", "********", "redacted" }) do
      if low:find(ph, 1, true) then
        return false
      end
    end
    return true
  end },
}
for _, hdr in ipairs({ "-----BEGIN PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY", "-----BEGIN EC PRIVATE KEY", "-----BEGIN DSA PRIVATE KEY",
  "-----BEGIN OPENSSH PRIVATE KEY", "-----BEGIN ENCRYPTED PRIVATE KEY", "-----BEGIN PGP PRIVATE KEY" }) do
  for _, form in ipairs(b64_forms(hdr)) do
    M.PATTERNS[#M.PATTERNS + 1] = { "private key (base64)", form, nil, nil, true }
  end
end
-- A MATCH that spells out that it is not real ("AKIAIOSFODNN7EXAMPLE", "ghp_xxxxxxxx...") is
-- documentation of a format. Judged on the matched token only: a real token on a line that says
-- "example" (a comment, a repo or a host called example) is still a secret.
local PLACEHOLDER = { "example", "dummy", "placeholder", "your_", "your-", "xxxxxxxx", "fake", "redacted" }
local function placeholder(m)
  local low = m:lower()
  for _, ph in ipairs(PLACEHOLDER) do
    if low:find(ph, 1, true) then
      return true
    end
  end
  return false
end

--- Candidate starts of the URL pattern: a scheme is looked for from each "://", never from each letter (the
--- pattern retried from every start of a long run of letters is quadratic: 64 KB took 16 s).
local function url_find(line, pat, init)
  local at = init
  while true do
    local k = line:find("://", at, true)
    if not k then
      return nil
    end
    -- the scheme: the run of scheme characters before "://" (":" and "/" end it, so the runs of all the "://" of a
    -- line add up to the length of the line), from its first letter
    local b = k
    while b > init and line:sub(b - 1, b - 1):match("[%w%+%.%-]") do
      b = b - 1
    end
    while b < k and not line:sub(b, b):match("%a") do
      b = b + 1
    end
    if b < k then
      local i, j = line:find("^" .. pat, b)
      if i then
        return i, j
      end
    end
    at = k + 3
  end
end

--- Kinds of secret found in `text` (a list without duplicates). Never returns the secret itself.
--- Linear in the size of the text: nothing is retried from every position. `deadline` (vim.uv.hrtime()
--- nanoseconds) stops the search between lines; the second result says it did.
--- @param text string
--- @param deadline? integer
--- @return string[] kinds, boolean timed_out
function M.text(text, deadline)
  local kinds, seen = {}, {}
  local timed_out = false
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    if deadline and vim.uv.hrtime() > deadline then
      timed_out = true
      break
    end
    local lower
    for _, pat in ipairs(M.PATTERNS) do
      local kind = pat[1]
      if not seen[kind] then
        local subject = line
        if pat[5] == "lower" then
          lower = lower or line:lower()
          subject = lower
        end
        local init = 1
        while true do
          local i, j
          if kind == "credentials in a URL" then
            i, j = url_find(subject, pat[2], init)
          else
            i, j = subject:find(pat[2], init)
          end
          if not i then
            break
          end
          local m = subject:sub(i, j)
          local ok = (pat[5] or boundary(subject, i, j, pat[6])) and (not pat[3] or #m == pat[3]) and (not pat[4] or pat[4](m))
          -- the URL pattern judges its own password part (the host may well be example.com)
          if ok and kind ~= "credentials in a URL" and placeholder(m) then
            ok = false
          end
          if ok then
            seen[kind] = true
            kinds[#kinds + 1] = kind
            break
          end
          init = j + 1
        end
      end
    end
  end
  return kinds, timed_out
end

-- (path, mtime sec, nsec, size) -> kinds: a rescan of an unchanged project costs the stat calls only
local cache = {}

--- Walk `project`. Returns
---   { hits = { { path, kind } }, multi = { { path, dev, ino, nlink } }, files, truncated, why? }
--- @param project string
--- @param opts? { content?: boolean, skip_names?: table<string,boolean> , allow?: table<string,boolean> }
function M.project(project, opts)
  opts = opts or {}
  local uv = vim.uv
  local want_content = opts.content ~= false
  local t0 = uv.hrtime()
  local res = { hits = {}, multi = {}, files = 0, truncated = false, unread = { large = 0, binary = 0, extension = 0 } }
  local total = 0
  local function out_of_budget()
    if res.files >= M.MAX_FILES then
      return "more than " .. M.MAX_FILES .. " files"
    elseif total >= M.MAX_TOTAL_BYTES then
      return "more than " .. math.floor(M.MAX_TOTAL_BYTES / 1048576) .. " MB read"
    elseif (uv.hrtime() - t0) / 1e6 > M.MAX_MS then
      return "more than " .. M.MAX_MS .. " ms"
    end
  end
  local queue, qi = { { project, 0 } }, 1
  while qi <= #queue do
    local dir, depth = queue[qi][1], queue[qi][2]
    qi = qi + 1
    if qi > M.MAX_DIRS + 1 then
      res.truncated, res.why = true, "more than " .. M.MAX_DIRS .. " directories"
      return res
    end
    if (uv.hrtime() - t0) / 1e6 > M.MAX_MS then
      res.truncated, res.why = true, "more than " .. M.MAX_MS .. " ms"
      return res
    end
    local h = uv.fs_scandir(dir)
    if h then
      while true do
        local name, ty = uv.fs_scandir_next(h)
        if not name then
          break
        end
        local path = dir .. "/" .. name
        if ty == nil or ty == "unknown" then
          -- some file systems do not report the type with the name
          local l = uv.fs_lstat(path)
          ty = l and l.type or nil
        end
        if ty == "directory" then
          if depth < M.MAX_DEPTH and not M.SKIP_DIRS[name] then
            queue[#queue + 1] = { path, depth + 1 }
          end
        elseif ty == "file" then
          local why = out_of_budget()
          if why then
            res.truncated, res.why = true, why
            return res
          end
          res.files = res.files + 1
          local st = uv.fs_stat(path)
          if st then
            if st.nlink and st.nlink > 1 then
              res.multi[#res.multi + 1] = { path = path, dev = st.dev, ino = st.ino, nlink = st.nlink }
            end
            local ext = name:match("%.([%w]+)$")
            if want_content and st.size > M.MAX_FILE_BYTES then
              res.unread.large = res.unread.large + 1
            elseif want_content and ext and M.SKIP_EXT[ext:lower()] then
              res.unread.extension = res.unread.extension + 1
            end
            if want_content and st.size > 0 and st.size <= M.MAX_FILE_BYTES and not (ext and M.SKIP_EXT[ext:lower()]) then
              local key = path
              local c = cache[key]
              local sig = st.mtime.sec .. ":" .. st.mtime.nsec .. ":" .. st.size
              local kinds
              local binary = false
              if c and c.sig == sig then
                kinds, binary = c.kinds, c.binary
                if binary then
                  res.unread.binary = res.unread.binary + 1
                end
              else
                kinds = {}
                local f = io.open(path, "rb")
                if f then
                  local data = f:read("a") or ""
                  f:close()
                  total = total + #data
                  if not data:sub(1, 1024):find("%z") then
                    local timed
                    kinds, timed = M.text(data, t0 + M.MAX_MS * 1e6)
                    if timed then
                      res.truncated, res.why = true, "more than " .. M.MAX_MS .. " ms"
                      return res
                    end
                  else
                    binary = true
                    res.unread.binary = res.unread.binary + 1
                  end
                end
                cache[key] = { sig = sig, kinds = kinds, binary = binary }
              end
              if #kinds > 0 then
                res.hits[#res.hits + 1] = { path = path, kind = kinds[1] }
              end
            end
          end
        end
      end
    end
  end
  return res
end

return M
