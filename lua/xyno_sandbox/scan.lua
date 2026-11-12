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

local function boundary(s, i, j)
  -- the match s[i..j] is not part of a longer token
  local before = i > 1 and s:sub(i - 1, i - 1) or ""
  local after = s:sub(j + 1, j + 1)
  return not before:match("[%w_]") and not after:match("[%w_]")
end

-- { kind, lua pattern, optional exact length of the whole match }
M.PATTERNS = {
  { "AWS access key id", "A[SK]IA[%u%d]+", 20 },
  { "AWS secret access key", "[Aa][Ww][Ss]_?[Ss][Ee][Cc][Rr][Ee][Tt]_?[Aa][Cc][Cc][Ee][Ss][Ss]_?[Kk][Ee][Yy][\"']?%s*[=:]%s*[\"']?[%w/+]+", nil,
    function(m)
      local v = m:match("[=:]%s*[\"']?([%w/+]+)$")
      return v and #v == 40
    end },
  { "GitHub token", "gh[pousr]_[%w]+", 40 },
  { "GitHub fine-grained token", "github_pat_[%w_]+", nil, function(m) return #m >= 60 end },
  { "GitLab token", "glpat%-[%w_%-]+", 26 },
  { "Slack token", "xox[abprs]%-[%w%-]+", nil, function(m) return #m >= 24 end },
  { "Slack webhook", "hooks%.slack%.com/services/T%w+/B%w+/%w+" },
  { "Stripe live key", "[sr]k_live_[%w]+", nil, function(m) return #m >= 32 end },
  { "Anthropic key", "sk%-ant%-[%w_%-]+", nil, function(m) return #m >= 40 end },
  { "OpenAI key", "sk%-proj%-[%w_%-]+", nil, function(m) return #m >= 40 end },
  { "OpenAI key", "sk%-[%w]+T3BlbkFJ[%w]+" },
  { "Google API key", "AIza[%w_%-]+", 39 },
  { "npm token", "npm_[%w]+", 40 },
  { "SendGrid key", "SG%.[%w_%-]+%.[%w_%-]+", nil, function(m) return #m == 69 end },
  { "private key", "%-%-%-%-%-BEGIN [%u ]*PRIVATE KEY[%u ]*%-%-%-%-%-" },
  { "credentials in a URL", "https?://[^/%s:@\"']+:[^/%s@\"']+@[%w%.%-]+", nil, function(m)
    local pw = m:match("^https?://[^:]+:([^@]+)@")
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
-- Lines that are documentation of a format, not a secret.
local PLACEHOLDER = { "example", "dummy", "placeholder", "your_", "your-", "<your", "xxxxxxxx", "fake", "redacted" }

--- Kinds of secret found in `text` (a list without duplicates). Never returns the secret itself.
--- @param text string
--- @return string[]
function M.text(text)
  local kinds, seen = {}, {}
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    if #line <= 4000 then -- a minified line is not a config line
      local low = line:lower()
      local doc = false
      for _, ph in ipairs(PLACEHOLDER) do
        doc = doc or low:find(ph, 1, true) ~= nil
      end
      if not doc then
        for _, pat in ipairs(M.PATTERNS) do
          local kind = pat[1]
          if not seen[kind] then
            local init = 1
            while true do
              local i, j = line:find(pat[2], init)
              if not i then
                break
              end
              local m = line:sub(i, j)
              local ok = boundary(line, i, j) and (not pat[3] or #m == pat[3]) and (not pat[4] or pat[4](m))
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
    end
  end
  return kinds
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
  local res = { hits = {}, multi = {}, files = 0, truncated = false }
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
    local h = uv.fs_scandir(dir)
    if h then
      while true do
        local name, ty = uv.fs_scandir_next(h)
        if not name then
          break
        end
        local path = dir .. "/" .. name
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
            if want_content and st.size > 0 and st.size <= M.MAX_FILE_BYTES and not (ext and M.SKIP_EXT[ext:lower()]) then
              local key = path
              local c = cache[key]
              local sig = st.mtime.sec .. ":" .. st.mtime.nsec .. ":" .. st.size
              local kinds
              if c and c.sig == sig then
                kinds = c.kinds
              else
                kinds = {}
                local f = io.open(path, "rb")
                if f then
                  local data = f:read("a") or ""
                  f:close()
                  total = total + #data
                  if not data:sub(1, 1024):find("%z") then
                    kinds = M.text(data)
                  end
                end
                cache[key] = { sig = sig, kinds = kinds }
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
