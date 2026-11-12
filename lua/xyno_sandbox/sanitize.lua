-- A copy of a git config without the places credentials hide in. The sandbox mounts the copy
-- read-only over <gitdir>/config (see plan.lua), so `git remote -v` and `git log` still work, but a
-- token in a remote URL, a credential helper that names a store file, or an extra HTTP header is not
-- visible to the agent. Pure: text in, text out.
local M = {}

-- Keys (lower case, any section) whose whole value is dropped.
M.DROP_KEYS = {
  extraheader = true, -- http.extraHeader = Authorization: ...
  password = true, token = true, askpass = true, sshcommand = false,
}

--- Remove the user info of a URL: `https://user:TOKEN@host/x` -> `https://host/x`; for other schemes
--- only the password part (`ssh://git:pw@host` -> `ssh://git@host`).
local function strip_userinfo(s)
  return (s:gsub("(%a[%w+.-]*://)([^/%s@\"]+)@", function(scheme, info)
    local sch = scheme:lower()
    if sch:match("^https?://$") or sch:match("^ftps?://$") or sch:match("^git://$") then
      return scheme
    end
    local user = info:match("^([^:]*):")
    return scheme .. (user or info) .. "@"
  end))
end
M.strip_userinfo = strip_userinfo

--- @param text string the config file
--- @return string sanitized, string[] changes  what was removed (never the secret itself)
function M.git_config(text)
  local out, changes = {}, {}
  local section = ""
  local drop_cont = false
  for line in (text .. (text:sub(-1) == "\n" and "" or "\n")):gmatch("([^\n]*)\n") do
    if drop_cont then
      drop_cont = line:sub(-1) == "\\"
    else
      local header = line:match("^%s*%[([^%]]*)%]")
      if header then
        section = header:lower()
      end
      local new = strip_userinfo(line)
      if new ~= line then
        changes[#changes + 1] = "URL credentials removed"
      end
      line = new
      local key = line:match("^%s*([%w_-]+)%s*=") or line:match("^%s*([%w_-]+)%s*$")
      if key and not header then
        local k = key:lower()
        if (section:match("^credential") and k == "helper") or M.DROP_KEYS[k] then
          changes[#changes + 1] = section .. "." .. k .. " hidden"
          drop_cont = line:sub(-1) == "\\"
          line = nil
        end
      end
      if line ~= nil then
        out[#out + 1] = line
      end
    end
  end
  return table.concat(out, "\n") .. "\n", changes
end

-- ------------------------------------------------------------------ ~/.claude.json

-- Top-level keys of ~/.claude.json that never reach the sandbox: keys of the account, the other
-- projects' repository paths, an anonymous id, and the old global prompt history.
M.CLAUDE_JSON_DROP = {
  "githubRepoPaths", "primaryApiKey", "customApiKeyResponses", "userID", "anonymousId", "history", "apiKey",
  -- the agent does not need these to work and each is either an identifier of the account, a command that
  -- runs with the account's cloud credentials, or a cache keyed to the account
  "env", "hooks", "awsAuthRefresh", "awsCredentialExport", "apiKeyHelper", "cachedGrowthBookFeatures",
  "cachedStatsigGates", "cachedDynamicConfigs",
}
-- Keys (at any depth) whose value is removed when the key NAME says it is a credential.
M.CLAUDE_JSON_SECRET_KEYS = { "token", "secret", "password", "passwd", "apikey", "api_key", "authorization", "credential", "bearer", "cookie" }
-- MCP server fields that carry credentials or run programs with them.
M.MCP_DROP = { "env", "headers", "headersHelper", "oauth", "apiKeyHelper" }

local function secret_key(k)
  local low = tostring(k):lower()
  for _, s in ipairs(M.CLAUDE_JSON_SECRET_KEYS) do
    if low:find(s, 1, true) then
      return true
    end
  end
  return false
end

local function scrub_value(v, depth)
  if depth > 24 then
    return vim.NIL
  end
  if type(v) == "string" then
    local scan = require("xyno_sandbox.scan")
    if #scan.text(v) > 0 or strip_userinfo(v) ~= v then
      return ""
    end
    return v
  elseif type(v) == "table" then
    local out = {}
    local is_list = vim.islist(v)
    for k, x in pairs(v) do
      if not is_list and secret_key(k) then
        out[k] = nil
      else
        out[k] = scrub_value(x, depth + 1)
      end
    end
    if next(out) == nil then
      return is_list and {} or vim.empty_dict()
    end
    return out
  end
  return v
end

local function scrub_mcp(servers)
  if type(servers) ~= "table" then
    return servers
  end
  for _, srv in pairs(servers) do
    if type(srv) == "table" then
      for _, k in ipairs(M.MCP_DROP) do
        srv[k] = nil
      end
    end
  end
  return servers
end

--- The decoded ~/.claude.json for the sandbox: only the entries of `project_keys` stay of `projects`,
--- the account's keys, email and name, MCP server credentials (env, headers) and every string that
--- is a known token format or has credentials in a URL are removed.
--- @param data table decoded JSON (modified)
--- @param project_keys string[] the project directory spellings
--- @return table
function M.claude_json(data, project_keys)
  if type(data) ~= "table" or vim.islist(data) and #data > 0 then
    return vim.empty_dict() -- not a JSON object (null, a number, a list...): nothing of it is kept
  end
  if type(data.projects) == "table" then
    local keep = {}
    for _, key in ipairs(project_keys) do
      if key and data.projects[key] ~= nil then
        keep[key] = data.projects[key]
      end
    end
    data.projects = next(keep) and keep or vim.empty_dict()
    for _, entry in pairs(data.projects) do
      if type(entry) == "table" then
        entry.mcpServers = scrub_mcp(entry.mcpServers)
      end
    end
  end
  for _, k in ipairs(M.CLAUDE_JSON_DROP) do
    data[k] = nil
  end
  data.mcpServers = scrub_mcp(data.mcpServers)
  if type(data.oauthAccount) == "table" then
    for k in pairs(data.oauthAccount) do
      local low = tostring(k):lower()
      if low:find("email", 1, true) or low:find("name", 1, true) or low:find("uuid", 1, true) then
        data.oauthAccount[k] = nil
      end
    end
  end
  local projects = data.projects
  data.projects = nil
  local out = scrub_value(data, 0)
  out.projects = projects and scrub_value(projects, 1) or nil
  return out
end

return M
