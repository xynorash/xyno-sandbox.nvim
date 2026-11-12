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

return M
