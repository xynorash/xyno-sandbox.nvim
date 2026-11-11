-- The policy preview and the approvals list. lines() is pure (a plan in, text out); the windows
-- around it only show lines() and ask the operator about exceptions.
local M = {}

local CAP = 25

local function short(p, home)
  if home and p:sub(1, #home + 1) == home .. "/" then
    return "~" .. p:sub(#home + 1)
  end
  return p
end

--- The preview text for a plan. Only variable NAMES appear, never values; the command's
--- arguments (which hold the prompt) are not shown.
--- @param plan table
--- @param ctx? { status?: table, full?: boolean, home?: string }
--- @return string[]
function M.lines(plan, ctx)
  ctx = ctx or {}
  local home = ctx.home or plan.home or vim.uv.os_homedir()
  local out = {}
  local function add(s)
    out[#out + 1] = s
  end
  local function section(title, items, fmt)
    add("")
    add(("%s (%d)"):format(title, #items))
    if #items == 0 then
      add("  none")
    end
    local limit = ctx.full and math.huge or CAP
    for i, it in ipairs(items) do
      if i > limit then
        add(("  ... and %d more (:XynoSandboxPolicy! lists all)"):format(#items - CAP))
        break
      end
      add("  " .. fmt(it))
    end
  end

  add("xyno-sandbox: policy preview")
  add("")
  add("project   " .. short(plan.project, home))
  local c = plan.agent and plan.agent.cmd or {}
  add(("command   %s (%d argument%s not shown)"):format(c[1] or "?", math.max(#c - 1, 0), #c == 2 and "" or "s"))

  if plan.mode ~= "bwrap" then
    add("")
    add("UNSANDBOXED (" .. tostring(plan.via) .. "): " .. tostring(plan.reason))
    add("Nothing below is enforced: the whole filesystem, your credentials and the network are reachable.")
    if plan.agent and plan.agent.skip_permissions then
      add("")
      add("Agent permission prompts: OFF (" .. plan.agent.flag .. ") and no sandbox either.")
    end
    return out
  end

  local st = ctx.status
  add("sandbox   bubblewrap" .. (st and st.ready == "pending" and " (readiness check running)" or ""))
  add("network   " .. (plan.network == "open" and "OPEN (not restricted: the agent reaches the internet and local services)"
    or plan.network))
  add("")
  if plan.agent.stripped then
    add("Agent permission prompts: ON (" .. "--dangerously-skip-permissions removed by strip_skip_permissions)")
  elseif plan.agent.skip_permissions then
    add("Agent permission prompts: OFF (" .. plan.agent.flag .. "): the agent acts without asking;")
    add("  this sandbox is the only barrier. Set strip_skip_permissions = true to remove the flag.")
  else
    add("Agent permission prompts: not disabled by the command")
  end

  section("Writable", plan.writable, function(w)
    return ("%s  [%s]"):format(short(w.path, home), w.why)
  end)
  section("Read-only inside the writable paths, git directories locked", plan.git_locked, function(p)
    return short(p, home)
  end)
  local other = {}
  for _, r in ipairs(plan.readonly) do
    if r.why ~= "git" then
      other[#other + 1] = r
    end
  end
  section("Read-only (would run or steer tools outside the sandbox)", other, function(r)
    return ("%s  [%s]"):format(short(r.path, home), r.why)
  end)
  local guards = {}
  for _, m in ipairs(plan.masks) do
    guards[#guards + 1] = { path = m.path, why = m.why }
  end
  for _, g in ipairs(plan.guard_files) do
    guards[#guards + 1] = { path = g.path, why = g.why }
  end
  section("Absent files and directories guarded (cannot be created)", guards, function(g)
    return ("%s  [%s]"):format(short(g.path, home), g.why)
  end)
  section("Hidden credential paths (replaced with empty ones)", plan.hidden, function(h)
    return ("%s  [%s]"):format(short(h.path, home), h.kind)
  end)
  section("Stripped environment variables (names only, values are never shown)", plan.env_strip, function(n)
    return n
  end)

  if #plan.env_kept > 0 or #plan.exceptions > 0 or #plan.rejected > 0 then
    add("")
    add(("Approved exceptions (%d)"):format(#plan.exceptions))
    for _, e in ipairs(plan.exceptions) do
      add(("  %s %s  [%s]"):format(e.kind, e.kind == "env" and e.value or short(e.value, home), e.scope or "project"))
    end
    for _, r in ipairs(plan.rejected) do
      add(("  IGNORED %s %s: %s"):format(r.kind, tostring(r.value), r.reason))
    end
  end
  if #plan.notes > 0 then
    add("")
    for _, n in ipairs(plan.notes) do
      add("Note: " .. n)
    end
  end
  return out
end

-- ----------------------------------------------------------------- windows

local function float(lines, title, footer)
  local buf = vim.api.nvim_create_buf(false, true)
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].filetype = "xyno-sandbox"
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modifiable = false
  local width = math.min(110, math.max(vim.o.columns - 6, 40))
  local height = math.min(#lines + 1, math.max(vim.o.lines - 6, 8))
  local win = vim.api.nvim_open_win(buf, true, {
    relative = "editor", style = "minimal", border = "rounded", width = width, height = height,
    row = math.max(math.floor((vim.o.lines - height) / 2) - 1, 0), col = math.max(math.floor((vim.o.columns - width) / 2), 0),
    title = " " .. title .. " ", footer = " " .. footer .. " ", footer_pos = "center",
  })
  vim.wo[win].wrap = true
  return buf, win
end

local function set_lines(buf, lines)
  vim.bo[buf].modifiable = true
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modifiable = false
end

local function select(items, opts, cb)
  vim.ui.select(items, opts, cb)
end

--- Ask which exception to consider, then approve (once / for the project) or refuse it.
--- @param plan table the plan being shown
--- @param project string
--- @param done fun(exception?: table)  called with the exception to add for this launch (scope "once"), or nil
function M.pick_exception(plan, project, done)
  local ex = require("xyno_sandbox.exceptions")
  local home = plan.home or vim.uv.os_homedir()
  local cands = {}
  for _, h in ipairs(plan.hidden or {}) do
    cands[#cands + 1] = { label = "show hidden path " .. short(h.path, home), kind = "unhide", value = h.path }
  end
  for _, n in ipairs(plan.env_strip or {}) do
    cands[#cands + 1] = { label = "let environment variable " .. n .. " through", kind = "env", value = n }
  end
  cands[#cands + 1] = { label = "make another path writable...", kind = "writable" }
  select(cands, { prompt = "Exception to consider", format_item = function(c) return c.label end }, function(c)
    if not c then
      return done(nil)
    end
    local function decide(value)
      if not value or value == "" then
        return done(nil)
      end
      local what = ("%s %s"):format(c.kind, c.kind == "writable" and value or short(value, home))
      local choices = { "Approve for this launch only", "Approve for this project (remembered, revocable)", "Refuse" }
      select(choices, { prompt = "Exception: " .. what .. " (project " .. short(project, home) .. ")" }, function(_, idx)
        if idx == 1 or idx == 2 then
          local e, why = ex.decide(project, "approved", { kind = c.kind, value = value }, idx == 2 and "project" or "once")
          if not e and why then
            vim.notify("xyno-sandbox: refused: " .. why, vim.log.levels.WARN)
          end
          return done(e and idx == 1 and e or nil)
        end
        ex.decide(project, "refused", { kind = c.kind, value = value })
        return done(nil)
      end)
    end
    if c.kind == "writable" then
      vim.ui.input({ prompt = "Absolute path to make writable: " }, decide)
    else
      decide(c.value)
    end
  end)
end

--- Show the policy of a plan. With `confirm`, the operator launches or cancels.
--- @param opts { build: fun(once: table[]): table?, project: string, confirm?: boolean, full?: boolean,
---   status?: fun(): table, on_done?: fun(go: boolean, plan: table?, once: table[]) }
function M.show(opts)
  local once = {}
  local plan = opts.build(once)
  if not plan then
    if opts.on_done then
      opts.on_done(false, nil, once)
    end
    return
  end
  local footer = opts.confirm and "<CR>/y launch   q/n cancel   e exception" or "q close   e exception"
  local buf, win = float(M.lines(plan, { full = opts.full, status = opts.status and opts.status() }),
    opts.confirm and "Launch inside the sandbox?" or "Sandbox policy", footer)
  local finished = false
  local function finish(go)
    if finished then
      return
    end
    finished = true
    if vim.api.nvim_win_is_valid(win) then
      vim.api.nvim_win_close(win, true)
    end
    if opts.on_done then
      opts.on_done(go, plan, once)
    end
  end
  local function map(keys, fn)
    for _, k in ipairs(keys) do
      vim.keymap.set("n", k, fn, { buffer = buf, nowait = true, silent = true })
    end
  end
  if opts.confirm then
    map({ "<CR>", "y" }, function() finish(true) end)
    map({ "q", "n", "<Esc>" }, function() finish(false) end)
  else
    map({ "q", "<Esc>", "<CR>" }, function() finish(false) end)
  end
  map({ "e" }, function()
    if plan.mode ~= "bwrap" then
      return vim.notify("xyno-sandbox: no sandbox, no exceptions to approve", vim.log.levels.INFO)
    end
    M.pick_exception(plan, opts.project, function(e)
      if e then
        once[#once + 1] = e
      end
      plan = opts.build(once) or plan
      if vim.api.nvim_buf_is_valid(buf) then
        set_lines(buf, M.lines(plan, { full = opts.full, status = opts.status and opts.status() }))
      end
      if vim.api.nvim_win_is_valid(win) then
        vim.api.nvim_set_current_win(win)
      end
    end)
  end)
  vim.api.nvim_create_autocmd("BufWipeout", { buffer = buf, once = true, callback = function() finish(false) end })
  return buf, win
end

-- -------------------------------------------------------------- approvals

--- Lines of the approvals list and the row -> { project, id } index.
function M.approval_lines(all, home)
  local out, index = { "xyno-sandbox: remembered approvals   (x revokes the one under the cursor, q closes)", "" }, {}
  local projects = vim.tbl_keys(all)
  table.sort(projects)
  for _, p in ipairs(projects) do
    out[#out + 1] = short(p, home)
    for _, a in ipairs(all[p]) do
      out[#out + 1] = ("  [%d] %s %s   (%s)"):format(a.id, a.kind, a.kind == "env" and a.value or short(a.value, home), a.ts)
      index[#out] = { project = p, id = a.id }
    end
  end
  if #projects == 0 then
    out[#out + 1] = "  none"
  end
  return out, index
end

function M.approvals()
  local ex = require("xyno_sandbox.exceptions")
  local home = vim.uv.os_homedir()
  local lines, index = M.approval_lines(ex.list(), home)
  local buf, win = float(lines, "Sandbox approvals", "x revoke   q close")
  local function refresh()
    lines, index = M.approval_lines(ex.list(), home)
    set_lines(buf, lines)
  end
  vim.keymap.set("n", "q", function()
    vim.api.nvim_win_close(win, true)
  end, { buffer = buf, nowait = true })
  vim.keymap.set("n", "x", function()
    local row = vim.api.nvim_win_get_cursor(win)[1]
    local it = index[row]
    if it then
      ex.revoke(it.project, it.id)
      refresh()
    end
  end, { buffer = buf, nowait = true })
end

return M
