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

  local plan_mod = require("xyno_sandbox.plan")
  local ops = plan_mod.ops(plan)
  local function opt_text(args)
    local out = {}
    for i, t in ipairs(args) do
      if args[1] == "--setenv" and i == 3 then
        t = "<value not shown>"
      elseif plan.empty_file and t == plan.empty_file then
        t = "<empty file>"
      elseif t:sub(1, #home + 1) == home .. "/" then
        t = short(t, home)
      end
      out[#out + 1] = t
    end
    return table.concat(out, " ")
  end
  local function op_text(op)
    local parts = {}
    for _, o in ipairs(plan_mod.split_options(op.args)) do
      parts[#parts + 1] = opt_text(o)
    end
    return table.concat(parts, " ")
  end
  local function op_section(title, name)
    local list = vim.tbl_filter(function(o)
      return o.section == name
    end, ops)
    if #list == 0 then
      return
    end
    section(title, list, function(o)
      return ("%s  [%s]"):format(op_text(o), o.why)
    end)
  end

  local st = ctx.status
  add("sandbox   bubblewrap" .. (st and st.ready == "pending" and " (readiness check running)" or ""))
  if plan.network == "open" then
    add("network   OPEN (not restricted: the agent reaches the internet and local services)")
  else
    add(
      "network   FILTERED: no direct network; HTTPS only through a local proxy, by host name (no DNS from the sandbox)"
    )
  end
  if plan.home_mode == "allowlist" then
    add("home      EMPTY: $HOME shows only the paths listed under Home view, the project and the writable paths")
  else
    add('home      READABLE except the hidden credential paths below (home = "denylist")')
  end
  if plan.blocked then
    add("")
    add("BLOCKED: " .. plan.blocked)
  end
  add("")
  if plan.agent.stripped then
    add("Agent permission prompts: ON (" .. "--dangerously-skip-permissions removed by strip_skip_permissions)")
  elseif plan.agent.skip_permissions then
    add("Agent permission prompts: OFF (" .. plan.agent.flag .. "): the agent acts without asking;")
    add("  this sandbox is the only barrier. Set strip_skip_permissions = true to remove the flag.")
  else
    add("Agent permission prompts: not disabled by the command")
  end

  if plan.net then
    section("Network allowlist (all other hosts, raw IPs and DNS are blocked)", plan.net.hosts, function(h)
      return ("%s  [%s]"):format(h.host, h.why)
    end)
  end
  op_section("Base view (every sandbox)", "base")
  op_section("Host sockets and services masked (empty tmpfs, nothing connectable; kept read-only below it)", "sockets")
  op_section("Other users' homes hidden (empty tmpfs; toolchains kept read-only)", "homes")
  op_section("Home view", "home")
  section("Writable", plan.writable, function(w)
    return ("%s  [%s]"):format(short(w.path, home), w.why)
  end)
  if plan.git_write and #plan.git_write > 0 then
    add("")
    add(
      "Git write mode (policy.git_write = true): the agent CAN git add / git commit. Writable: index, objects, refs, HEAD, logs in"
    )
    for _, g in ipairs(plan.git_write) do
      add("  " .. short(g, home))
    end
    add(
      "  Read-only: hooks/, config, info/, config.worktree (no hook, fsmonitor, alias, filter or exclude can be planted)."
    )
    add(
      "  Not renamable (own mount): .git, modules/. Pinned: commondir. No state of rebase / am / worktree / submodule add (read-only or empty)."
    )
    add("  It can still rewrite history and move refs of this repository (recover with git reflog).")
  end
  section("Read-only inside the writable paths, git directories locked", plan.git_locked, function(p)
    return short(p, home)
  end)
  local other = {}
  for _, r in ipairs(plan.readonly) do
    if r.why ~= "git" and r.why ~= "git (write mode)" then
      other[#other + 1] = r
    end
  end
  section("Read-only (would run or steer tools outside the sandbox)", other, function(r)
    return ("%s  [%s]"):format(short(r.path, home), r.why)
  end)
  if #(plan.runs_later or {}) > 0 then
    section(
      "Agent-editable, runs later on your machine (not locked: the agent has to edit these; changes are summarised when the run ends)",
      plan.runs_later,
      function(p)
        return short(p, home)
      end
    )
  end
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
  local proj_hidden, cred_hidden = {}, {}
  for _, h in ipairs(plan.hidden) do
    table.insert(h.why:match("^project ") and proj_hidden or cred_hidden, h)
  end
  local function hfmt(h)
    return ("%s  [%s, %s]"):format(short(h.path, home), h.kind, h.why)
  end
  section("Hidden project secrets and sockets (replaced with empty ones; e approves one)", proj_hidden, hfmt)
  section("Hidden credential paths (replaced with empty ones)", cred_hidden, hfmt)
  op_section("Git configs shown without credentials (URL tokens, credential helpers, auth headers removed)", "git")
  if #(plan.hardlinks or {}) > 0 then
    section("Hidden files that have other hard links", plan.hardlinks, function(l)
      return ("%s  [%d links: %d other name%s hidden%s]"):format(
        short(l.path, home),
        l.links,
        l.masked,
        l.masked == 1 and "" or "s",
        l.unaccounted > 0 and (", " .. l.unaccounted .. " elsewhere NOT hidden") or ""
      )
    end)
  end
  if plan.scan and plan.scan.enabled then
    add("")
    add(
      (
        "Content scan: %d file%s checked for known token formats%s; %d hidden. It does not find passwords, generic keys or"
        .. " anything in a format it does not know (see the README)."
      ):format(
        plan.scan.files,
        plan.scan.files == 1 and "" or "s",
        plan.scan.truncated and (" (STOPPED: " .. tostring(plan.scan.why) .. ")") or "",
        plan.scan.hits or 0
      )
    )
    local u = plan.scan.unread
    if u and (u.large > 0 or u.binary > 0) then
      add(
        ("  Not read at all: %d over 256 KB, %d binary (NUL byte). No file is skipped for its name or extension."):format(
          u.large,
          u.binary
        )
      )
    end
  end
  op_section("Other mounts", "ephemeral")
  op_section("Agent state (~/.claude)", "claude")
  op_section("Agent config copy", "claude_json")
  op_section("Agent transcripts", "projects")
  op_section("Network socket directory", "net")
  section("Stripped environment variables (names only, values are never shown)", plan.env_strip, function(n)
    return n
  end)
  add("")
  add(
    ("Environment: bwrap starts with `env -i` and %d variables; stripped values never exist in the sandbox"):format(
      #(plan.env_pass or {})
    )
  )
  if ctx.full then
    local names = {}
    for _, kv in ipairs(plan.env_pass or {}) do
      names[#names + 1] = kv[1]
    end
    add("  passed (names): " .. table.concat(names, " "))
  end
  op_section("Set inside the sandbox (values not shown)", "setenv")
  local iso = vim.tbl_filter(function(o)
    return o.section == "isolation"
  end, ops)[1]
  add("")
  add("Isolation  " .. table.concat(iso.args, " "))
  if #(plan.symlinks or {}) > 0 then
    section("Project symlinks that leave the project", plan.symlinks, function(l)
      return ("%s -> %s  [%s]"):format(
        short(l.path, home),
        short(l.target, home),
        l.readable and "target READABLE in the sandbox" or "target not visible in the sandbox"
      )
    end)
  end

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
  if ctx.full then
    -- the exact mount order bwrap applies (a later mount wins over an earlier one)
    local options = {}
    for _, o in ipairs(ops) do
      if o.section ~= "isolation" then
        vim.list_extend(options, plan_mod.split_options(o.args))
      end
    end
    add("")
    add(("Mount order (%d options, top to bottom)"):format(#options))
    for i, o in ipairs(options) do
      add(("  %d. %s"):format(i, opt_text(o)))
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
  -- wrapped rows, not lines: a long line that wraps must not push the last lines out of a too-short
  -- window (they were cut with "@@@")
  local rows = 0
  for _, l in ipairs(lines) do
    rows = rows + math.max(1, math.ceil(vim.fn.strdisplaywidth(l) / width))
  end
  local avail = math.max(vim.o.lines - 6, 8)
  local height = math.min(rows + 1, avail)
  if rows + 1 > avail then
    footer = footer .. "   j/k scroll"
  end
  local win = vim.api.nvim_open_win(buf, true, {
    relative = "editor",
    style = "minimal",
    border = "rounded",
    width = width,
    height = height,
    row = math.max(math.floor((vim.o.lines - height) / 2) - 1, 0),
    col = math.max(math.floor((vim.o.columns - width) / 2), 0),
    title = " " .. title .. " ",
    footer = " " .. footer .. " ",
    footer_pos = "center",
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
  if plan.net then
    cands[#cands + 1] = { label = "allow another network host (name, *.suffix, host:port)...", kind = "host" }
  end
  select(cands, {
    prompt = "Exception to consider",
    format_item = function(c)
      return c.label
    end,
  }, function(c)
    if not c then
      return done(nil)
    end
    local function decide(value)
      if not value or value == "" then
        return done(nil)
      end
      local what = ("%s %s"):format(
        c.kind,
        (c.kind == "writable" or c.kind == "unhide") and short(value, home) or value
      )
      local choices = { "Approve for this launch only", "Approve for this project (remembered, revocable)", "Refuse" }
      select(
        choices,
        { prompt = "Exception: " .. what .. " (project " .. short(project, home) .. ")" },
        function(_, idx)
          if idx == 1 or idx == 2 then
            local e, why =
              ex.decide(project, "approved", { kind = c.kind, value = value }, idx == 2 and "project" or "once")
            if not e and why then
              vim.notify("xyno-sandbox: refused: " .. why, vim.log.levels.WARN)
            end
            return done(e and idx == 1 and e or nil)
          end
          ex.decide(project, "refused", { kind = c.kind, value = value })
          return done(nil)
        end
      )
    end
    if c.kind == "host" then
      vim.ui.input({ prompt = "Host name to allow (e.g. github.com): " }, decide)
    elseif c.kind == "writable" then
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
  local buf, win = float(
    M.lines(plan, { full = opts.full, status = opts.status and opts.status() }),
    opts.confirm and "Launch inside the sandbox?" or "Sandbox policy",
    footer
  )
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
    map({ "<CR>", "y" }, function()
      finish(true)
    end)
    map({ "q", "n", "<Esc>" }, function()
      finish(false)
    end)
  else
    map({ "q", "<Esc>", "<CR>" }, function()
      finish(false)
    end)
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
  vim.api.nvim_create_autocmd("BufWipeout", {
    buffer = buf,
    once = true,
    callback = function()
      finish(false)
    end,
  })
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
      out[#out + 1] = ("  [%d] %s %s   (%s)"):format(
        a.id,
        a.kind,
        a.kind == "env" and a.value or short(a.value, home),
        a.ts
      )
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
