-- What a run changed in the project tree that acts OUTSIDE the sandbox later.
--
-- Two jobs, both on the real filesystem (the plan is pure and cannot do them):
--
--  1. PLANTED NAMES. Files and directories whose names make a tool of yours run something
--     (`.cargo/config.toml`, `.envrc`, `.claude/settings.json`, `.vscode/tasks.json`, a nested `.git`
--     with hooks, `mise.toml`, `rust-toolchain.toml`, ...: plan.WATCH_NAMES) are read-only in the
--     sandbox where they exist, and masked where they are absent in the shallowest directories
--     (plan.SUBDIR_MASK_MAX). Everywhere else a run can still create one, so a snapshot is taken at
--     launch and compared when the run ends: every NEW protected name is copied into a quarantine
--     directory under the state dir (nothing is lost), removed from the project, and the project is
--     marked dirty: the next launch is refused until you reviewed the quarantine (:XynoSandboxReview,
--     then :XynoSandboxReview clear).
--
--  2. FILES THE AGENT MAY EDIT THAT RUN LATER. Makefile, justfile, package.json, Cargo.toml, build.rs,
--     CI workflows... cannot be locked (the agent has to edit them); a hash of each is kept at launch and
--     a summary of what changed (lines added and removed) is reported when the run ends.
--
-- It is bounded (directories, time) and says when a bound stopped the walk.
local plan_mod = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local M = {}

M.MAX_DIRS = 20000
M.MAX_DEPTH = 40
M.MAX_MS = 1500
-- the directories in SKIP_DIRS are walked too, for the protected names only (a cargo config under target/debug, an .envrc in
-- node_modules/x), with a budget of their own so that a huge build tree cannot use up the main one
M.SKIP_MAX_DIRS = 4000
M.SKIP_MAX_MS = 700
M.REVIEW_MAX_BYTES = 128 * 1024
M.CONTENT_MAX_BYTES = 8 * 1024 * 1024 -- content read inside protected names per snapshot (more: signature only)
M.REVIEW_KEEP_BYTES = 4 * 1024 * 1024 -- text kept in memory for the diff summary (more: hashes only)
M.QUARANTINE_FILE_MAX = 1024 * 1024
M.QUARANTINE_ENTRIES_MAX = 300
M.QUARANTINE_DEPTH = 8 -- directory levels copied into the quarantine
M.UNLOCK_MAX = 5000 -- entries opened for the owner when a removal fails on read-only directories
-- walked in a second pass with the smaller budget above (M.SKIP_MAX_DIRS / M.SKIP_MAX_MS), after everything else
M.SKIP_DIRS = { target = true, node_modules = true, [".git"] = true, [".venv"] = true, venv = true, __pycache__ = true }
-- their content changes by itself while you work (the index, the IDE's workspace file): only their
-- appearance counts, never a change inside
M.NOISY = { [".git"] = true, [".idea"] = true }

local function is_review(name, dir)
  for _, n in ipairs(plan_mod.REVIEW_NAMES) do
    if n == name then
      return true
    end
  end
  return dir:sub(-18) == "/.github/workflows"
end

local function sig_of(st)
  return ("%s:%d:%d.%d"):format(st.type, st.size or 0, st.mtime and st.mtime.sec or 0, st.mtime and st.mtime.nsec or 0)
end

local function list(path)
  local out = {}
  local h = vim.uv.fs_scandir(path)
  while h do
    local name, ty = vim.uv.fs_scandir_next(h)
    if not name then
      break
    end
    out[#out + 1] = { name, ty }
  end
  table.sort(out, function(a, b)
    return a[1] < b[1]
  end)
  return out
end

-- signature of a protected directory: its whole listing (bounded), so a file planted inside changes it.
-- `collect(rel, st, path)` (optional) is called for every entry that is inside the bound (the content record uses it).
local function dir_sig(path, collect)
  local parts, n = {}, 400
  local function rec(p, rel, d)
    for _, e in ipairs(list(p)) do
      n = n - 1
      if n < 0 then
        return
      end
      local st = vim.uv.fs_lstat(p .. "/" .. e[1])
      if st then
        parts[#parts + 1] = rel .. e[1] .. "=" .. sig_of(st)
        if collect then
          collect(rel .. e[1], st, p .. "/" .. e[1])
        end
        if st.type == "directory" and d < 6 then
          rec(p .. "/" .. e[1], rel .. e[1] .. "/", d + 1)
        end
      end
    end
  end
  rec(path, "", 0)
  return table.concat(parts, "|")
end

local function read_small(path, max)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local data = f:read(max + 1) or "" -- (nil at the end of an empty file)
  f:close()
  if #data > max then
    return nil
  end
  return data
end

local function ident(st)
  return ("%.0f:%.0f"):format(st.dev or 0, st.ino or 0)
end

--- Walk `project` and record the protected names and the review files. The directories of SKIP_DIRS are
--- walked after the rest with a budget of their own. A bound that stopped the walk is recorded:
--- `truncated` (main budget), `skip_truncated` (the second pass), `depth_cut` (a directory below MAX_DEPTH).
--- @param project string
--- @return { protected: table<string,string>, ino: table<string,string>, review: table<string,table>, dirs: integer, truncated: boolean, skip_truncated: boolean, depth_cut: boolean, why?: string }
function M.snapshot(project)
  local snap = {
    protected = {},
    ino = {},
    content = {},
    review = {},
    trees = {},
    bin = {},
    dirs = 0,
    skip_dirs = 0,
    truncated = false,
    skip_truncated = false,
    depth_cut = false,
  }
  local watch, slashed = {}, {}
  for _, n in ipairs(plan_mod.WATCH_NAMES) do
    if n:find("/", 1, true) then
      slashed[#slashed + 1] = n
    else
      watch[n] = true
    end
  end
  local kept = 0
  local content_bytes = 0
  -- what is IN a protected name: one record per file below it ({ id = hash of the content, text? }), so a changed
  -- file is found whatever its size and mtime say, and a protected name that moved is compared by content
  local function file_rec(path, st)
    if st.type == "link" then
      return { id = "link:" .. tostring(vim.uv.fs_readlink(path)) }
    elseif st.type == "file" then
      if st.size <= M.REVIEW_MAX_BYTES and content_bytes + st.size <= M.CONTENT_MAX_BYTES then
        local data = read_small(path, M.REVIEW_MAX_BYTES)
        if data then
          content_bytes = content_bytes + #data
          local rec = { id = "sha:" .. vim.fn.sha256(data) }
          if kept + #data <= M.REVIEW_KEEP_BYTES then
            rec.text = data
            kept = kept + #data
          end
          return rec
        end
      end
      return { id = "sig:" .. sig_of(st) } -- too big (or unreadable): the signature only
    end
    return { id = st.type }
  end
  local function record_protected(path, noisy)
    local st = vim.uv.fs_lstat(path)
    if st then
      local sig = sig_of(st)
      if st.type == "directory" and not noisy then
        local files = { [""] = { id = "directory" } }
        sig = sig
          .. "#"
          .. dir_sig(path, function(rel, est, epath)
            files[rel] = file_rec(epath, est)
          end)
        snap.content[path] = { files = files }
      elseif noisy then
        sig = st.type -- appearance only
      else
        snap.content[path] = { files = { [""] = file_rec(path, st) } }
      end
      if snap.content[path] then
        local ids = {}
        for rel, f in pairs(snap.content[path].files) do
          ids[#ids + 1] = rel .. "\0" .. f.id
        end
        table.sort(ids)
        snap.content[path].hash = vim.fn.sha256(table.concat(ids, "\n"))
      end
      snap.protected[path] = sig
      snap.ino[path] = ident(st)
    end
  end
  local function record_review(path)
    local st = vim.uv.fs_lstat(path)
    if not st or st.type ~= "file" then
      return
    end
    local rec = { sig = sig_of(st), size = st.size }
    local data = st.size <= M.REVIEW_MAX_BYTES and read_small(path, M.REVIEW_MAX_BYTES) or nil
    if data then
      rec.sha = vim.fn.sha256(data)
      if kept + #data <= M.REVIEW_KEEP_BYTES then
        rec.text = data
        kept = kept + #data
      end
    end
    snap.review[path] = rec
  end
  -- sources that a tool compiles and runs later (plan.REVIEW_TREES): the content of the whole directory
  local trees = {}
  for _, n in ipairs(plan_mod.REVIEW_TREES) do
    trees[n] = true
  end
  local function record_tree(path)
    local files = { [""] = { id = "directory" } }
    dir_sig(path, function(rel, est, epath)
      files[rel] = file_rec(epath, est)
    end)
    local ids = {}
    for rel, f in pairs(files) do
      ids[#ids + 1] = rel .. "\0" .. f.id
    end
    table.sort(ids)
    snap.trees[path] = { files = files, hash = vim.fn.sha256(table.concat(ids, "\n")) }
  end
  -- node_modules/.bin (of the project and of its workspaces, not of dependencies): what an `npm run` / `npx` on your
  -- machine starts by name. One record per entry: a link's target, a file's hash (signature past 128 KB).
  local function record_bin(path)
    local n = 0
    for _, e in ipairs(list(path)) do
      n = n + 1
      if n > 500 then
        break
      end
      local ep = path .. "/" .. e[1]
      local st = vim.uv.fs_lstat(ep)
      if st then
        snap.bin[ep] = file_rec(ep, st).id
      end
    end
  end
  local skipped = {}
  -- one breadth-first pass over `queue`; directories of SKIP_DIRS go to `skipped` (first pass) or are entered (second)
  local function pass(queue, second)
    local t0 = vim.uv.hrtime()
    local max_dirs, max_ms = second and M.SKIP_MAX_DIRS or M.MAX_DIRS, second and M.SKIP_MAX_MS or M.MAX_MS
    local count = 0
    local qi = 1
    while qi <= #queue do
      local dir, depth = queue[qi][1], queue[qi][2]
      qi = qi + 1
      count = count + 1
      local over
      if count > max_dirs then
        over = "more than " .. max_dirs .. " directories"
      elseif (vim.uv.hrtime() - t0) / 1e6 > max_ms then
        over = "more than " .. max_ms .. " ms"
      end
      if over then
        if second then
          snap.skip_truncated = true
          snap.skip_why = over .. " inside target, node_modules, virtualenvs"
        else
          snap.truncated, snap.why = true, over
        end
        break
      end
      if second then
        snap.skip_dirs = snap.skip_dirs + 1
      else
        snap.dirs = snap.dirs + 1
      end
      local present = {}
      for _, e in ipairs(list(dir)) do
        local name, ty = e[1], e[2]
        present[name] = true
        local path = dir .. "/" .. name
        if watch[name] then
          record_protected(path, M.NOISY[name])
        end
        if is_review(name, dir) then
          record_review(path)
        end
        if trees[name] and (ty == "directory" or ty == nil or ty == "unknown") then
          record_tree(path)
        end
        if name == ".bin" and dir:sub(-13) == "/node_modules" and not dir:sub(1, -14):find("/node_modules", 1, true) then
          record_bin(path)
        end
        if ty == nil or ty == "unknown" then
          local st = vim.uv.fs_lstat(path)
          ty = st and st.type
        end
        if ty == "directory" and not watch[name] then
          if depth >= M.MAX_DEPTH then
            snap.depth_cut = true
          elseif M.SKIP_DIRS[name] and not second then
            skipped[#skipped + 1] = { path, depth + 1 }
          else
            queue[#queue + 1] = { path, depth + 1 }
          end
        end
      end
      if present[".config"] then
        for _, rel in ipairs(slashed) do
          if vim.uv.fs_lstat(dir .. "/" .. rel) then
            record_protected(dir .. "/" .. rel, false)
          end
        end
      end
    end
  end
  pass({ { project, 0 } }, false)
  if #skipped > 0 then
    pass(skipped, true)
  end
  return snap
end

local function count_lines(text)
  local n = 0
  for _ in (text or ""):gmatch("[^\n]*\n?") do
    n = n + 1
  end
  return n
end

--- Lines added and removed between two texts (nil, nil when either text was not kept).
local function line_delta(a, b)
  if not a or not b then
    return nil, nil
  end
  local ok, hunks = pcall(vim.text.diff, a, b, { result_type = "indices" })
  if not ok or type(hunks) ~= "table" then
    return nil, nil
  end
  local plus, minus = 0, 0
  for _, h in ipairs(hunks) do
    minus = minus + h[2]
    plus = plus + h[4]
  end
  return plus, minus
end

local function nlines(text)
  if not text or text == "" then
    return 0
  end
  local _, n = text:gsub("\n", "")
  return n + (text:sub(-1) == "\n" and 0 or 1)
end

--- The lines that differ between two texts, as "+ x" / "- y" (at most `max`, each cut at 72 characters). nil when a
--- text was not kept. A created file has `a == ""`.
local function diff_lines(a, b, max)
  if not a or not b then
    return nil
  end
  local ok, hunks = pcall(vim.text.diff, a, b, { result_type = "indices" })
  if not ok or type(hunks) ~= "table" then
    return nil
  end
  local al, bl = vim.split(a, "\n", { plain = true }), vim.split(b, "\n", { plain = true })
  local out = {}
  local function put(sign, text)
    if #out < max then
      text = text:gsub("[%c]", " ")
      out[#out + 1] = sign .. " " .. (#text > 72 and (text:sub(1, 72) .. "...") or text)
    end
  end
  for _, h in ipairs(hunks) do
    for i = h[1], h[1] + h[2] - 1 do
      put("-", al[i] or "")
    end
    for i = h[3], h[3] + h[4] - 1 do
      put("+", bl[i] or "")
    end
  end
  return out
end
M._diff_lines = diff_lines

--- What changed between two content records of a protected name: lines added and removed (nil when a file's text
--- was not kept) and the names (relative to the protected name) that differ.
local function content_delta(b, a)
  local plus, minus, names, known = 0, 0, {}, true
  local function add(p, m)
    if p and m then
      plus, minus = plus + p, minus + m
    else
      known = false
    end
  end
  local function lines_of(f)
    if f.text then
      return nlines(f.text)
    elseif f.id:sub(1, 4) == "sha:" or f.id:sub(1, 4) == "sig:" then
      return nil -- a file whose text was not kept: the count is unknown
    end
    return 0 -- a directory or a link has no lines
  end
  for rel, af in pairs(a.files) do
    local bf = b.files[rel]
    if not bf then
      names[#names + 1] = rel == "" and "(itself)" or rel
      add(lines_of(af), 0)
    elseif bf.id ~= af.id then
      names[#names + 1] = rel == "" and "(itself)" or rel
      add(line_delta(bf.text, af.text))
    end
  end
  for rel, bf in pairs(b.files) do
    if not a.files[rel] then
      names[#names + 1] = rel == "" and "(itself)" or rel
      add(0, lines_of(bf))
    end
  end
  table.sort(names)
  return known and plus or nil, known and minus or nil, names
end

--- What differs between a launch snapshot and a snapshot taken now.
--- `moved`: the same inode under a new path. `tampered`: of those, the ones whose CONTENT is not what it was at launch
--- (a protected directory renamed and then given a new file). `modified`: a name that existed at launch and changed
--- (signature or content); `details[path]` holds its lines added and removed.
--- @return { planted: string[], modified: string[], removed: string[], moved: { from: string, to: string }[], tampered: { from: string, to: string, plus?: integer, minus?: integer, names: string[] }[], details: table<string, table>, incomplete: string[], partial: string[], info: string[], review: { path: string, change: string, plus?: integer, minus?: integer }[] }
function M.compare(before, after)
  local res = {
    planted = {},
    modified = {},
    removed = {},
    review = {},
    trees = {},
    bin = {},
    moved = {},
    tampered = {},
    details = {},
    incomplete = {},
    partial = {},
    info = {},
  }
  -- a directory that was RENAMED during the run (mv sub sub_old) shows its protected names under a new path: they are the
  -- same inodes as before, not new files. Their CONTENT is still compared with what it was at launch.
  local gone = {}
  for p in pairs(before.protected) do
    if after.protected[p] == nil and before.ino and before.ino[p] then
      gone[before.ino[p]] = p
    end
  end
  local function changed(p_before, p_after)
    local bc = before.content and before.content[p_before]
    local ac = after.content and after.content[p_after]
    if bc and ac and bc.hash ~= ac.hash then
      local plus, minus, names = content_delta(bc, ac)
      return true, { plus = plus, minus = minus, names = names }
    end
    return false
  end
  for p, sig in pairs(after.protected) do
    local from = before.protected[p] == nil and after.ino and gone[after.ino[p] or ""] or nil
    if from then
      res.moved[#res.moved + 1] = { from = from, to = p }
      local diff, d = changed(from, p)
      if diff then
        res.tampered[#res.tampered + 1] = { from = from, to = p, plus = d.plus, minus = d.minus, names = d.names }
      end
      gone[after.ino[p]] = nil
    elseif before.protected[p] == nil then
      res.planted[#res.planted + 1] = p
    else
      local diff, d = changed(p, p)
      if diff or before.protected[p] ~= sig then
        res.modified[#res.modified + 1] = p
        res.details[p] = d or { plus = 0, minus = 0, names = {} }
      end
    end
  end
  local moved_from = {}
  for _, m in ipairs(res.moved) do
    moved_from[m.from] = true
  end
  for p in pairs(before.protected) do
    if after.protected[p] == nil and not moved_from[p] then
      res.removed[#res.removed + 1] = p
    end
  end
  -- a bound that stopped the walk now but not at launch means the tree grew past what can be checked: whatever was
  -- created beyond it is unknown. Fail closed (dirty). A tree that was already too large at launch is only reported.
  for _, b in ipairs({
    { "truncated", "the project walk stopped (" .. tostring(after.why) .. ")" },
    { "depth_cut", "directories deeper than " .. M.MAX_DEPTH .. " levels were not entered" },
  }) do
    if after[b[1]] then
      table.insert(before[b[1]] and res.partial or res.incomplete, b[2])
    end
  end
  -- The walk inside target/, node_modules/ and virtualenvs is a second, separate budget. An ordinary first build
  -- fills target/ with thousands of directories, so "the bound was hit now and not at launch" says nothing about
  -- protected names there: it is INFO (res.info), never `incomplete` (which refuses the next launch). Only a
  -- protected NAME that the walk finds (planted / modified, below) marks the project dirty.
  if after.skip_truncated and not before.skip_truncated then
    res.info[#res.info + 1] = "the walk inside target, node_modules and virtualenvs stopped ("
      .. tostring(after.skip_why)
      .. "): the tree grew during the run (a build); protected names in the part that was not walked are not compared"
  elseif after.skip_truncated then
    table.insert(
      res.partial,
      "the walk inside target, node_modules and virtualenvs stopped (" .. tostring(after.skip_why) .. ")"
    )
  end
  for p, a in pairs(after.review) do
    local b = before.review[p]
    if not b then
      res.review[#res.review + 1] =
        { path = p, change = "created", plus = a.text and count_lines(a.text) - 1 or nil, minus = 0, lines = a.text and diff_lines("", a.text, 6) or nil }
    elseif (a.sha or a.sig) ~= (b.sha or b.sig) then
      local plus, minus = line_delta(b.text, a.text)
      res.review[#res.review + 1] =
        { path = p, change = "changed", plus = plus, minus = minus, lines = diff_lines(b.text, a.text, 6) }
    end
  end
  for p, b in pairs(before.review) do
    if not after.review[p] then
      res.review[#res.review + 1] =
        { path = p, change = "deleted", plus = 0, minus = b.text and count_lines(b.text) - 1 or nil }
    end
  end
  -- build sources and node_modules/.bin
  res.trees, res.bin = {}, {}
  for p, a in pairs(after.trees or {}) do
    local b = before.trees and before.trees[p]
    if not b then
      local plus, _, names = content_delta({ files = {} }, a)
      res.trees[#res.trees + 1] = { path = p, change = "created", plus = plus, minus = 0, names = names }
    elseif b.hash ~= a.hash then
      local plus, minus, names = content_delta(b, a)
      res.trees[#res.trees + 1] = { path = p, change = "changed", plus = plus, minus = minus, names = names }
    end
  end
  for p, b in pairs(before.trees or {}) do
    if not (after.trees and after.trees[p]) then
      res.trees[#res.trees + 1] = { path = p, change = "deleted", names = {} }
    end
  end
  table.sort(res.trees, function(x, y)
    return x.path < y.path
  end)
  -- (only where the second pass looked at launch AND now: a bound that stopped it is already reported above)
  if not before.skip_truncated and not after.skip_truncated then
    for ep, id in pairs(after.bin or {}) do
      local bid = before.bin and before.bin[ep]
      if bid == nil then
        res.bin[#res.bin + 1] = { path = ep, change = "added", id = id }
      elseif bid ~= id then
        res.bin[#res.bin + 1] = { path = ep, change = "changed", id = id }
      end
    end
    for ep in pairs(before.bin or {}) do
      if not (after.bin and after.bin[ep]) then
        res.bin[#res.bin + 1] = { path = ep, change = "removed", id = "" }
      end
    end
    table.sort(res.bin, function(x, y)
      return x.path < y.path
    end)
  end
  table.sort(res.moved, function(x, y)
    return x.to < y.to
  end)
  table.sort(res.tampered, function(x, y)
    return x.to < y.to
  end)
  table.sort(res.planted)
  table.sort(res.modified)
  table.sort(res.removed)
  table.sort(res.review, function(x, y)
    return x.path < y.path
  end)
  return res
end

-- ------------------------------------------------------------- quarantine

local function copy_tree(src, dest, budget, depth)
  local st = vim.uv.fs_lstat(src)
  if not st then
    return
  end
  budget.n = budget.n - 1
  if budget.n < 0 then
    budget.cut = true
    return
  end
  if st.type == "link" then
    local target = vim.uv.fs_readlink(src)
    if target then
      vim.fn.mkdir(vim.fs.dirname(dest), "p")
      vim.uv.fs_symlink(target, dest)
    end
  elseif st.type == "directory" then
    vim.fn.mkdir(dest, "p")
    if depth < M.QUARANTINE_DEPTH then
      if not vim.uv.fs_scandir(src) then
        vim.uv.fs_chmod(src, bit.bor(st.mode, tonumber("700", 8))) -- (a 000 directory the agent made: it is ours)
      end
      for _, e in ipairs(list(src)) do
        copy_tree(src .. "/" .. e[1], dest .. "/" .. e[1], budget, depth + 1)
      end
    end
  elseif st.type == "file" then
    vim.fn.mkdir(vim.fs.dirname(dest), "p")
    if st.size <= M.QUARANTINE_FILE_MAX then
      local data = read_small(src, M.QUARANTINE_FILE_MAX)
      if not data and bit.band(st.mode, tonumber("400", 8)) == 0 then
        vim.uv.fs_chmod(src, bit.bor(st.mode, tonumber("600", 8)))
        data = read_small(src, M.QUARANTINE_FILE_MAX)
      end
      if data then
        local f = io.open(dest, "wb")
        if f then
          f:write(data)
          f:close()
          vim.uv.fs_chmod(dest, tonumber("600", 8))
        end
      end
    else
      budget.cut = true
    end
  end
end

local function safe_key(project)
  return (project:gsub("[^%w]", "_")):sub(-80) .. "-" .. vim.fn.sha256(project):sub(1, 8)
end

local function dirty_path(project)
  return store.dir() .. "/dirty/" .. safe_key(project) .. ".json"
end

--- Remove a file, a link or a directory tree. A symlink is unlinked, never followed. 0 = removed, -1 = something is left.
--- (Not vim.fn.delete: it prints E484 for every directory it cannot open.)
local function rmtree(p)
  local st = vim.uv.fs_lstat(p)
  if not st then
    return 0
  end
  local ok = true
  if st.type == "directory" then
    for _, e in ipairs(list(p)) do
      if rmtree(p .. "/" .. e[1]) ~= 0 then
        ok = false
      end
    end
    return (ok and vim.uv.fs_rmdir(p)) and 0 or -1
  end
  return vim.uv.fs_unlink(p) and 0 or -1
end

M._delete = rmtree -- (replaceable in specs)

--- Give the owner every permission on the directories at and below `p` (a directory the agent made 555 or 000 cannot be
--- emptied otherwise; the mode of a file does not matter for removing it). Symlinks are left alone. Bounded.
local function unlock_tree(p, budget)
  local st = vim.uv.fs_lstat(p)
  budget.n = budget.n - 1
  if not st or budget.n < 0 then
    return
  end
  if st.type == "directory" then
    vim.uv.fs_chmod(p, bit.bor(st.mode, tonumber("700", 8)))
    for _, e in ipairs(list(p)) do
      unlock_tree(p .. "/" .. e[1], budget)
    end
  end
end

--- Remove `p`; when that fails (a 555 parent, a 555 directory inside) give the owner write access to the parents up to
--- `root` and to everything below `p`, try again, and put the modes of the parents back. Returns the result of the delete
--- (0 = removed).
local function force_delete(root, p)
  local rc = M._delete(p)
  if rc == 0 then
    return 0
  end
  local restore = {}
  local dir = vim.fs.dirname(p)
  while dir and #dir >= #root and dir ~= "/" do
    local st = vim.uv.fs_lstat(dir)
    if st and st.type == "directory" and bit.band(st.mode, tonumber("700", 8)) ~= tonumber("700", 8) then
      restore[#restore + 1] = { dir, bit.band(st.mode, tonumber("7777", 8)) }
      vim.uv.fs_chmod(dir, bit.bor(st.mode, tonumber("700", 8)))
    end
    if dir == root then
      break
    end
    dir = vim.fs.dirname(dir)
  end
  unlock_tree(p, { n = M.UNLOCK_MAX })
  rc = M._delete(p)
  for _, r in ipairs(restore) do
    vim.uv.fs_chmod(r[1], r[2])
  end
  return rc
end

--- Top-level names of each git directory of git write mode (`dirs`, plan.git_audit), at launch.
function M.git_top(dirs)
  local out = {}
  for _, d in ipairs(dirs or {}) do
    local set = {}
    for _, e in ipairs(list(d)) do
      set[e[1]] = true
    end
    out[d] = set
    local mset = {}
    for _, e in ipairs(list(d .. "/modules")) do
      mset[e[1]] = true
    end
    out[d .. "/modules"] = mset
  end
  return out
end

--- End of a git write mode run: the paths below a git directory that are NEW since launch and outside the allowlist
--- (plan.git_write_allowed). A mount cannot refuse a new name in a directory git must write to, so this is the
--- enforcement for those; a new submodule git directory below modules/ is not allowed at all. Returns paths.
function M.git_audit(before, dirs)
  local plan = require("xyno_sandbox.plan")
  local out = {}
  for _, d in ipairs(dirs or {}) do
    local had = before and before[d] or {}
    for _, e in ipairs(list(d)) do
      if not had[e[1]] and not plan.git_write_allowed(e[1]) then
        out[#out + 1] = d .. "/" .. e[1]
      end
    end
  end
  -- a new name below modules/ (a submodule git directory made by hand)
  for _, d in ipairs(dirs or {}) do
    local mod = d .. "/modules"
    local had = before and before[mod] or {}
    for _, e in ipairs(list(mod)) do
      if not had[e[1]] then
        out[#out + 1] = mod .. "/" .. e[1]
      end
    end
  end
  return out
end

--- Copy `paths` (planted names) into the quarantine and remove them from the project. Returns
--- { dir, moved = { { path, ok } }, cut }. A parent directory the agent made read-only (555) is opened up for the removal and put back
--- afterwards (a directory the sweep cannot list or enter never shows a planted name in the first place); a name that still cannot be removed is reported (`ok = false`).
function M.quarantine(project, paths)
  local stamp = os.date("!%Y%m%dT%H%M%SZ")
  local dir = ("%s/quarantine/%s/%s"):format(store.dir(), safe_key(project), stamp)
  local moved, cut = {}, false
  vim.fn.mkdir(dir, "p")
  vim.uv.fs_chmod(dir, tonumber("700", 8))
  for _, p in ipairs(paths) do
    local rel = p:sub(1, #project + 1) == project .. "/" and p:sub(#project + 2) or vim.fs.basename(p)
    local budget = { n = M.QUARANTINE_ENTRIES_MAX }
    copy_tree(p, dir .. "/" .. rel, budget, 0)
    cut = cut or budget.cut or false
    local rc = force_delete(project, p)
    moved[#moved + 1] = { path = p, ok = rc == 0 }
  end
  return { dir = dir, moved = moved, cut = cut }
end

--- Mark the project dirty (the next launch is refused until cleared).
function M.mark_dirty(project, info)
  local rec = {
    project = project,
    ts = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    planted = info.planted or {},
    quarantine = info.quarantine,
    failed = info.failed or {},
    modified = info.modified or {},
    tampered = info.tampered or {},
    incomplete = info.incomplete or {},
  }
  local ok, text = pcall(vim.json.encode, rec)
  if not ok then
    return false
  end
  local path = dirty_path(project)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = io.open(path, "wb")
  if not f then
    return false
  end
  f:write(text)
  f:close()
  vim.uv.fs_chmod(path, tonumber("600", 8))
  return true
end

--- The dirty record of a project or nil.
function M.dirty(project)
  local f = io.open(dirty_path(project), "rb")
  if not f then
    return nil
  end
  local raw = f:read("*a")
  f:close()
  local ok, rec = pcall(vim.json.decode, raw)
  if ok and type(rec) == "table" then
    return rec
  end
  -- a record that cannot be read still blocks: it exists for a reason
  return { project = project, planted = {}, unreadable = true }
end

function M.clear_dirty(project)
  return vim.uv.fs_unlink(dirty_path(project)) and true or false
end

--- The refusal text of a dirty project.
function M.dirty_reason(rec)
  local planted = rec.planted or {}
  local shown = {}
  for i = 1, math.min(5, #planted) do
    shown[#shown + 1] = planted[i]
  end
  local text = ""
  if #planted > 0 then
    text = (
      "a previous sandbox run created %d file%s that run outside the sandbox (%s%s) and they were removed from the project;"
      .. " a copy is in %s."
    ):format(
      #planted,
      #planted == 1 and "" or "s",
      table.concat(shown, ", "),
      #planted > 5 and ", ..." or "",
      rec.quarantine or "the state directory"
    )
  end
  if rec.incomplete and #rec.incomplete > 0 then
    text = text
      .. (#planted > 0 and " " or "")
      .. ("The end-of-run check of the project tree could not be completed (%s), so more may have been created."):format(
        table.concat(rec.incomplete, "; ")
      )
  end
  if rec.tampered and #rec.tampered > 0 then
    local t = rec.tampered[1]
    text = text
      .. (text ~= "" and " " or "")
      .. ("A protected name was moved and its content changed (%s -> %s%s)."):format(
        tostring(t.from),
        tostring(t.to),
        #rec.tampered > 1 and (", and %d more"):format(#rec.tampered - 1) or ""
      )
  end
  if text == "" then
    text = "a previous sandbox run left this project marked for review."
  end
  return text .. " Review it (:XynoSandboxReview), then clear the mark with :XynoSandboxReview clear"
end

--- The report text of a finished run (nil when nothing changed). The second result marks the lines that are about a
--- protected name that was changed or moved-and-changed: those are shown as errors, not as hints.
function M.report(res)
  local lines, loud = {}, {}
  if #res.review > 0 then
    local parts = {}
    for _, r in ipairs(res.review) do
      local d = (r.plus and r.minus) and (" +%d -%d"):format(r.plus, r.minus) or ""
      local shown = r.lines and #r.lines > 0 and (" [" .. table.concat(r.lines, " | ") .. "]") or ""
      parts[#parts + 1] = ("%s %s%s%s"):format(r.change, r.path, d, shown)
    end
    lines[#lines + 1] = ("files that run on your machine later were edited (review before you build or run them): %s"):format(
      table.concat(vim.list_slice(parts, 1, 8), "; ") .. (#parts > 8 and ("; ... " .. #parts .. " in all") or "")
    )
  end
  if res.trees and #res.trees > 0 then
    local parts = {}
    for _, t in ipairs(res.trees) do
      local d = (t.plus and t.minus) and (" +%d -%d"):format(t.plus, t.minus) or ""
      local names = #t.names > 0 and (" (" .. table.concat(vim.list_slice(t.names, 1, 4), ", ") .. ")") or ""
      parts[#parts + 1] = ("%s %s%s%s"):format(t.change, t.path, d, names)
    end
    lines[#lines + 1] = ("build sources that a tool compiles and RUNS on your machine at the next build were edited (read the diff before you build): %s"):format(
      table.concat(vim.list_slice(parts, 1, 8), "; ") .. (#parts > 8 and ("; ... " .. #parts .. " in all") or "")
    )
    loud[#lines] = true
  end
  if res.bin and #res.bin > 0 then
    local added, changed, removed = {}, {}, {}
    for _, b in ipairs(res.bin) do
      local list_ = b.change == "added" and added or b.change == "changed" and changed or removed
      local what = b.id:sub(1, 5) == "link:" and (" -> " .. b.id:sub(6)) or (b.id:sub(1, 4) == "sha:" and " (file)" or "")
      list_[#list_ + 1] = vim.fs.basename(b.path) .. what
    end
    local function part(label, l)
      return #l > 0 and ("%s %d: %s%s"):format(label, #l, table.concat(vim.list_slice(l, 1, 6), ", "), #l > 6 and ", ..." or "")
        or nil
    end
    local parts = vim.tbl_filter(function(x)
      return x ~= nil
    end, { part("added", added), part("changed", changed), part("removed", removed) })
    lines[#lines + 1] = ("node_modules/.bin changed (what `npm run` / `npx` starts on your machine; an install does this too, a plain file or a link out of node_modules is not what an install makes): %s"):format(
      table.concat(parts, "; ")
    )
    -- loud: a REGULAR file added or changed (an npm install makes links; pnpm makes shell shims, which is noise), or a link
    -- whose target leaves node_modules
    for _, b in ipairs(res.bin) do
      if b.change ~= "removed" then
        local target = b.id:sub(1, 5) == "link:" and b.id:sub(6) or nil
        if not target or target:sub(1, 1) == "/" or target:sub(1, 6) == "../../" then
          loud[#lines] = true
        end
      end
    end
  end
  if #res.modified > 0 then
    local parts = {}
    for _, p in ipairs(res.modified) do
      local d = res.details and res.details[p]
      parts[#parts + 1] = p .. ((d and d.plus and d.minus) and (" +%d -%d"):format(d.plus, d.minus) or "")
    end
    lines[#lines + 1] = ("existing files that act outside the sandbox CHANGED (review them before you use this project): %s"):format(
      table.concat(vim.list_slice(parts, 1, 8), ", ") .. (#parts > 8 and (", ... " .. #parts .. " in all") or "")
    )
    loud[#lines] = true
  end
  if res.tampered and #res.tampered > 0 then
    local parts = {}
    for _, t in ipairs(res.tampered) do
      local d = (t.plus and t.minus) and (" +%d -%d"):format(t.plus, t.minus) or ""
      parts[#parts + 1] = ("%s -> %s%s (%s)"):format(t.from, t.to, d, table.concat(vim.list_slice(t.names, 1, 4), ", "))
    end
    lines[#lines + 1] = ("protected names that were MOVED and whose content is not what it was (review them before you use this project): %s"):format(
      table.concat(vim.list_slice(parts, 1, 8), "; ") .. (#parts > 8 and ("; ... " .. #parts .. " in all") or "")
    )
    loud[#lines] = true
  end
  return lines, loud
end

return M
