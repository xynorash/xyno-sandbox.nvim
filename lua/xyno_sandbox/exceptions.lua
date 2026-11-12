-- Logged approval flow for exceptions to the default policy. Nothing is approved silently:
-- every decision (approved, refused, revoked) is appended to the log with a timestamp, the
-- project, the kind and the path or variable NAME (never a value). A refused exception changes
-- nothing: the plan built afterwards is identical to the one built without it.
--
-- kinds:  env       let one environment variable through (it is no longer stripped)
--         unhide    show one hidden credential path (the real one, read-only like the rest of $HOME)
--         writable  make one more existing path writable
--         host      allow one more network host (name, *.suffix, optional :port) through the proxy
-- scopes: "once"    for this launch only (the caller passes the returned exception as opts.exceptions)
--         "project" remembered for this project; listed and revocable (:XynoSandboxApprovals)
local plan = require("xyno_sandbox.plan")
local store = require("xyno_sandbox.store")
local M = {}

local function normalize(kind, value)
  if kind == "env" then
    return value
  elseif kind == "host" then
    local ent = require("xyno_sandbox.net").parse_entry(value)
    return ent and ent.text or value
  end
  return plan.normalize(value) or value
end

--- Record an operator decision.
--- @param project string
--- @param decision "approved"|"refused"
--- @param exc { kind: string, value: string }
--- @param scope? "once"|"project"  default "once"
--- @return table? exception  the exception to apply (approved and valid), else nil
--- @return string? reason    why an approval was turned into a refusal
function M.decide(project, decision, exc, scope)
  assert(decision == "approved" or decision == "refused", "decision must be approved or refused")
  scope = scope == "project" and "project" or "once"
  local value = normalize(exc.kind, exc.value)
  local entry = { project = project, kind = exc.kind, value = value, decision = decision, scope = scope }
  if decision == "refused" then
    store.log(entry)
    return nil
  end
  local ok, why = plan.validate_exception(
    { kind = exc.kind, value = value },
    { home = vim.uv.os_homedir(), state_dir = store.dir(), probes = plan.real_probes() }
  )
  if not ok then
    entry.decision, entry.reason = "refused", why
    store.log(entry)
    return nil, why
  end
  if scope == "project" then
    store.remember(project, exc.kind, value)
  end
  store.log(entry)
  return { kind = exc.kind, value = value, scope = scope }
end

--- Remembered approvals: of one project (list) or of all (project -> list).
function M.list(project)
  if project then
    return store.approvals(project)
  end
  return store.all_approvals()
end

--- Withdraw a remembered approval; logged as "revoked". Returns true when it existed.
function M.revoke(project, id)
  local rec = store.revoke(project, id)
  if not rec then
    return false
  end
  store.log({ project = project, kind = rec.kind, value = rec.value, decision = "revoked", scope = "project" })
  return true
end

return M
