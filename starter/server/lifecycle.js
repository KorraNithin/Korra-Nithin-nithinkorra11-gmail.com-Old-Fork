// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// YOURS TO WRITE. This file ships as a stub.
//
// Put here the rules more than one route needs, so "what ends a session" has exactly
// one implementation. Sources: PERMISSIONS.md §7.2 and D8.
//
// Two traps worth naming before you start:
//   - `roles.rank` is MODIFICATION AUTHORITY ONLY. It must never answer a can()
//     question. operator and auditor are unordered by permission, and ranking them is
//     the modelling error the auditor role exists to catch.
//   - a permission change does NOT end a session in flight (grantfathering). Suspension,
//     membership removal and device transfer DO. See PERMISSIONS.md §7.

import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';
import { resolve } from './permissions.js';

// Read from `roles`, never hardcode the five names — personalisation may add a
// sixth (README: "at least one role ... this exercise's prose never mentions").
export function roleRanks(db) {
  const rows = db.prepare(`SELECT key, rank FROM roles`).all();
  const ranks = {};
  for (const row of rows) ranks[row.key] = row.rank;
  return ranks;
}

export function assertRoleExists(db, role) {
  const row = db.prepare(`SELECT 1 FROM roles WHERE key = ?`).get(role);
  if (!row) throw badRequest(`unknown role: ${role}`);
}

// D8: rank is MODIFICATION AUTHORITY ONLY, never a can() answer -- this is the one
// place roles are ordered (`owner > admin > operator > auditor > viewer`), and it
// stays out of permissions.js on purpose so it can never leak into a resolve() call.
// Strictly higher rank may modify strictly lower; equal rank (admin -> admin) and
// self (rank === rank, same role) are both refused by the same "<=" check.
// D8: rank is MODIFICATION AUTHORITY ONLY, never a can() answer -- this is the one
// place roles are ordered (`owner > admin > operator > auditor > viewer`), and it
// stays out of permissions.js on purpose so it can never leak into a resolve() call.
// Equal-or-higher rank may modify; only STRICTLY lower rank is refused. Self-
// modification is a completely separate refusal (SELF_ROLE_CHANGE in the route), not
// this rank check -- confirmed by check-api.js "demoting a NON-last owner is allowed",
// where an owner (rank 50) demotes a DIFFERENT owner (rank 50): equal rank, allowed.
// My first version used "<=" here, which wrongly refused that case too -- see
// BUILD-LOG.md / DECISIONS.md for the correction.
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  assertRoleExists(db, callerRole);
  assertRoleExists(db, targetRole);
  if (ranks[callerRole] < ranks[targetRole]) {
    throw forbidden(`${callerRole} may not modify ${targetRole}`, 'modification_rank');
  }
}

// D8: removing or demoting the last owner is 409 LAST_OWNER, not 403 -- it is a
// state-conflict, not a permission refusal. Only ACTIVE owners count: a suspended
// owner isn't currently exercising ownership, so they don't protect the org from
// going ownerless in practice (logged in DECISIONS.md -- this line isn't stated
// explicitly in PERMISSIONS.md §6).
export function assertNotLastOwner(db, orgId, userId) {
  const { n } = db
    .prepare(
      `SELECT COUNT(*) AS n FROM memberships
        WHERE org_id = ? AND role = 'owner' AND status = 'active' AND user_id != ?`
    )
    .get(orgId, userId);
  if (n === 0) throw lastOwner();
}

// The one place a session ends. Bulk by design: suspension and membership removal
// end every active session for a user in an org; a device transfer/decommission ends
// every active session on that device. `exceptSessionId` lets a caller end "every
// other" session (e.g. superseding one) without a second query.
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const clauses = [`org_id = ?`, `state = 'active'`];
  const params = [orgId];
  if (userId) { clauses.push(`user_id = ?`); params.push(userId); }
  if (deviceId) { clauses.push(`device_id = ?`); params.push(deviceId); }
  if (exceptSessionId) { clauses.push(`id != ?`); params.push(exceptSessionId); }

  const ids = db.prepare(`SELECT id FROM sessions WHERE ${clauses.join(' AND ')}`).all(...params);
  const end = db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`);
  const endedAt = nowIso();
  for (const { id } of ids) end.run(reason, endedAt, id);
  return ids.length;
}

// A session's authority is snapshotted at start and never re-derived afterwards
// (PERMISSIONS.md §7: "A session's authority is snapshotted when it starts and does
// not change afterwards"). This IS that snapshot -- stored verbatim in
// sessions.authorized_by, which is why the column has `CHECK (json_valid(...))`.
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const { role, permissions } = resolve(db, { userId, orgId, deviceId });
  return JSON.stringify({ role, permissions, snapshotAt: nowIso() });
}

// started_at + org.max_session_minutes (default 60), per PERMISSIONS.md §7 -- the TTL
// that makes grandfathering safe: a revoked grant's authority dies with the session,
// within the hour at the latest, even though the session itself isn't touched early.
export function sessionExpiry(db, orgId) {
  const org = db.prepare(`SELECT max_session_minutes FROM organizations WHERE id = ?`).get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
}