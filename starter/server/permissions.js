// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// A grant's `permission` column may be an exact key or a wildcard pattern
// ('device:*', '*'). Never hardcode the resource list -- read `permissions` from
// the table, since the database is personalised with a permission this exercise's
// prose never names (README "Your database is personalised").
function patternMatches(pattern, key) {
  if (pattern === '*') return true;
  if (pattern === key) return true;
  return pattern.endsWith(':*') && key.startsWith(pattern.slice(0, -1));
}

function denyAll(keys, reason) {
  const out = {};
  for (const key of keys) out[key] = { effect: 'deny', source: null, reason };
  return out;
}

// Everything resolution needs, in a fixed small number of queries -- never one
// query per permission or per device. Shared by resolve() and resolveDevices() so a
// device-row list does exactly one round trip regardless of row count.
function loadResolutionInputs(db, { userId, orgId, now }) {
  const nowIso = now instanceof Date ? now.toISOString() : now;

  const membership = db
    .prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`)
    .get(orgId, userId);

  const allPermissions = db.prepare(`SELECT key FROM permissions`).all().map((r) => r.key);

  const baseline = membership
    ? new Set(
        db
          .prepare(`SELECT permission FROM role_permissions WHERE role = ?`)
          .all(membership.role)
          .map((r) => r.permission)
      )
    : new Set();

  // Only grants that are live right now: not revoked, and inside the half-open
  // window (PERMISSIONS.md D7 -- expires_at == now already counts as expired).
  const grants = membership
    ? db
        .prepare(
          `SELECT g.id, g.device_id, g.effect, gp.permission
             FROM grants g
             JOIN grant_permissions gp ON gp.grant_id = g.id
            WHERE g.org_id = ? AND g.user_id = ? AND g.revoked_at IS NULL
              AND (g.starts_at IS NULL OR g.starts_at <= ?)
              AND (g.expires_at IS NULL OR g.expires_at > ?)`
        )
        .all(orgId, userId, nowIso, nowIso)
    : [];

  return { membership, allPermissions, baseline, grants };
}

// PERMISSIONS.md §3, in order: identity -> applicable grants -> deny wins ->
// baseline or allow grant -> implicit deny with provenance.
//
// deviceId === null is the org-level view (PERMISSIONS.md §3: "the union across all
// devices in the org") -- every grant for this user in this org is in scope,
// org-wide or device-scoped alike. A specific deviceId is the exact per-device
// question -- only org-wide grants (device_id IS NULL) and grants on that one
// device apply. This is also why an org-wide deny is never carved out by a
// device-scoped allow (D1): the deny is always in scope, whichever question is asked.
function computeEffects({ membership, allPermissions, baseline, grants }, deviceId) {
  if (!membership) return denyAll(allPermissions, 'not_a_member');
  if (membership.status !== 'active') {
    return denyAll(allPermissions, membership.status === 'suspended' ? 'suspended' : 'not_a_member');
  }

  const inScope = (g) => deviceId === null || g.device_id === null || g.device_id === deviceId;

  const out = {};
  for (const key of allPermissions) {
    const applicable = grants.filter((g) => inScope(g) && patternMatches(g.permission, key));

    const deny = applicable.find((g) => g.effect === 'deny');
    if (deny) {
      out[key] = { effect: 'deny', source: `grant:${deny.id}`, reason: 'explicit_deny' };
      continue;
    }

    if (baseline.has(key)) {
      out[key] = { effect: 'allow', source: `role:${membership.role}`, reason: null };
      continue;
    }

    const allow = applicable.find((g) => g.effect === 'allow');
    out[key] = allow
      ? { effect: 'allow', source: `grant:${allow.id}`, reason: null }
      : { effect: 'deny', source: null, reason: 'implicit' };
  }
  return out;
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const inputs = loadResolutionInputs(db, { userId, orgId, now });
  return { role: inputs.membership?.role ?? null, permissions: computeEffects(inputs, deviceId) };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
// One query for membership, baseline and grants, then resolved in memory per device --
// the device-row shape in BRIEF.md §5.2 exists specifically so this never becomes a
// per-row round trip.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = loadResolutionInputs(db, { userId, orgId, now });
  const byDevice = {};
  for (const deviceId of deviceIds) byDevice[deviceId] = computeEffects(inputs, deviceId);
  return { role: inputs.membership?.role ?? null, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  return resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission]?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable. Translates
// resolve()'s internal reasons ('implicit', 'not_a_member') into the HTTP-facing
// reason vocabulary from PERMISSIONS.md §5, keeping the ones already in that
// vocabulary ('explicit_deny', 'suspended') as-is.
export function assertCan(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions[permission];
  if (result?.effect === 'allow') return result;
  const reason = result?.reason === 'explicit_deny' || result?.reason === 'suspended'
    ? result.reason
    : 'missing_permission';
  throw forbidden(`missing permission: ${permission}`, reason);
}

// No privilege laundering (D9): a caller may only grant authority it holds at that
// scope. A wildcard pattern being granted is expanded to the concrete permissions it
// covers, and every one of them must resolve to 'allow' for this caller at this scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const catalogueKeys = Object.keys(permissions);

  const expand = (pattern) => {
    if (pattern === '*') return catalogueKeys;
    if (pattern.endsWith(':*')) {
      const prefix = pattern.slice(0, -1);
      return catalogueKeys.filter((key) => key.startsWith(prefix));
    }
    return [pattern];
  };

  for (const pattern of patterns) {
    for (const key of expand(pattern)) {
      if (permissions[key]?.effect !== 'allow') {
        throw forbidden(`cannot grant ${pattern}: you do not hold ${key} at this scope`, 'scope_mismatch');
      }
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, both
// on the same device -- and a refusal must say WHICH of the two was missing, because
// they are different problems for the caller (AUTH-DATA-MODEL.md §9).
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest(`unknown session mode: ${mode}`);

  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  if (permissions['session:start']?.effect !== 'allow') {
    throw forbidden('cannot start sessions', 'missing_permission');
  }
  if (permissions[modePermission]?.effect !== 'allow') {
    throw forbidden(`cannot start a ${mode} session on this device`, 'missing_device_permission');
  }
  return permissions;
}