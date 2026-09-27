// Per-request context: turn a bearer token into an authenticated caller.
//
// YOURS TO WRITE. This file ships as a stub so the server boots and every
// authenticated request fails loudly instead of appearing to work.
//
// What it has to do (BRIEF.md §3, PERMISSIONS.md §6):
//   - read the bearer token, verify it with verifyAccessToken() from ./auth.js
//   - look the membership up and refuse a token whose org or membership is gone
//   - THE TOKEN'S org CLAIM IS THE ONLY ORG THE CALLER MAY ADDRESS. A request that
//     names a different org is INVISIBLE — 404, never 403. Isolation is structural:
//     the caller cannot name another org, rather than being filtered afterwards.
//   - check freshness against memberships.perm_version (AUTH-DATA-MODEL.md §3), so a
//     role or grant change takes effect on the NEXT request, not at token expiry
//   - throw through the one error path in ./http.js
//
// authenticate(db, secret) returns (req, params) => caller, where caller carries at
// least { userId, orgId, role, membership, claims }.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  // One indexed lookup per request: memberships_by_user covers this, and joining
  // organizations lets us see in the same query whether the org itself is gone.
  const getMembership = db.prepare(
    `SELECT m.*, o.deleted_at AS org_deleted_at
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
      WHERE m.org_id = ? AND m.user_id = ?`
  );

  return function buildContext(req, params) {
    const header = req.headers['authorization'] ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(token, secret);

    // Structural isolation (AUTH-DATA-MODEL.md §4.4): the token's `org` claim is the
    // ONLY org this caller may address. A route naming a different org in the path is
    // invisible, not forbidden -- 404 before we even look the resource up, so a caller
    // can never distinguish "wrong org" from "doesn't exist".
    if (params?.org && params.org !== claims.org) {
      throw notFound();
    }

    const membership = getMembership.get(claims.org, claims.sub);

    // "gone" covers both halves of the context.js comment: the membership row itself
    // is missing, or the org it points at has been soft-deleted, or the membership was
    // removed outright. All three mean this caller no longer has any standing here.
    // A REMOVED membership is 401 (AUTH-DATA-MODEL.md §10), not merely "no permissions".
    if (!membership || membership.org_deleted_at || membership.status === 'removed') {
      throw unauthenticated('membership no longer valid');
    }

    // Freshness (AUTH-DATA-MODEL.md §3): compares by !==, not <, against perm_version.
    // A role change, grant change, or suspension bumps this, so a stale token is
    // rejected on the very next request rather than riding out its 15-minute TTL.
    assertFresh(claims, membership);

    // Deliberately NOT rejecting `status === 'suspended'` here. The token still
    // verifies and the membership still exists -- PERMISSIONS.md §3 step 1 says a
    // suspended user "has no permissions anywhere", which is the resolution engine's
    // job to enforce (empty set, every check denies), not context.js's. Rejecting here
    // with 401 would be wrong: AUTH-DATA-MODEL.md §10 calls for 403 with an empty
    // permission set, which requires reaching the permission check, not authentication.

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}