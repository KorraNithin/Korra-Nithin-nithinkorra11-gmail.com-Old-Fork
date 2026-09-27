// Append-only audit writes.
//
// audit_events has BEFORE UPDATE / BEFORE DELETE triggers, so this module only ever
// INSERTs. Two things the spec is explicit about (BRIEF.md §4, PERMISSIONS.md §8):
//
//   - DENIED attempts are recorded, not just successes. A log that only holds
//     successes cannot answer "who tried to change what".
//   - a single action produces a single row. Write the success row inside the same
//     transaction as the change it describes; do not also log the allow from a wrapper.
//
// Schema columns: id, org_id (NOT NULL), actor_id, action, target_type, target_id,
// result ('allow'|'deny'), reason_code, request_id, at.

import { newId, nowIso } from './db.js';
import { HttpError } from './http.js';

// The only place that writes to audit_events. One INSERT, no UPDATE/DELETE -- the
// triggers would reject those anyway, so this is just being honest about the shape.
export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId('evt'),
    orgId,
    actorId ?? null,
    action,
    targetType ?? null,
    targetId ?? null,
    result,
    reasonCode ?? null,
    requestId ?? null,
    nowIso()
  );
}

// Run fn(); if it refuses with a permission error, record the denial before
// rethrowing. Only a FORBIDDEN (403) is a "denied attempt" in the audit sense --
// PERMISSIONS.md §8 is about who tried to change what and was refused authority to.
// A 404 (structurally invisible resource), 400 (malformed input) or 401 (not who they
// claim to be) is not an authorization decision, so logging those here would blur the
// one thing this log is supposed to answer precisely.
export async function auditDenials(db, ctx, meta, fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType,
        targetId: meta.targetId,
        result: 'deny',
        reasonCode: err.reason,
        requestId: meta.requestId,
      });
    }
    throw err;
  }
}