// All ~30 endpoints (BRIEF.md §5.1), wired onto the four server modules.
//
// Conventions used throughout, since BRIEF.md leaves route structure to us:
//   - A single resource GET/PATCH/DELETE returns that resource's fields directly at
//     the top level of the body (no wrapper) -- LOCKED for sessions, since
//     check-api.js reads `body.state`, `body.end_reason` directly.
//   - A collection GET returns { <name>: [...] } -- also locked for devices/sessions
//     by check-api.js (`body.devices`, `body.sessions`).
//   - "A resource you cannot see is a 404, not a 403" (BRIEF.md §3.1) is applied
//     uniformly: GET of a single device/session the caller lacks view rights on is
//     404, matching the list-filtering behaviour, not 403.

import { send, badRequest, forbidden, notFound, conflict, gone, deviceBusy, normalizeTs, HttpError } from '../http.js';
import { newId, nowIso } from '../db.js';
import {
  issueAccessToken,
  newRefreshToken,
  hashRefreshToken,
  newInviteToken,
  hashInviteToken,
  hashPassword,
  verifyPassword,
  REFRESH_TTL_SECONDS,
} from '../auth.js';
import { resolve, resolveDevices, assertCan, assertMayGrant, assertCanStartSession } from '../permissions.js';
import { assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

const MAX_AUDIT_LIMIT = 1000; // undocumented; our own bound -- see DECISIONS.md

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

function parseCookies(req) {
  const header = req.headers['cookie'];
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function setRefreshCookie(res, raw, req) {
  // Secure has to track whether the CONNECTION is actually encrypted, not NODE_ENV.
  // This app has no TLS anywhere in its own code -- `npm start` (NODE_ENV=production)
  // still serves plain HTTP, and so does the e2e harness (tests/playwright.config.js
  // runs NODE_ENV=production against http://localhost). Tying Secure to NODE_ENV made
  // the cookie unreadable on its own reload: "a reload restores the session from the
  // refresh cookie" failed for exactly this reason -- the browser silently refuses to
  // send a Secure cookie back over plain HTTP, so the very next request found no
  // cookie at all. req.socket.encrypted is true only behind an actual TLS socket (or
  // a trusted proxy terminating it, which this app doesn't have), so it's the
  // honest signal here.
  const secure = req?.socket?.encrypted ? '; Secure' : '';
  res.setHeader('Set-Cookie', `rt=${raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${REFRESH_TTL_SECONDS}${secure}`);
}

function issueRefreshToken(db, userId, familyId = newId('fam')) {
  const raw = newRefreshToken();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId, new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString());
  return { raw, familyId };
}

// The one membership lookup every org-scoping auth endpoint needs: exists AND active,
// or the caller cannot proceed. These routes take orgId from the BODY, not the URL,
// so context.js's automatic params.org structural check never sees it -- an org this
// user isn't a member of at all is still invisible (404), same principle, applied here.
function requireActiveMembership(db, userId, orgId) {
  const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`).get(orgId, userId);
  if (!membership) throw notFound();
  if (membership.status !== 'active') throw forbidden('membership is not active', 'inactive_membership');
  return membership;
}

function orgsForUser(db, userId) {
  return db
    .prepare(
      `SELECT o.id, o.name, o.theme, m.role
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY m.rowid ASC`
    )
    .all(userId);
}

function defaultOrgId(db, userId) {
  const row = db
    .prepare(
      `SELECT m.org_id AS orgId
         FROM memberships m JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
        ORDER BY m.rowid ASC LIMIT 1`
    )
    .get(userId);
  return row?.orgId ?? null;
}

// Shared shape for login / token-switch / refresh / invite-accept -- all end with
// "here is a caller, scoped to an org, with a fresh access token".
function buildAuthPayload(db, secret, { userId, orgId }) {
  const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`).get(orgId, userId);
  const user = db.prepare(`SELECT id, email, name FROM users WHERE id = ?`).get(userId);
  const { permissions } = resolve(db, { userId, orgId, deviceId: null });
  const token = issueAccessToken({ userId, orgId, role: membership.role, permVersion: membership.perm_version }, secret);
  return { token, orgId, role: membership.role, user, orgs: orgsForUser(db, userId), permissions };
}

function parsePagingParam(query, name, { min, max, fallback }) {
  const raw = query.get(name);
  if (raw === null) return fallback;
  if (!/^-?\d+$/.test(raw)) throw badRequest(`${name} must be an integer`);
  const n = Number(raw);
  if (n < min || (max !== undefined && n > max)) throw badRequest(`${name} out of range`);
  return n;
}

function getActiveMembership(db, orgId, userId) {
  return db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`).get(orgId, userId);
}

function getDevice(db, orgId, deviceId) {
  return db.prepare(`SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`).get(deviceId, orgId);
}

// ---------------------------------------------------------------------------
export function registerRoutes(router, { db, secret }) {
  // ==== AUTH =================================================================

  router.post('/v1/auth/login', (ctx, params, res) => {
    const { email, password, orgId } = ctx.body ?? {};
    if (typeof email !== 'string' || typeof password !== 'string') throw badRequest('email and password are required');

    const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email.trim().toLowerCase());
    // Same status/message whether the account doesn't exist or the password is wrong --
    // BRIEF.md §5.3: telling those apart is an account enumeration oracle.
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw new HttpError(401, 'UNAUTHENTICATED', 'invalid email or password');
    }

    const targetOrgId = orgId ?? defaultOrgId(db, user.id);
    if (!targetOrgId) throw new HttpError(401, 'UNAUTHENTICATED', 'no active organization membership');
    requireActiveMembership(db, user.id, targetOrgId);

    const payload = buildAuthPayload(db, secret, { userId: user.id, orgId: targetOrgId });
    const { raw } = issueRefreshToken(db, user.id);
    setRefreshCookie(res, raw, ctx.req);
    send(res, 200, payload);
  });

  router.post('/v1/auth/refresh', (ctx, params, res) => {
    const raw = parseCookies(ctx.req).rt;
    if (!raw) throw new HttpError(401, 'UNAUTHENTICATED', 'missing refresh token');

    const row = db.prepare(`SELECT * FROM refresh_tokens WHERE token_hash = ?`).get(hashRefreshToken(raw));
    if (!row) throw new HttpError(401, 'UNAUTHENTICATED', 'invalid refresh token');

    // Replay of an already-rotated token: kill the whole lineage (AUTH-DATA-MODEL.md §10).
    if (row.revoked_at) {
      db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`).run(nowIso(), row.family_id);
      throw new HttpError(401, 'UNAUTHENTICATED', 'refresh token reuse detected');
    }
    if (row.expires_at <= nowIso()) throw new HttpError(401, 'UNAUTHENTICATED', 'refresh token expired');

    // orgId is optional here, unlike /auth/token: a page reload has NO client-side
    // memory to supply one (the UI keeps the access token in memory only, nothing in
    // web storage), so refresh has to be able to restore a session from the cookie
    // alone. Falls back to the same "earliest active membership" default as login.
    const orgId = ctx.body?.orgId ?? defaultOrgId(db, row.user_id);
    if (!orgId) throw new HttpError(401, 'UNAUTHENTICATED', 'no active organization membership');
    requireActiveMembership(db, row.user_id, orgId);

    db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`).run(nowIso(), row.id);
    const { raw: newRaw } = issueRefreshToken(db, row.user_id, row.family_id);
    setRefreshCookie(res, newRaw, ctx.req);

    send(res, 200, buildAuthPayload(db, secret, { userId: row.user_id, orgId }));
  });

  router.post('/v1/auth/token', (ctx, params, res) => {
    const { orgId } = ctx.body ?? {};
    if (!orgId) throw badRequest('orgId is required');
    requireActiveMembership(db, ctx.userId, orgId);
    send(res, 200, buildAuthPayload(db, secret, { userId: ctx.userId, orgId }));
  });

  router.get('/v1/auth/me', (ctx, params, res) => {
    const user = db.prepare(`SELECT id, email, name FROM users WHERE id = ?`).get(ctx.userId);
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: null });
    send(res, 200, { user, orgId: ctx.orgId, role: ctx.role, orgs: orgsForUser(db, ctx.userId), permissions });
  });

  // ==== ORGS =================================================================

  router.get('/v1/orgs', (ctx, params, res) => {
    send(res, 200, { orgs: orgsForUser(db, ctx.userId) });
  });

  router.post('/v1/orgs', (ctx, params, res) => {
    const { name, theme } = ctx.body ?? {};
    if (typeof name !== 'string' || name.trim().length === 0) throw badRequest('name is required');

    const orgId = newId('org');
    db.prepare(`INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)`).run(orgId, name.trim(), theme ?? 'slate');
    db.prepare(`INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'owner', 'active', ?)`)
      .run(newId('mem'), orgId, ctx.userId, nowIso());

    audit(db, { orgId, actorId: ctx.userId, action: 'org.create', targetType: 'organization', targetId: orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: orgId, name: name.trim(), theme: theme ?? 'slate', role: 'owner' });
  });

  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'org.update', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'org:update')
    );
    const { name, theme, maxSessionMinutes } = ctx.body ?? {};
    const fields = [], values = [];
    if (name !== undefined) { fields.push('name = ?'); values.push(name); }
    if (theme !== undefined) { fields.push('theme = ?'); values.push(theme); }
    if (maxSessionMinutes !== undefined) { fields.push('max_session_minutes = ?'); values.push(maxSessionMinutes); }
    if (fields.length > 0) db.prepare(`UPDATE organizations SET ${fields.join(', ')} WHERE id = ?`).run(...values, params.org);

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.update', targetType: 'organization', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 200, db.prepare(`SELECT id, name, theme, max_session_minutes FROM organizations WHERE id = ?`).get(params.org));
  });

  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'org.delete', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'org:delete')
    );
    db.prepare(`UPDATE organizations SET deleted_at = ? WHERE id = ?`).run(nowIso(), params.org);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.delete', targetType: 'organization', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: params.org, deleted: true });
  });

  // ==== MEMBERS ==============================================================

  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.list', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:read')
    );
    const members = db
      .prepare(
        `SELECT m.user_id AS userId, u.name, u.email, m.role, m.status, m.joined_at AS joinedAt
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? ORDER BY m.rowid ASC`
      )
      .all(params.org);
    send(res, 200, { members });
  });

  // Registered BEFORE ':userId' -- router.js: "register specific paths before
  // parameterised ones if they could overlap." 'me' would otherwise be captured as
  // a literal :userId value by the route below.
  router.delete('/v1/orgs/:org/members/me', (ctx, params, res) => {
    const membership = getActiveMembership(db, params.org, ctx.userId);
    if (!membership) throw notFound();
    if (membership.role === 'owner') assertNotLastOwner(db, params.org, ctx.userId);

    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(membership.id);
    endActiveSessions(db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.leave', targetType: 'membership', targetId: membership.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: ctx.userId, status: 'removed' });
  });

  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (params.userId === ctx.userId) throw new HttpError(403, 'SELF_ROLE_CHANGE', 'you cannot change your own role');

    await auditDenials(db, ctx, { action: 'member.role_update', targetType: 'membership', targetId: params.userId, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:role:update')
    );

    const target = getActiveMembership(db, params.org, params.userId);
    if (!target) throw notFound();

    const { role } = ctx.body ?? {};
    assertRoleExists(db, role);
    // Rank rules: the caller must outrank BOTH the role being taken away and the role
    // being conferred (D8) -- this is what stops "admin cannot confer owner".
    assertCanModify(db, ctx.role, target.role);
    assertCanModify(db, ctx.role, role);

    if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, params.org, params.userId);

    db.prepare(`UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE id = ?`).run(role, target.id);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.role_update', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, role });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.suspend', targetType: 'membership', targetId: params.userId, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:remove')
    );
    const target = getActiveMembership(db, params.org, params.userId);
    if (!target) throw notFound();
    if (target.role === 'owner') assertNotLastOwner(db, params.org, params.userId);

    // No perm_version bump: the token still verifies (context.js decision), and
    // resolve() reads `status` fresh on every call, giving the empty set immediately.
    db.prepare(`UPDATE memberships SET status = 'suspended' WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.suspend', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, status: 'suspended' });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.reinstate', targetType: 'membership', targetId: params.userId, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:remove')
    );
    const target = getActiveMembership(db, params.org, params.userId);
    if (!target) throw notFound();

    db.prepare(`UPDATE memberships SET status = 'active' WHERE id = ?`).run(target.id);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.reinstate', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, status: 'active' });
  });

  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'member.remove', targetType: 'membership', targetId: params.userId, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:remove')
    );
    const target = getActiveMembership(db, params.org, params.userId);
    if (!target) throw notFound();
    if (target.role === 'owner') assertNotLastOwner(db, params.org, params.userId);

    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.remove', targetType: 'membership', targetId: target.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { userId: params.userId, status: 'removed' });
  });

  // ==== INVITES ==============================================================

  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.create', targetType: 'invite', targetId: null, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:invite')
    );

    const { role } = ctx.body ?? {};
    const email = String(ctx.body?.email ?? '').trim().toLowerCase();
    if (!email) throw badRequest('email is required');
    assertRoleExists(db, role);
    // AUTH-DATA-MODEL.md §6: "the invited role must be one the inviter could assign
    // themselves" -- the same rank rule as a role change (D8).
    assertCanModify(db, ctx.role, role);

    const activeMember = db
      .prepare(
        `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.org_id = ? AND u.email = ? AND m.status = 'active'`
      )
      .get(params.org, email);
    if (activeMember) throw conflict('this email is already an active member of this organization');

    const rawToken = newInviteToken();
    const inviteId = newId('inv');
    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(inviteId, params.org, email, role, hashInviteToken(rawToken), ctx.userId, new Date(Date.now() + 7 * 86_400_000).toISOString());
    } catch {
      throw conflict('an invite is already pending for this email');
    }

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: inviteId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: inviteId, email, role, inviteToken: rawToken });
  });

  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.list', targetType: 'invite', targetId: null, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:invite')
    );
    const invites = db
      .prepare(
        `SELECT id, email, role, expires_at AS expiresAt, created_at AS createdAt
           FROM invites WHERE org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL
          ORDER BY created_at DESC`
      )
      .all(params.org);
    send(res, 200, { invites });
  });

  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'invite.revoke', targetType: 'invite', targetId: params.id, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:invite')
    );
    const invite = db
      .prepare(`SELECT * FROM invites WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`)
      .get(params.id, params.org);
    if (!invite) throw notFound();

    db.prepare(`UPDATE invites SET revoked_at = ? WHERE id = ?`).run(nowIso(), invite.id);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: invite.id, revoked: true });
  });

  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = db.prepare(`SELECT * FROM invites WHERE token_hash = ?`).get(hashInviteToken(params.token));
    if (!invite) throw notFound();
    if (invite.accepted_at || invite.revoked_at || invite.expires_at <= nowIso()) throw gone();

    const org = db.prepare(`SELECT name FROM organizations WHERE id = ?`).get(invite.org_id);
    // AUTH-DATA-MODEL.md §6: only orgName, role, email, expiresAt. No org id, no device data.
    send(res, 200, { orgName: org.name, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
  });

  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const invite = db.prepare(`SELECT * FROM invites WHERE token_hash = ?`).get(hashInviteToken(params.token));
    if (!invite) throw notFound();
    if (invite.accepted_at) throw conflict('this invite has already been accepted');
    if (invite.revoked_at || invite.expires_at <= nowIso()) throw gone();

    const { name, password } = ctx.body ?? {};
    if (typeof password !== 'string' || password.length < 8) throw badRequest('password must be at least 8 characters');

    let user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(invite.email);
    if (!user) {
      if (typeof name !== 'string' || name.trim().length === 0) throw badRequest('name is required');
      const userId = newId('usr');
      db.prepare(`INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)`)
        .run(userId, invite.email, name.trim(), hashPassword(password));
      user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
    }

    const existingMembership = getActiveMembership(db, invite.org_id, user.id);
    if (existingMembership) {
      db.prepare(`UPDATE memberships SET role = ?, status = 'active', joined_at = ?, perm_version = perm_version + 1 WHERE id = ?`)
        .run(invite.role, nowIso(), existingMembership.id);
    } else {
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`
      ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso());
    }

    db.prepare(`UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?`).run(nowIso(), user.id, invite.id);

    const payload = buildAuthPayload(db, secret, { userId: user.id, orgId: invite.org_id });
    const { raw } = issueRefreshToken(db, user.id);
    setRefreshCookie(res, raw, ctx.req);

    audit(db, { orgId: invite.org_id, actorId: user.id, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, payload);
  });

  // ==== DEVICES ==============================================================

  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.list', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'device:list')
    );
    const rows = db.prepare(`SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL`).all(params.org);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds: rows.map((r) => r.id) });

    const devices = rows
      .filter((r) => byDevice[r.id]['device:view']?.effect === 'allow')
      .map((r) => ({ id: r.id, name: r.name, kind: r.kind, online: !!r.online, permissions: byDevice[r.id] }));
    send(res, 200, { devices });
  });

  router.get('/v1/orgs/:org/devices/:id', (ctx, params, res) => {
    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();
    const { permissions } = resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: device.id });
    // Not present, not permitted to view -- same rule as the list, so a single fetch
    // can't be used to probe for devices the list already hid (BRIEF.md §3.1).
    if (permissions['device:view']?.effect !== 'allow') throw notFound();
    send(res, 200, { id: device.id, name: device.name, kind: device.kind, online: !!device.online, permissions });
  });

  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.create', targetType: 'device', targetId: null, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'device:provision')
    );
    const { name, kind } = ctx.body ?? {};
    if (typeof name !== 'string' || name.trim().length === 0) throw badRequest('name is required');

    const deviceId = newId('dev');
    db.prepare(`INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)`).run(deviceId, params.org, name.trim(), kind);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.create', targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: deviceId, name: name.trim(), kind, online: false });
  });

  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.update', targetType: 'device', targetId: params.id, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'device:update')
    );
    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();

    const { name, kind, online } = ctx.body ?? {};
    const fields = [], values = [];
    if (name !== undefined) { fields.push('name = ?'); values.push(name); }
    if (kind !== undefined) { fields.push('kind = ?'); values.push(kind); }
    if (online !== undefined) { fields.push('online = ?'); values.push(online ? 1 : 0); }
    if (fields.length > 0) db.prepare(`UPDATE devices SET ${fields.join(', ')} WHERE id = ?`).run(...values, device.id);

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    const updated = db.prepare(`SELECT * FROM devices WHERE id = ?`).get(device.id);
    send(res, 200, { id: updated.id, name: updated.name, kind: updated.kind, online: !!updated.online });
  });

  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.delete', targetType: 'device', targetId: params.id, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'device:provision')
    );
    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();

    db.prepare(`UPDATE devices SET deleted_at = ? WHERE id = ?`).run(nowIso(), device.id);
    endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'admin_terminated' });
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.delete', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: device.id, deleted: true });
  });

  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'device.transfer', targetType: 'device', targetId: params.id, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'device:provision')
    );
    const device = getDevice(db, params.org, params.id);
    if (!device) throw notFound();

    const { targetOrgId } = ctx.body ?? {};
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    // The caller must ALSO hold device:provision in the destination org (BRIEF.md §5.1:
    // "in both orgs"). Not a member there at all -> that org is invisible to them, 404,
    // same structural principle as everywhere else.
    const destMembership = getActiveMembership(db, targetOrgId, ctx.userId);
    if (!destMembership) throw notFound();
    const destPerms = resolve(db, { userId: ctx.userId, orgId: targetOrgId, deviceId: null }).permissions;
    if (destPerms['device:provision']?.effect !== 'allow') throw forbidden('missing device:provision in the destination organization', 'missing_permission');

    db.prepare(`UPDATE devices SET org_id = ? WHERE id = ?`).run(targetOrgId, device.id);
    endActiveSessions(db, { orgId: params.org, deviceId: device.id, reason: 'device_transferred' });
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: device.id, name: device.name, kind: device.kind, orgId: targetOrgId });
  });

  // ==== GRANTS ===============================================================

  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grant.create', targetType: 'grant', targetId: null, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'grant:create')
    );

    const { userId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body ?? {};

    // Order follows AUTH-DATA-MODEL.md §8's table exactly.
    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty array');
    for (const p of permissions) {
      const known = db.prepare(`SELECT 1 FROM permission_patterns WHERE pattern = ?`).get(p);
      if (!known) throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
    }
    if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');

    let device = null;
    if (deviceId) {
      device = getDevice(db, params.org, deviceId);
      if (!device) throw notFound();
    }

    const targetMembership = getActiveMembership(db, params.org, userId);
    if (!targetMembership || targetMembership.status !== 'active') throw notFound();

    const normalizedStarts = normalizeTs(startsAt, 'startsAt');
    const normalizedExpires = normalizeTs(expiresAt, 'expiresAt');
    if (normalizedExpires && normalizedExpires <= nowIso()) {
      throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt must be in the future');
    }

    // No laundering: the caller must hold every permission being granted, at this scope.
    assertMayGrant(db, ctx, permissions, deviceId ?? null);
    if (userId === ctx.userId) throw forbidden('cannot grant to yourself', 'self_grant');

    const grantId = newId('grt');
    db.prepare(
      `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(grantId, params.org, userId, deviceId ?? null, effect, normalizedStarts, normalizedExpires, ctx.userId);
    for (const p of permissions) {
      db.prepare(`INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)`).run(grantId, p);
    }

    db.prepare(`UPDATE memberships SET perm_version = perm_version + 1 WHERE id = ?`).run(targetMembership.id);
    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: grantId, userId, deviceId: deviceId ?? null, effect, permissions, startsAt: normalizedStarts, expiresAt: normalizedExpires });
  });

  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grant.list', targetType: 'grant', targetId: null, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'user:read')
    );
    const userIdFilter = ctx.query.get('userId');
    const rows = db
      .prepare(
        `SELECT * FROM grants WHERE org_id = ? AND revoked_at IS NULL ${userIdFilter ? 'AND user_id = ?' : ''} ORDER BY created_at DESC`
      )
      .all(...(userIdFilter ? [params.org, userIdFilter] : [params.org]));

    const permsByGrant = db.prepare(`SELECT permission FROM grant_permissions WHERE grant_id = ?`);
    const grants = rows.map((g) => ({
      id: g.id,
      userId: g.user_id,
      deviceId: g.device_id,
      effect: g.effect,
      startsAt: g.starts_at,
      expiresAt: g.expires_at,
      permissions: permsByGrant.all(g.id).map((r) => r.permission),
    }));
    send(res, 200, { grants });
  });

  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'grant.revoke', targetType: 'grant', targetId: params.id, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'grant:revoke')
    );
    const grant = db.prepare(`SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL`).get(params.id, params.org);
    if (!grant) throw notFound(); // already revoked -- no longer visible (AUTH-DATA-MODEL.md §8)

    db.prepare(`UPDATE grants SET revoked_at = ? WHERE id = ?`).run(nowIso(), grant.id);
    const targetMembership = getActiveMembership(db, params.org, grant.user_id);
    if (targetMembership) db.prepare(`UPDATE memberships SET perm_version = perm_version + 1 WHERE id = ?`).run(targetMembership.id);

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { id: grant.id, revoked: true });
  });

  // ==== SESSIONS =============================================================

  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    const { deviceId, mode } = ctx.body ?? {};
    const device = getDevice(db, params.org, deviceId);
    if (!device) throw notFound();

    await auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId, requestId: ctx.requestId }, () =>
      assertCanStartSession(db, ctx, mode, deviceId)
    );

    const sessionId = newId('ses');
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId });
    const expiresAt = sessionExpiry(db, params.org);

    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      ).run(sessionId, params.org, ctx.userId, deviceId, mode, authorizedBy, expiresAt);
    } catch (err) {
      // D10: the DB, not application logic, enforces one exclusive (control/terminal)
      // session per device -- a second concurrent request loses the race here. The
      // actual SqliteError message is "UNIQUE constraint failed: sessions.device_id" --
      // it does not name the index -- so match on the error code, the one UNIQUE
      // constraint reachable from this exact INSERT.
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') throw deviceBusy();
      throw err;
    }

    audit(db, { orgId: params.org, actorId: ctx.userId, action: 'session.start', targetType: 'session', targetId: sessionId, result: 'allow', requestId: ctx.requestId });
    const row = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(sessionId);
    send(res, 201, row);
  });

  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'session.list', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'session:view')
    );
    const sessions = db.prepare(`SELECT * FROM sessions WHERE org_id = ? ORDER BY started_at DESC`).all(params.org);
    send(res, 200, { sessions });
  });

  router.get('/v1/sessions/:id', (ctx, params, res) => {
    const session = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();

    const isParticipant = session.user_id === ctx.userId;
    const canView = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: null }).permissions['session:view']?.effect === 'allow';
    if (!isParticipant && !canView) throw notFound(); // invisible, not forbidden -- BRIEF.md §3.1
    send(res, 200, session);
  });

  router.delete('/v1/sessions/:id', (ctx, params, res) => {
    const session = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();

    const isOwn = session.user_id === ctx.userId;
    const canTerminate = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: null }).permissions['session:terminate']?.effect === 'allow';
    if (!isOwn && !canTerminate) throw notFound();

    db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`)
      .run(isOwn ? 'user_stopped' : 'admin_terminated', nowIso(), session.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.terminate', targetType: 'session', targetId: session.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(session.id));
  });

  // ==== EFFECTIVE PERMISSIONS ================================================

  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    if (params.userId !== ctx.userId) {
      await auditDenials(db, ctx, { action: 'user.effective', targetType: 'membership', targetId: params.userId, requestId: ctx.requestId }, () =>
        assertCan(db, ctx, 'user:read')
      );
    }
    const target = getActiveMembership(db, params.org, params.userId);
    if (!target) throw notFound();
    const result = resolve(db, { userId: params.userId, orgId: params.org, deviceId: null });
    send(res, 200, { role: result.role, permissions: result.permissions });
  });

  // ==== AUDIT ================================================================

  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    await auditDenials(db, ctx, { action: 'audit.read', targetType: 'organization', targetId: params.org, requestId: ctx.requestId }, () =>
      assertCan(db, ctx, 'audit:read')
    );
    const limit = parsePagingParam(ctx.query, 'limit', { min: 1, max: MAX_AUDIT_LIMIT, fallback: 50 });
    const offset = parsePagingParam(ctx.query, 'offset', { min: 0, fallback: 0 });

    const events = db
      .prepare(`SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?`)
      .all(params.org, limit, offset);
    send(res, 200, { events });
  });
}