// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// TODO — yours to implement.
//
// Verify an access token and return its claims, or throw `unauthenticated(...)`.
// The signing half above is done for you; the verifying half is the exercise.
//
// It must reject ALL of the following, each with a 401 UNAUTHENTICATED:
//
//   1. a token that is not three dot-separated segments
//   2. a header or payload that is not valid base64url-encoded JSON
//   3. a header whose `alg` is anything other than 'HS256', or whose `typ` is not 'JWT'
//      -- read the header, do NOT trust it. This is the `alg: none` and
//         algorithm-substitution defence. The constants ALG, ISS and AUD are above.
//   4. a signature that does not match, compared in constant time
//   5. an `exp` that is missing, not a number, or <= now (note: <=, not <)
//   6. an `iss` or `aud` that is not ours
//   7. a missing or empty `jti`
//
// On success, return the decoded claims object.
//
// AUTH-DATA-MODEL.md §10 lists the failure modes; §2 defines the claim set.
// `node scripts/check-jwt.js` is the public test suite for this function.
// ---------------------------------------------------------------------------
export function verifyAccessToken(token, secret) {
  if (typeof token !== 'string' || token.length === 0) {
    throw unauthenticated('malformed token');
  }

  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw unauthenticated('malformed token');
  }
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = JSON.parse(unb64(h).toString('utf8'));
  } catch {
    throw unauthenticated('malformed header');
  }
  try {
    payload = JSON.parse(unb64(p).toString('utf8'));
  } catch {
    throw unauthenticated('malformed payload');
  }

  const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isPlainObject(header) || !isPlainObject(payload)) {
    throw unauthenticated('malformed token');
  }

  // Pin the algorithm. Read the header, never trust it: only HS256/JWT is acceptable,
  // whatever the header itself claims. This is the alg:none / algorithm-substitution defence.
  if (header.alg !== ALG || header.typ !== 'JWT') {
    throw unauthenticated('unsupported algorithm');
  }

  // Signature, compared in constant time. Guard the length check ourselves —
  // timingSafeEqual throws on a length mismatch instead of returning false.
  let signature;
  try {
    signature = unb64(s);
  } catch {
    throw unauthenticated('malformed signature');
  }
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  if (signature.length !== expected.length || !timingSafeEqual(signature, expected)) {
    throw unauthenticated('bad signature');
  }

  const { exp, iss, aud, jti } = payload;
  const now = Math.floor(Date.now() / 1000);
  if (typeof exp !== 'number' || exp <= now) throw unauthenticated('token expired');
  if (iss !== ISS) throw unauthenticated('bad issuer');
  if (aud !== AUD) throw unauthenticated('bad audience');
  if (typeof jti !== 'string' || jti.length === 0) throw unauthenticated('missing jti');

  return payload;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
