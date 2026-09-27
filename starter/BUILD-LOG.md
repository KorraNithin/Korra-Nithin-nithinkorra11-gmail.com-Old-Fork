# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

## Phase 0 — orientation

### 2026-09-26

`npm install` failed on Windows: `better-sqlite3` needs a native binary, no prebuilt one exists
for Node v24.12.0 (too new), and the fallback compile failed too (`node-gyp` found Visual Studio
Build Tools but no Windows SDK component installed). Tried switching to Node 20 via nvm-windows
first — the installer didn't register `nvm` on PATH, not worth debugging further under time
pressure. Fixed instead by adding the Windows SDK component to the existing VS Build Tools
install (Visual Studio Installer -> Modify -> Individual components -> Windows 11 SDK). Also hit
`EPERM` cleanup errors during `npm install` from running inside a OneDrive-synced folder — moved
the repo out of OneDrive entirely rather than fight the sync lock. Both are environment problems,
not code, but cost real time before any of the actual exercise started.

## Phase 1 — token verification

### 2026-09-26

Implemented `verifyAccessToken`. First pass compared the signature with just
`timingSafeEqual(signature, expected)`. Ran `check-jwt.js`: 41/43 passed, but "signature
truncated" and "signature is not base64url" failed — not with a clean rejection, but with
`RangeError: Input buffers must have the same byte length`. `timingSafeEqual` throws on a length
mismatch instead of returning false, so a malformed signature crashed the check instead of
producing a 401 — in production that would be a 500 with a stack trace on attacker-controlled
input, not a clean auth failure. Fixed by checking `signature.length !== expected.length` before
calling `timingSafeEqual`. Reran: 43/43.

## Phase 2 — caller context and the resolution engine

### 2026-09-26

My first model for org-level resolution (`resolve()` with `deviceId: null`) was "org-level only
looks at org-wide grants (`device_id IS NULL`); device-scoped grants only matter when a specific
device is asked about." Rereading `PERMISSIONS.md §3` broke that: it explicitly calls org-level
"the union across all devices in the org" — if a permission holds on even one device, the
org-level view should reflect that, not be blind to it. Moved to: org-level scope includes EVERY
grant for that user in the org, org-wide and device-scoped alike; a specific `deviceId` narrows
scope to org-wide grants plus that one device's grants. `check-permissions.js` (35/35) doesn't
actually force this distinction — no test combines `deviceId: null` with a device-scoped grant —
so this is a documented interpretation, not something the public suite confirmed. Logged in
`DECISIONS.md`.

## Phase 3 — orgs, members, invites

### 2026-09-26

`check-api.js`: "demoting a NON-last owner is allowed" failed — an owner (rank 50) demoting a
DIFFERENT owner (also rank 50) got 403, expected 200. My `assertCanModify` required strictly
higher rank to modify anyone at all, including a peer, using `ranks[caller] <= ranks[target]`.
That's wrong: the real rule is equal-OR-higher rank may modify; only strictly lower rank is
refused. Self-modification is a completely separate refusal (`SELF_ROLE_CHANGE`, checked before
`assertCanModify` even runs), not something rank equality should catch. Changed the condition
from `<=` to `<`. This wasn't a typo — I'd conflated two independent rules (peer-authority vs.
self-protection) into one comparison. Reran `check-api.js`: 66/66.

Also worked out from `AUTH-DATA-MODEL.md §6` (not stated anywhere else) that invite creation
reuses this exact same rank check: "the invited role must be one the inviter could assign
themselves" is the same authority question as a role change, so `assertCanModify(ctx.role,
invitedRole)` guards invite creation too, with no separate rule needed.

## Phase 4 — devices and grants

### 2026-09-26

`AUTH-DATA-MODEL.md §8`'s self-grant test (dana granting herself `audit:read`) doesn't fail
`assertMayGrant` — dana is owner and already holds `audit:read` via role baseline, so the
no-laundering check (assertMayGrant) legitimately passes. Self-granting has to be its own,
separate refusal, unrelated to whether the caller holds the permission — a caller can hold a
permission and still not be allowed to grant it to themselves. Added a standalone
`userId === ctx.userId` check in the grants route, ordered after `assertMayGrant` per the table
in `AUTH-DATA-MODEL.md §8`.

## Phase 5 — sessions

### 2026-09-26

`check-api.js`: `DEVICE_BUSY` (409) wasn't firing on a second concurrent `control` session on the
same device — got an unhandled 500 instead. My catch checked
`err.message.includes('one_exclusive_session_per_device')`, but the actual `SqliteError` text is
just `"UNIQUE constraint failed: sessions.device_id"` — it never names the index. Fixed by
checking `err.code === 'SQLITE_CONSTRAINT_UNIQUE'` instead, which is the only UNIQUE constraint
reachable from that specific INSERT. This is the "let the DB enforce it, don't pre-check and
race" pattern (D10) — the exclusivity guarantee is real specifically because the constraint, not
application logic, is what fires under concurrent requests.

Also built `assertCanStartSession` to check `session:start` and the mode's device permission
(`device:view`/`device:control`/`device:terminal`) as two SEPARATE checks in a fixed order, so a
refusal can say which one failed (`missing_permission` vs `missing_device_permission`) — this
distinction is asked for directly in `AUTH-DATA-MODEL.md §9` and confirmed correct by
`check-api.js`'s three-case session-start block.

## Phase 6 — audit

### 2026-09-26

Verified `auditDenials` empirically before wiring it into routes: called it with a function that
throws `forbidden(...)` (a 403) and confirmed a `deny` row gets written with the reason code
intact; called it with a function that throws `notFound()` (a 404) and confirmed NOTHING gets
logged. That's a deliberate line, not an oversight — `PERMISSIONS.md §8` frames the log as
answering "who tried to change what," which is an authorization question; a 404 is structural
invisibility and a 400 is malformed input, neither of which is a permission system saying no to
someone with standing to ask. Logged as a decision since the doc doesn't spell out which status
counts as a "denial" — it's my reading, held until a hidden test says otherwise.

## Phase 7 — the console

_Not started yet._

## Phase 8 — hardening

_Not started yet._

## Open threads

- The console (frontend) is entirely unbuilt as of this entry — everything above is the server
  and its three public test suites (`check-jwt.js` 43/43, `check-permissions.js` 35/35,
  `check-api.js` 66/66).
- Pagination bounds on `GET /orgs/:org/audit` (`limit` max 1000) are my own invented number, not
  derived from any document — nothing states a maximum anywhere I found.
- `assertNotLastOwner` only counts `status = 'active'` owners as protection (a suspended owner
  doesn't count). Logged in `DECISIONS.md`; unconfirmed by any test.
- Device transfer writes its audit row scoped to the SOURCE org only, not the destination org.
  Haven't decided if a transfer should produce two audit rows (one per org) — time-boxed this as
  "good enough" rather than researching it further.
- The "Where this repo argues with itself" section in `DECISIONS.md` is still empty. Still
  looking — the specs are dense enough that I expect to find one before submission, and I'm not
  going to leave it blank if I do.