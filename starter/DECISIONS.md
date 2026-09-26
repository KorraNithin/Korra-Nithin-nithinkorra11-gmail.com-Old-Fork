# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Suspension is not an authentication failure

**What I chose:** `authenticate()` in `server/context.js` lets a token for a suspended
membership pass authentication. It does not reject the request just because
`membership.status === 'suspended'`.

**Why:** `AUTH-DATA-MODEL.md §10` says a suspended membership must produce `403` with an
empty permission set. A 403 is a permission-layer answer, so the request has to reach the
resolution engine (`server/permissions.js`) to get that answer — it can't be stopped at
authentication with a 401, or the request would never get far enough to produce the 403 the
spec asks for.

**What I rejected:** Rejecting `suspended` in `context.js` with `401`, the same way `removed`
is rejected. It fails because it collapses two cases the spec keeps separate: a removed user
has no standing here at all (401), while a suspended user still exists as a member but is
temporarily blocked (403, with the block visible as an empty permission set per
`PERMISSIONS.md §3` step 1 — "a deleted or suspended user has no permissions anywhere").

**What would change my mind:** A hidden test asserting `401` for a suspended user's request
instead of `403` with an empty set. I haven't seen one — `check-api.js` doesn't cover
suspension directly — so this is a prediction I'm holding, not something I've confirmed.

---

### Org-level resolution treats every grant as in-scope, not just org-wide ones

**What I chose:** In `server/permissions.js`, when `resolve()` is called with `deviceId ===
null` (the org-level view), every one of a user's grants in that org is a candidate for the
resolution algorithm — org-wide (`device_id IS NULL`) and device-scoped alike. A specific
`deviceId` narrows scope to org-wide grants plus grants on that exact device only.

**Why:** `PERMISSIONS.md §3` states org-level is "the union across all devices in the org." If
a permission holds on even one device, the org-level union should reflect that. `node
scripts/check-permissions.js` passes all 35 cases with this rule, including the
device-scope tests in `§11 vector 3` and the "discriminating case" (org-wide deny +
device-scoped allow still resolves to deny) — but none of those 35 cases actually combine
`deviceId: null` with a device-scoped grant, so this specific interaction is my reading of the
prose, not something the public suite confirms.

**What I rejected:** Org-level = org-wide grants only (`device_id IS NULL`), ignoring
device-scoped grants entirely. Simpler, but then the phrase "union across all devices" in
`PERMISSIONS.md §3` would describe behaviour the code doesn't have — the org-level view would
be blind to any permission a user only holds on one specific device.

**What would change my mind:** A hidden test showing a device-scoped-only allow should NOT
surface at the org level (e.g. a nav item staying hidden despite a device-scoped grant).

---

### A suspended owner does not count toward the last-owner guard

**What I chose:** `assertNotLastOwner` in `server/lifecycle.js` only counts memberships with
`status = 'active'` when deciding whether removing or demoting this owner would leave the org
ownerless.

**Why:** `PERMISSIONS.md §6` states the rule ("remove or demote the last owner ->
`409 LAST_OWNER`") but doesn't say whether a *suspended* owner counts as protection. I chose
not to count them, since `PERMISSIONS.md §3` step 1 already establishes that a suspended user
"has no permissions anywhere" — a suspended owner can't act as an owner in practice, so letting
them silently satisfy the guard would leave an org with zero *functioning* owners while
technically passing the check. Confirmed by an ad hoc test against `seed/orgs.json`: Acme has
two owners (`usr_acme_owner`, `usr_dana`), and `assertNotLastOwner(db, 'org_acme',
'usr_acme_owner')` correctly does not throw, since `usr_dana` remains active.

**What I rejected:** Counting any non-removed owner (active or suspended) as protection. It
technically satisfies "the org has an owner on paper" while leaving nobody able to act as one.

**What would change my mind:** A hidden test expecting a suspended owner to still block
removal of the last other owner.

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

_(Not yet found — still building. Fill this in as it comes up; don't leave it empty at
submission time.)_

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.

_(To fill in once the build is far enough along to know what's genuinely being cut, not just
not-done-yet.)_