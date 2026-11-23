# What Lugh's dependants need of it (2026-11-20)

The maintainer, to the stack: "Every project that is a dependency should follow suite - confirm with their dependants that the
functionality they need is covered." Lugh asked Lir, Louhi, Mimir, Kvasir and Macha the same three questions (A: used today;
B: needed, per item, with the calls, the step it blocks, the test that proves it, what would not fit; C: constraints). Their
answers are recorded here, then reconciled into Lugh's items, which go back to each for confirmation before code.

## Answers

### Mimir (2026-11-20; Mimir's design, "Authentication", rulings 12, 13, 14, 18)

- A: nothing used. The plugin is Mimir's stage 6.
- B1, the status read (scope `lugh:principals.status`):
  - `GET /api/v1/principals/{id}/status` answers kind (user, app or group), enabled, and the version as an ETag; 404 when the
    principal is unknown.
  - lugh_client: `ApiClient` status(id, deadline, executor, done(Status{kind, enabled, etag} | not_found | error)).
  - The scope stays narrow, and the ETag is stable until the principal changes.
- B2, principal events over Lir:
  - `lugh/principals/<id>` on any change, carrying the version, idempotent on it, plus a heartbeat.
  - Mimir subscribes with `lugh:events.read`. With no heartbeat within a bound (30 s proposed) it refuses principals it has not
    rechecked; it never fails open.
- B3: its service principal by client credentials (`lugh:events.read`, `lugh:principals.status`), through TokenSource and
  discover.
- B4: AUTH needs nothing of Lugh by default (Mimir's own secrets, bound to a principal id). Optionally a Lugh access token as
  the AUTH password, verified in process with RelyingParty (audience, expiry, `mimir:connect`), never a network call per AUTH.
- B5: only a coarse scope, `mimir:connect`; Valkey ACL rules stay Mimir's.
- C: AUTH never blocks or waits on the network; about 10^4 principals, 10^4 connections a node, a few events a second.

### Kvasir (2026-11-20; Kvasir's design 346-365)

- A: nothing linked. It copies Lugh's back-off rules (5 failures a name, 20 an address, 1 s doubling to 15 min, forgotten
  after an hour) on Dannan's Backoff.
- B1, MySQL sign-in for Lugh principals:
  - An app password over caching_sha2_password's full path (in clear inside TLS), which Kvasir asks Lugh to verify, as an LDAP
    bind does: verify(principal, app_password, deadline, executor, done(Outcome{ok, principal_id, disabled, retry_after})).
  - A token in the same field is accepted too, if Lugh takes one there.
  - From any Kvasir node to any Lugh node.
  - Constant time for an absent principal; an outage refuses as unavailable, never 1045.
- B2, grants as Lugh scopes: `kvasir:<cluster>:<privilege>:<db>[.<table>]`, a proposal for the maintainer; database and table must be
  unambiguous.
- B3, principal events: each event carries the principal id and a monotonic version, so a node that missed one knows (gap
  reporting); sessions end on every node within 5 s.
- B4: RelyingParty if it holds B1's verify; TokenSource for its service credentials; built against lugh_client from an
  installed package with no fetch of Lugh's server.
- C: completions posted to Kvasir's executor, never inline; a 2 s budget with a hard deadline; Kvasir's back-off before Lugh
  is asked; scope lists bounded (1,000 scopes or 64 KiB asked).

### Louhi (2026-11-20; Lugh pinned at dbb0573)

- A: HttpsClient(io, ca_path) and Https::send; HttpsKeySource make, start, stop and status; Verifier and verify_access with
  AccessToken's subject, audiences, scopes, expires, jkt and x5t; OAuthClient with client_credentials, device_authorization,
  device_tokens and refresh; Endpoints::from_discovery; ClientIdentity; TokenSet; DeviceAuthorization; testing's jwks and
  sign_access_token. Services: discovery, JWKS, the token endpoint (client credentials, device flow, refresh).
- B: the shapes sent are right. RelyingParty with status() and cnf; TokenSource's current() thread-safe (it is: a lock).
  Two changes taken: FakeHttps made thread-safe (louhi-ctl's tests answer from the test thread), and bearer_token's bound
  16 KiB, Louhi's, provided Lugh's tokens never exceed it (item 8). Plain http:// not needed.
- C: called from io threads on strands and from louhi-ctl's main thread on futures; 30 s a step.

### Macha (2026-11-20; for P13, after its 0.95.1 cutover)

- A: its own users (scrypt per record, five additive roles, `credential_generation` cutting off sessions cluster-wide,
  tombstones for ever, root and anonymous), and sessions (32-byte bearer tokens, 30 days, gossiped), `POST /api/v1/session`.
- B:
  1. Bearer tokens verified offline on every request, through RelyingParty; never introspection per request.
  2. Roles as claims, the five strings, with `expand_roles` applied consistently.
  3. Immediate invalidation: a password, role or delete change cuts off existing tokens cluster-wide without a network check
     per request (Lugh's equivalent of `credential_generation`, or a revocation list, replicated to Macha nodes).
  4. Anonymous access: an operator-editable visitor role set, and a way to refuse it.
  5. The web UI by the OIDC code flow with PKCE; the issuer reachable whatever node answers.
  6. Break-glass, as `macha-users` is (offline, node stopped).
  7. Migration: scrypt hashes imported with their N, r, p and salt, rehashed at first sign-in; usernames, Macha's id as an
     external id, roles and tombstones kept.
  8. The users API moves to Lugh; `/api/v1/session`'s shape is for the maintainer.
- C: validation on worker lanes, never the reactor, no I/O on the request path; password work capped and refused, not
  queued; up to 4096 users; a Macha-only node verifies with public keys only.

### Lir (2026-11-20; lir TODO/2026-11-20-requirements.md, "To Lugh")

- A: the Verifier and AccessToken, HttpsKeySource (make, Settings, IssuerStatus, status), HttpsClient; the rewrite adds
  TopicGrants.
- B: TopicGrants as agreed (parse in lugh_client, the checks in lugh::client_topics on lir::mqtt). Of the relying-party
  pieces only the verifier, the key source and FakeHttps (Lir verifies, never obtains tokens). Principal events: Lugh is an
  ordinary lir::client, with a client identity granting `lir:pub` (and `lir:retain` if events are retained) on Lugh's
  topics and a client id unique per Lugh node. QoS 1 needs Dagda's log under Lir; until then Lir's rewrite states Maximum
  QoS 0, so the publisher runs against the standing cluster's old Lir until Lir says QoS 1 is live. Lugh's events are
  retained per principal, so a late subscriber reads each principal's latest version, and a lost QoS 0 event shows as a gap
  at the next one.
- C: verification from memory on the connection's strand; key fetches ahead of time, off it.

### Confirmations

- Mimir (2026-11-20): all five shapes; yes to the principal's version in tokens; a gap or a missed heartbeat makes it recheck
  through the status read.
- Macha (2026-11-20): confirmed; the version floor must hold across a partition (a cut-off node keeps its last floor and
  keeps serving); its break-glass stays local (macha-users), since no Lugh token can be issued with every Lugh node down;
  signed playback and artwork URLs stay Macha's.
- Kvasir (2026-11-20): confirmed. It asked that an app password never parse as a JWS; Lugh first agreed, then withdrew it
  on the maintainer's word: "No arbitrary special sauce. Passwords must be as used by global standards, and can certainly contain
  dots." Lugh promises nothing about a password's characters. Kvasir's plugin tries a token when the field parses as a
  JWS and, if it is not a valid token, the same field as an app password.
- Louhi (2026-11-20): confirmed, with FakeHttps thread-safe and the 16 KiB bearer bound (both done).
- Dannan (2026-11-20): one Fault enum for the stack (adds `unavailable` and `timed_out`, both 503 in Lugh's API) and the keyed
  map (full buckets dropped first, then least recently touched), agreed.

## Lugh's items, reconciled (confirmed unless marked)

1. **The status read.** A route `GET /api/v1/principals/{id}/status` under the new scope `lugh:principals.status`, and
   `ApiClient::principal_status`. Mimir and Kvasir.
2. **Principal events over Lir.** Lugh publishes `lugh/principals/<id>` with the principal's version on every change, plus a
   heartbeat, through `lir::client` (`2026-11-15-principal-events.md`). Missed events are detected by the version. Lugh's
   publisher becomes Lir's first in-stack client. Mimir and Kvasir; Louhi likely.
3. **App-password verification over the network.** An API route a service principal calls (a new scope, say
   `lugh:credentials.verify`), and `ApiClient::verify_app_password`. The constant work and the decoy are Lugh's
   (`Passwords::spend`); Lugh's own back-off applies beside the caller's. Kvasir.
4. **Reaching any Lugh node.** `ApiClient` and TokenSource fail over across the issuers or base URLs they are given, each
   name resolved by the system's resolver (the maintainer, 2026-11-23: Dannan's DNS responder, stack item 25, is dropped,
   and no project depends on Manannan for DNS; a resolver in Dannan only if that is ever simpler). How an issuer's name
   reaches a healthy node is the operator's DNS. Mimir, Kvasir, Louhi.
5. **Application scopes.** `mimir:connect` and Kvasir's `kvasir:` grammar are application scopes Lugh already grants as opaque
   words (RFC 6749 characters, at most `kMostScopeBytes`). Kvasir's grammar needs quoting for a '.' in a name; that is
   Kvasir's, for the maintainer.
6. **The relying-party pieces** (RelyingParty, bearer_token, discover, TokenSource, FakeHttps): built on
   `feature/client-relying-party`. Mimir, Kvasir, Louhi.
8. **A bound on an issued access token**: Lugh's issuer refuses to issue an access token longer than 16 KiB less
   "Bearer ", so every relying party's `bearer_token` takes it. Louhi.
9. **Revocation reaching relying parties without a network check per request.** Today a token is honoured until its exp
   (the Verifier's stated limit). Macha needs a disable, password or role change to cut off existing tokens cluster-wide.
   The principal events (item 2) carry the version; lugh_client keeps, per principal, the version below which tokens are
   refused (a token carrying its principal's version as a claim), fed by the events and the status read. Macha, Mimir,
   Kvasir. A design for the maintainer: short token lives alone would bound it, but not to Macha's "immediate".
10. **Roles as claims** for Macha: Macha's five roles as application scopes (`macha:<role>`), with the expansion applied
    by Macha. **Anonymous**: an operator-editable visitor scope set, Macha's to refuse. **Import**: scrypt hashes with their
    parameters, rehashed at first sign-in; Macha's id kept as an external id; tombstones kept. **Break-glass**: Lugh's own
    (P13 already plans one per service). Macha, P13.
7. **lugh_client from an installed package** with no fetch of the node: today lugh_client is consumed by FetchContent with
   `LUGH_BUILD_NODE=OFF`. An installed package (`find_package(lugh)` exporting `lugh::client`) is asked by Kvasir.

## The shared admin UI (settled 2026-11-20)

The maintainer told Lir, Louhi, Mimir and Kvasir to give each an optional React status and admin dashboard whose "styling and
structure should be taken from Lugh's admin interface", signing in by username and password or by Lugh. One copy:
`lugh/ui`, package `@lugh/admin-ui`, carved from `dashboard/` (the styles, AdminLayout, NavBar, Messages, Confirm,
useAPI, useLoad, useAct, format, and a sign-in screen with both methods, Lugh's by the OIDC code flow with PKCE). Lugh's
dashboard consumes it first as an npm workspace; the four fetch Lugh's repository at a tag and depend on it by file path.
No registry, no publishing (a registry is the maintainer's call). After P8.0 and the client work; each consumer names its screens.
The dashboard's tests stay Vitest (the maintainer, 2026-11-20); whether its 5 Playwright tests move into Vitest's browser mode is
asked of the maintainer.
Components asked of the package (2026-11-20): Lir and Mimir both, so carried: a data table paged by an opaque cursor (and by
page), sortable and filterable; a detail panel of labelled fields with copy-to-clipboard; `useEvents(url)` over SSE with a
reconnecting back-off. Lir alone (its own unless another asks): a payload viewer. Mimir alone: a number tile with a sparkline,
a monospace editor. Louhi: the same base set, `useAPI` with a base path, and a status pill coloured from a map the service
gives (Mimir's badge too, so carried); a read-only JSON view (Louhi alone). Kvasir: the base set and the cursor table, nothing
of its own beyond its screens.

## Releases (the maintainer to the stack, 2026-11-20)

"When you have completed all current tasks, you may cut versions by rationalising docs - README should always be focused on
installation and use - creating deb packages, running full tests including sanitation and fuzzing, and tagging and merging to
main, pushing. You must maintain a release badge." For Lugh's first release: the README made about installing and using
Lugh; Debian packages (Lugh has none yet; Dannan's `debian/` is the model); debug, ASan and TSan, and the fuzz campaigns on
the instrumented build; tag `x.y.z` on `main`; a release badge. The maintainer, 2026-11-20: `main` reset to `develop`; Raven, Alpine and
OpenRC are purged.
