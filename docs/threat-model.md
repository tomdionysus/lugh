# Threat model

What Lugh defends, from whom, and with what; and where it does not, said plainly. It describes Lugh as built (P1 to P11 and
P7), before the cluster moves onto Dagda (P8). Where a defence is a plan rather than code, it says so.

## What is worth taking

| Asset | Where it is | Why it matters |
|---|---|---|
| Signing keys | `signing_keys`, sealed | Whoever holds one mints tokens every relying party accepts, for anyone |
| The master key | A systemd credential (or a passphrase), never on disk in clear | It opens the keyring, which opens every table |
| Password hashes, TOTP secrets, WebAuthn public keys, recovery code hashes | `credentials`, `factors`, sealed | Offline guessing (hashes); minting codes (TOTP secrets); nothing on their own (public keys) |
| Sessions, refresh tokens, codes | `sessions`, `grants` (the handle's hash only) | Acting as a person until they expire or are revoked |
| Client secrets, app passwords | Argon2id hashes, sealed | Acting as an application, or binding LDAP as a person |
| The directory and its scopes | `users`, `groups`, grants | Who may do what in every hosted system |
| The audit log | `audit`, hash-chained | The record of what happened, and of who did it |

## Who might attack

- **Anyone on the network**: reaches the HTTPS listener, the LDAP listeners and, where it is exposed, the mTLS listener.
- **Someone with a stolen password**: a person's, or root's from genesis.
- **Someone with a stolen session cookie or token**: from a compromised browser, a relying party's logs, or a device.
- **A malicious or compromised relying party**: a registered application that wants more than it was given.
- **A malicious page in the person's browser**: another site, trying to act through the person's session.
- **An administrator acting beyond their role**, or one whose session is stolen.
- **Someone on the host**: another local user, a backup reader, a stolen disk. Root on the host is out of scope: it holds the
  credential and the process.
- **A node of the cluster** (from P8): within the trust boundary the maintainer accepted (2026-11-04); see "The cluster".

## Surfaces

### HTTPS (`lugh/http`)

- **Trusts**: nothing before a credential resolves. TLS 1.3 only, no plaintext listener.
- **Defences**: request size and time limits; a bounded number of requests in flight (`503 busy`); per-address limits on open
  routes and per-caller limits on authenticated ones; one JSON error shape that never carries a secret or what a caller typed;
  security headers on every page; the client address taken from `X-Forwarded-For` only through a proxy named in
  `proxy.trusted_networks`.
- **Fuzzed**: the API's request parsing (`fuzz_api_request`), forms (`fuzz_form`).

### The sign-in (`lugh/signin`, `lugh/authn`)

- **Against guessing**: Argon2id for every password, and the same cost for an unknown name, so timing tells nothing; back-off per
  account and per address (five and twenty free failures, then a wait doubling from a second to fifteen minutes), answered before
  any hashing, so a waiting guesser costs nothing. Refusals look the same whether the name, the password, the account's state or its
  enrolment was wrong; the audit log keeps the reason.
- **Against a stolen password**: a second factor is required by default (`mfa`); enrolment starts only from a link an
  administrator issued, so a password alone never enrols the thief's authenticator. Root's genesis password is shown once and
  works for one first sign-in, which goes straight to enrolment.
- **Against replay**: a TOTP code works once (the last step used is stored and compared under the record's version); a WebAuthn
  challenge is single-use, bound to the visitor or the session, and expires in five minutes; a sign count that goes backwards is
  refused.
- **Against phishing**: WebAuthn checks the origin and the RP ID (the issuer's host); a relayed ceremony fails. Where `phr` is
  required a code is refused.
- **Against forged forms**: every form carries a CSRF token derived from the visitor's cookie under a key of the process's own;
  pages allow only their own stylesheet and one first-party script.
- **Fuzzed**: `fuzz_records`, `fuzz_webauthn` (CBOR, COSE, attestation and assertion parsing).

### Sessions

- **The cookie** is `__Host-lugh_session`: Secure, HttpOnly, `SameSite=Lax`, host-only, `Path=/`; a 256-bit handle of which only the SHA-256 is
  stored, so the table holds nothing that works as a cookie.
- **Lifetime**: 24 hours idle, 30 days absolute; ended by sign-out, by the person ending it, by an administrator, by a password
  change (every other session), by a factor reset, and within a minute of the person being disabled, removed or losing a group.
- **A change through a session** carries the session's CSRF token; a read does not, and a cross-site page cannot read the answer.
- **A stolen session at `mfa`** may use the person's own routes and administer nothing (`phr_required`); changing a factor needs a
  factor proved within ten minutes; changing the password needs the current one, with the sign-in's back-off; an app password that
  may change anything needs `phr`.

### The management API (`lugh/api`)

- **Every route declares its scope** in the router, which checks it before the handler runs; a session administering must be at
  `phr`. A field a route does not know is refused, so a misspelling is never a silent no-op.
- **Writes carry `If-Match`**, so no administrator overwrites a change they have not seen.
- **Secrets leave once**: a client secret, an enrolment link, an app password, a TOTP secret, recovery codes. `Cache-Control:
  no-store` on every answer.
- **A reset** (all of someone's factors) needs the administrator at `phr`.

### OAuth 2 and OIDC (`lugh/oauth`)

- **Only registered applications**, only to redirect URIs they registered, matched exactly; an unknown client or URI is an error
  page on Lugh, never a redirect. No dynamic registration, no implicit grant, no password grant.
- **Codes**: PKCE (S256) required; a code lives 60 seconds and is redeemed once, only on the node that made it.
- **Refresh tokens** rotate, and reuse of an old one revokes the family; bound to the session they came from.
- **Sender constraint**: DPoP or mTLS where an application asks for it, so a stolen access token is useless elsewhere.
- **Confidential clients** authenticate with `private_key_jwt` or `tls_client_auth`; client secrets only where policy allows, as
  Argon2id hashes, rotated with a day's overlap.
- **Signing keys** rotate every 90 days, and are published an hour before they sign and two hours after they stop.
- **Back-channel logout** reaches every application a session signed into, over HTTPS whose certificate is always checked.
- **Fuzzed**: `fuzz_jws`, `fuzz_scope`, `fuzz_client` (the client library's parsing of what a server answers).

### LDAP (`lugh/ldap`)

- **TLS always**: LDAPS, or a plaintext port that does nothing but StartTLS and the rootDSE. Simple bind only, over TLS.
- **A person whose policy needs a second factor** binds with an app password, never their main password, since LDAP cannot ask for
  a second factor. An app password carries a subset of its owner's scopes and, optionally, the networks it may come from; one that
  may change anything is made only at `phr`.
- **Bounded**: the BER decoder's depth and sizes, filters' depth and size, searches' size and time, operations queued per
  connection, idle connections closed.
- **Revoking** an app password ends connections already bound with it.
- **Fuzzed**: `fuzz_ber`, `fuzz_filter`, `fuzz_dn`.

### The dashboard (`dashboard/`, `lugh/http/static_site`)

- **No token in the browser**: same-origin, the session cookie and its CSRF token.
- **Its files** are read once at start into memory; no request reaches the disk, and no path a request names is opened.
- **Its pages** run under `default-src 'self'`, scripts from this origin and the page's own inline script by its hash,
  `frame-ancestors 'none'`.
- **Administering** needs `phr`, enforced on the server, not the page.

### The store and the keyring (frozen until P8)

- **At rest**: every record sealed with AES-256-GCM under a per-table data key, bound to its table, epoch and position; the keyring
  sealed under a KEK derived from the master key; a copy of the state directory without the master key yields neither records nor
  hashes.
- **Integrity**: a damaged middle stops the open (a dropped record may be a revocation); a removed key is never written again.
- **In memory**: keys in locked pages, kept out of core dumps, wiped when freed.
- **Fuzzed**: `fuzz_keyring`, `fuzz_store_log`, `fuzz_envelope`.

### The host

- **The unit** runs as `lugh`, with `ProtectSystem=strict`, private `/tmp` and devices, no new privileges, a system call filter,
  only `CAP_NET_BIND_SERVICE`, `MemoryMax=256M`, `LimitCORE=0`, and the master key as an encrypted credential (to the TPM where there
  is one). The state directory is the one place it may write.
- **Not yet tried on Linux**: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` (P12, H3).

### The cluster (P8)

Within the boundary the maintainer accepted: a node of the cluster is trusted with what its domains hold. `lugh/secrets` lives on Lugh nodes
only. A partition loosens the back-off to at most N times its limit, never removes it. Single-use grants are redeemed only on the
node that issued them, and fail closed when it cannot be reached.

## Known gaps

| Gap | Effect | Where it is closed |
|---|---|---|
| The hashing queue is unbounded | A flood of sign-ins queues Argon2id work without limit (the back-off still answers waiting callers before any hashing) | P8.1, on Dannan's `WorkerPool` |
| Back-off and the re-authentication window are per node | Across a cluster a guesser gets N times the limit; a window opened on one node is not open on another (which fails closed) | P8, summed by gossip |
| The audit chain is tamper-evident, not tamper-proof | Someone with the master key and the disk can rewrite it from a point onwards; `/api/v1/audit/verify` finds a break, not a consistent rewrite | Shipping it off the node (not planned) |
| Notifying a person of a change to their factors | Not yet: a stolen session that proved a factor could change factors unseen until the audit log is read | Principal events over Lir |
| ASan has not run on P7 | The build nodes' 4K-page kernels stop ASan from starting; P7 is green in debug and TSan | node-b's 16K kernel, then a 4K kernel with 48-bit VA |
| No fuzz campaign has run yet | Every target is written; none has run for long | P12, H1 and H2 |
