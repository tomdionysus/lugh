# P7: the dashboard

The design is `docs/architecture.md`, "Frontend (`dashboard/`)" and "HTTP surface": React 19, React Router 7 in SPA mode, Vite 7,
TypeScript 5.9, laid out like blackraven-admin's `dashboard/app/`, in T.O.M.S's look; same-origin, the Lugh session cookie and its
CSRF token, no token in the browser; served from disk by `static.directory`. Tests: GoogleTest for the server side, Vitest for
components and `lib/API.ts`, Playwright against a real `lugh-node`. Node on node-b (the maintainer, 2026-11-15).

## the maintainer's rulings (2026-11-16)

- **phr on the server, for administration.** A caller through a session below `phr` gets `403 phr_required` on every scoped
  route (directory, credentials, policies, apps, keys, audit, sessions); `/api/v1/me/*` stays open at `mfa`, so a person can add
  their first passkey from the dashboard. The dashboard offers the step-up (`/signin` asking for `phr`). Bearer and DPoP tokens are
  unchanged.
- **Root's first sign-in offers both** a passkey and TOTP. With TOTP, root adds a passkey through `/api/v1/me/factors` before
  administering.

## Steps

| ID | Step | State |
|---|---|---|
| D1 | `http::Caller` says whether it came through a session; the router refuses a scoped route to a session below `phr` with `403 phr_required`. Tests that administer through a session sign in at `phr` | done |
| D2 | Root's first sign-in offers a passkey as well as TOTP, proved on the real binary | done |
| D3 | The static handler: `static.directory`, the SPA's `index.html` for a path that is not a file, reserved prefixes a JSON 404, no symlink, dot-file or path outside the directory, fingerprinted assets cached, a CSP of its own | done |
| D4 | `dashboard/`: the scaffold, `app.css` tokens, `lib/API.ts` (the session's CSRF token, the one error shape, ETags), the layout, sign-in and step-up | done |
| D5 | Screens: me (factors with passkeys, sessions, password, app passwords), users, groups (members, scopes), policies, applications, keys, the audit log | done, first cut |
| D6 | `cmake --install` copies `dashboard/build/client` to `/usr/local/share/lugh/dashboard`, refusing a missing build | done |
| D7 | Node on node-b; Vitest; Playwright on the real `lugh-node` | done: Node 20.19 on node-b, Vitest 15, Playwright 5 on the real node |

## As built, and left open

- `continue=dashboard` is the sign-in's way back to `/` (a fixed word, never a URL), and `acr=urn:lugh:acr:phr` with it is the
  step-up. The TOTP setup's answer carries its QR modules, which the dashboard draws, so the encoder is the server's alone.
- A page's CSP allows its inline scripts by hash, since React Router's SPA page carries one. The maintainer confirmed it (2026-11-16).
- An app password with any scope beyond `lugh:directory.read`, made through a session, needs the session at `phr`, since it
  administers over LDAP where the router's gate does not reach (the maintainer, 2026-11-16). Done.
- Left for later: editing an application's every field (the API takes them; the screen registers and manages the common ones),
  the wordmark's display face, and a dark-only check of contrast.
