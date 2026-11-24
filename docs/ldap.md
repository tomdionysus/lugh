# LDAP

A second front end on the directory, exactly as `/api/v1` is the first, for software that speaks
LDAP and nothing else: mail servers, NAS boxes, VPN concentrators, Linux PAM and SSSD. It is
not a general-purpose LDAP server. The tree is fixed and generated, nothing is stored as an LDAP
entry, and there is no operator schema, no LDAP ACL and no replication over LDAP. The design and
why it is so are in `TODO/2026-11-04-ldap.md`.

## Turning it on

| Setting | Is |
|---|---|
| `ldap.listen.port` | LDAPS, usually 636. Left out, that listener is not there |
| `ldap.starttls.listen.port` | A plaintext port that does nothing but StartTLS and the rootDSE, usually 389. Left out, that listener is not there |
| `ldap.base_dn` | The top of the tree, such as `dc=example,dc=com`. Required for either |
| `ldap.most_pending` | Operations a connection may have queued before Lugh stops reading it. 8 by default |
| `ldap.idle` | Seconds a connection may do nothing. 600 by default, since SSSD and mail servers hold one open |
| `ldap.anonymous_bind` | Whether a bind with no name and no password succeeds. Off by default |
| `ldap.posix.uid_range`, `gid_range` | Where POSIX numbers come from, each `first-last`. Left out, nothing is numbered |
| `ldap.posix.primary_group` | The group whose number is every person's `gidNumber`. Required with the ranges |
| `ldap.posix.home`, `shell` | `homeDirectory`, with `{name}` for the user's, and `loginShell`: `/home/{name}` and `/bin/bash` by default. Neither is stored |

TLS is the HTTPS listener's certificate and TLS 1.3 only. A client that cannot do 1.3 goes through
stunnel or is replaced.

## The tree

```
<base>
  ou=people,<base>       uid=<name>,ou=people,<base>      persons
  ou=services,<base>     uid=<name>,ou=services,<base>    service users
  ou=groups,<base>       cn=<name>,ou=groups,<base>
```

| Entry | Object classes | Attributes |
|---|---|---|
| Person | `top`, `person`, `organizationalPerson`, `inetOrgPerson`, and `posixAccount` when numbered | `uid`; `cn` and `displayName`; `givenName`; `sn` (the display name whole until a family name is set); `mail`; `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`; `memberOf` |
| Service | As a person, less `posixAccount` | The same, less the POSIX ones |
| Group | `top`, `groupOfNames`, and `posixGroup` when numbered | `cn`; `description`; `member`; `gidNumber` |
| rootDSE | `top` | `namingContexts`, `supportedLDAPVersion`, `supportedControl`, `supportedExtension`, `vendorName`, `vendorVersion` |

Operational, so only when asked for by name or with `+`: `entryUUID`, `createTimestamp`,
`modifyTimestamp` and `lughEntryVersion`. `uid`, `cn`, `mail` and the rest match ignoring ASCII
case; `member` and `memberOf` match as DNs. `userPassword` is never there, in either direction.

**POSIX numbers.** A person or a group gets a number when made, once ranges are set, and it is never
given again, even after its holder is removed. A service gets none. What was made before the ranges
were set has no number and no `posixAccount` or `posixGroup` class, and a search never allocates one:
`POST /api/v1/ldap/posix/allocate` numbers them all, in creation order, in one audited pass, and can
be run again to finish one that stopped. A person's `gidNumber` is that of `primary_group`, so until
that group exists and has a number they have no `posixAccount`. A range used up refuses the
creation; a wider range goes on from where the counter is.

## Binding

Simple bind only, with a DN from the tree, over TLS only. SASL is `authMethodNotSupported`, and an
empty password `inappropriateAuthentication`. Every other refusal is `invalidCredentials` with the
same message, after the same work.

**Anonymous bind.** A stock client such as `ldapsearch -x` with no `-D` binds with no name and no
password before anything else, even to read the rootDSE, and stops when that is refused. Off by
default, it is refused, as `inappropriateAuthentication` over TLS and `confidentialityRequired` on
the plaintext port. With `ldap.anonymous_bind` on, that one form succeeds on either listener, since
it carries no credential, and leaves the connection anonymous: the rootDSE and nothing else, and on
a connection that was bound, the identity is gone. It is not audited, since it proves nobody. A name
with an empty password is never anonymous, whatever the setting.

- **A person whose policy is `pwd`** may bind with their main password. It goes through the sign-in's
  back-off, lockout and audit, and wrong guesses count at the sign-in pages too.
- **A person whose policy needs more, and every service,** binds with an app password
  (`/api/v1/me/app-passwords`, `/api/v1/users/{id}/app-passwords`). It carries its own scopes,
  read-only by default, cut at each operation to what its owner's groups grant then.

The identity is checked again at each operation, so a user disabled or removed, or an app password
revoked, stops a connection that is already bound.

## What a caller may do

Rights are Lugh's scopes, set in one place (`docs/api.md`).

| Operation | Needs |
|---|---|
| Bind, StartTLS, read the rootDSE, Who am I? | Nothing |
| Search and compare your own entry; search from the fixed containers | A bind |
| Search and compare anything else | `lugh:directory.read` |
| Add, modify, delete, rename | `lugh:directory.write` |
| Password Modify | A bind with your own main password |

What a caller may not read is not there: `noSuchObject`, or absent from the results, never
`insufficientAccessRights`, so the tree does not leak.

## Searching

Scopes `base`, `one` and `sub`. Filters are equality, presence, substring, `and`, `or` and `not`,
nested at most 16 deep. `approxMatch` is equality. `>=` and `<=` work on `uidNumber` and `gidNumber`
only. Anything else, extensible match among it, evaluates to Undefined, so it matches nothing and
is not an error. A comparison on an attribute the entry lacks is Undefined, and presence on one is
false, so `(!(mail=*))` finds those without one.

A filter that pins `uid`, `mail` or `entryUUID` by equality, alone or as one term of an `and`, goes
straight to that entry, as does `cn` under `ou=groups`. That is the shape of a PAM, SSSD or mail
lookup, and it opens one record. Anything else reads the whole directory once per search, which
is right for thousands of entries and wrong for millions.

A search answers at most 1000 entries, `sizeLimitExceeded` past that, and takes at most 30 seconds.
A client's own limits are honoured when they are lower. Paged results (RFC 2696) goes past the size
limit a page at a time, and a page token survives changes to the directory.

## Writing

| Operation | Does |
|---|---|
| Add | A person, a service or a group, under its container, with only the attributes below. A person starts not enrolled, and cannot bind until an administrator issues an enrolment link through the API; a service is enrolled at once and binds with an app password |
| Modify | A user's is one update, so it succeeds or fails entire. A group's changes its attributes or its `member` values, never both in one request |
| Delete | A user, with their memberships, password, factors and sessions, final as the API's is; or a group |
| ModifyDN | A rename under the same parent, with `deleteoldrdn` true. `newSuperior` is `unwillingToPerform` |

| Attribute | Write | Rule |
|---|---|---|
| `cn`, `displayName` | replace | One field; it cannot be deleted |
| `givenName`, `sn` | replace, delete | |
| `mail` | replace, delete | Unique; a person must keep one |
| `description` | replace, delete | On a group |
| `member` | add, delete, replace | Each value a DN in the tree, or nothing changes and the answer is `noSuchObject` |
| `userPassword` | never | `unwillingToPerform`: Password Modify is the only way |

Everything read-only (`memberOf`, `uidNumber`, `gidNumber`, `entryUUID`, the timestamps, the object
classes) answers `constraintViolation`, and an attribute the entry cannot have `noSuchAttribute`.

**The Assertion control** (RFC 4528) works on any write, with any filter. With
`(lughEntryVersion=<n>)` the write is also conditional on that version, as the API's `If-Match` is,
and a stale one is `assertionFailed`.

**Password Modify** (RFC 3062) changes the bound user's own password, after a bind with that
password, with the old one in the request and through the sign-in's back-off. Every session of
theirs ends. An app password can never change the main one, naming someone else is
`unwillingToPerform`, and Lugh will not make up a password for a client. An administrator sets
nobody's password, here or in the API: the enrolment link is the one way.

Writes, binds and password changes are audited in the same entries the API makes, with the bound
user as the actor and `ldap:<address>` as the source. A search is not.

## The connection

Operations on a connection are answered strictly in turn. Past `ldap.most_pending` queued, Lugh stops
reading, so a fast client is held back rather than refused. Abandon acts when it is read, and unbind
in its turn. Messages are capped at 64 KiB; one over the cap, or one that cannot be read, gets a
Notice of Disconnection and the connection closes.

Plaintext carries StartTLS and the rootDSE alone: anything else is `confidentialityRequired`. Bytes
that follow a StartTLS before the handshake end the connection rather than being acted on under TLS.
Requests are limited as HTTP's are, by address until bound and by caller after (`busy`). A critical
control Lugh does not do is `unavailableCriticalExtension`, and a non-critical one is ignored.

## Clients

Driven with OpenLDAP's tools, 2.6.13 directly and Apple's 2.4.28 through a proxy, since Apple's
cannot do TLS 1.3. To read the rootDSE, `ldapsearch -x` with no `-D` needs `ldap.anonymous_bind`.
OpenLDAP's library swaps the name `localhost` for the machine's hostname before checking the
certificate, so name the host the certificate names, or an address in its SAN. SSSD, PAM and mail
servers have not been tried.

## Not built

Operator schema or custom attributes, arbitrary DNs, `newSuperior`, aliases, referrals, LDAP ACLs,
SASL, server-side sort, VLV, persistent search, syncrepl, anonymous reads beyond the rootDSE, `userPassword` in either
direction, and writing `memberOf`, `uidNumber`, `gidNumber` or `objectClass`.
