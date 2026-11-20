# lugh_client for relying parties (after P8.0)

From the stack's placement plan (`../lir-develop-cluster/TODO/2026-11-20-cluster-stack-placement.md`, "Lugh" item 1, agreed
by every session 2026-11-20 under the maintainer's rule: what two or more projects need goes in the deepest shared dependency). Lugh is
the dependency Lir and Louhi share for sign-in, so the relying-party code each wrote for itself comes here. Test-first, after
P8.0; each consumer named its calls, below. Send Lir the header for review before the implementation, and each consumer the
commit to pin.

## The calls, as asked

Louhi (via the coordinator, 2026-11-20), replacing `louhi/auth/lugh.*`, discovery, `service_token` and `fake_https`:
- A relying-party class taking issuers, a CA path and an audience, returning a verified `AccessToken` with `cnf` (`jkt`,
  `x5t#S256`) exposed. Item 50.
- A bearer-extraction helper: the scheme case-insensitive, the value length-bounded. Item 50.
- `discover(issuer)` to the endpoints. Item 53.
- A client-credentials token source: `private_key_jwt` or `client_secret_basic`, with scopes; failover across issuers;
  cached; refreshed at two thirds of its life; a never-parking back-off (Dannan's `Retry`, its unbounded form when it lands);
  `current()` answers the token; `start` and `stop`. Item S10. The failover is also the no-special-node goal: no one Lugh
  node is the issuer a service depends on.
- `testing.h`'s fake HTTPS issuer, holding requests until the test answers. Item 54; it exists, used as is.
- Contingency: if the maintainer answers no to Q1 (an HTTP core in Dannan), `HttpsClient` takes plain `http://` too, which Louhi's API
  allows (the maintainer, 2026-11-15). If yes, not needed.

Lir (2026-11-20), item L3, the topic-scope grammar, the maintainer's of 2026-11-04: `lir:` (`pub` | `sub` | `retain`) `:` a
percent-encoded MQTT filter, each level decoded on its own, a level exactly `{sub}` being the token's subject.
- Parse: from scope strings and a subject (empty for none), the pub, sub and retain filters, and the `lir:` scopes refused,
  each with why; other applications' scopes skipped silently. Pure: no network, issuer or key source, since Lir also parses
  its own configuration for anonymous clients.
- Check, from memory, never waiting: may the set publish to a topic (retain or not; retain does not imply pub); may it
  subscribe to a filter as sent (`$share/<group>/` stripped, then a granted filter must cover the asked one).
- The verifier unchanged: JWS, key by `kid`, `typ`, `iss`, `nbf`, `exp`; subject, audiences, scopes, `exp`, `cnf`.
- `lugh-node` uses the same parser (`lugh/scopes/topic_scope.*` moves into `lugh_client`), so there is one grammar.
Lir's old parser (lir develop 92ab3a0, `lir/auth/scopes.{h,cpp}`) shows what it did; it is not a design to copy.

## Beside it, onto Dannan's as each lands (plan item 2)

hex, percent-encoding, the key source's back-off, the rate limiter onto Dannan's keyed bucket map, `recording_sink`, `Cidr`
onto `Prefix`, base64 and base32 onto `dannan/encoding/`, `Files` fsync onto the durable primitives, `on_pool` onto
`WorkerPool` (P8.1), the credential helper, health through Dannan's `Readiness` with overload. `merge::winner` onto Dagda's
register map D6 when it ships (`UniqueIndex` stays). Waiting on the maintainer: Q1, whether the HTTP core moves to Dannan, seeded from
Lugh's server.
