# Principal events over Lir (design, 2026-11-15)

The maintainer, 2026-11-15: hosted systems should not poll Lugh to see credential changes; the stack has an event system. Asked by
Mimir (Redis AUTH on long-lived connections must drop when a principal is disabled) and Louhi (workload and operator
identities). Not scheduled; recommended below.

## The problem

A relying party that holds a long-lived connection or a cached identity learns of a change only when a token expires (5
minutes by default), by introspection, or by polling `/api/v1`. Lugh already knows every change that matters at the moment it
commits it, and records it in the audit log. Nothing tells anyone else.

## Shape

- **What**: one event per change to a principal's standing:
  - disabled, enabled, removed;
  - main password changed, factors reset;
  - an app password made or revoked;
  - group membership changed, scope grants changed;
  - for a client: disabled, secret rotated, removed.

  Plus one event per signing key published or retired, for the keys' audience.
- **Where**: published on Lir, on topics under a prefix Lugh owns: `lugh/principals/<principal id>` and `lugh/keys`. Ids are
  Lugh's immutable ids, percent-encoded as Dannan encodes topic segments.
- **Carries**:
  - `{principal, kind, version, at, node}`;
  - `kind` is one of the changes above;
  - `version` is the principal's record version, which only goes up;
  - `at` is the commit's wall time.

  Never a secret, a hash, a name or an address: the event says that something changed and which version is current, and a
  subscriber that needs more reads it through the API under its own scopes.
- **Who may read**: a Lugh scope, `lugh:events.read`, granted to a hosted system's service principal. It is checked by Lir
  through its Lugh plugin, as any topic subscription is (the topic-scope grammar, O2).
- **Source**: the audit log, as an outbox. Committed change, then audit entry, then publish, in the log's order. A cursor (the
  last entry published) is kept per node, so a restart or a Lir outage resumes from the cursor, and nothing committed goes
  unpublished. Delivery is at least once; subscribers are idempotent on `version`.
- **Subscribers' rule (the safety property)**: on an event, drop or recheck whatever was granted under an older version. On
  silence past a bound (the subscriber's, say a minute, with Lugh publishing a heartbeat on `lugh/heartbeat` every 10
  seconds), refuse principals not checked again through the API since the last heartbeat. A lost event or a dead feed can
  only refuse someone, never keep a disabled principal in.
- **Bootstrap**:
  - Lir authenticates its clients through Lugh, and Lugh publishes to Lir. Lugh connects to Lir as its own service
    principal, by mTLS or a token it issues itself.
  - Lugh never waits on Lir to serve: publishing is asynchronous from the outbox.
  - Lir down means events late, not sign-ins stopped.
- **Code**: `lugh/events/` in `lugh-node`, wired in the composition root; an MQTT client from Lir's library or Dannan's, to
  be decided with Lir. `lugh_client` stays without Lir (the maintainer, 2026-11-14); a subscriber helper, if any, lives in Lir's Lugh
  plugin or the consumer.

## Questions for the maintainer

1. When: recommended after P8.1 (the audit log as a node-local Dagda space, `lugh-node` a Dannan node), so the outbox is
   built once on the store it keeps. Before P8, it would be built on the sealed store and moved.
2. The MQTT client Lugh links (Lir's, or a small one in Dannan).
3. Whether hosted systems also want group events (a group's members changed) or only per-principal ones.

## Tests

From this document:
- Every change kind publishes once, after commit, in log order.
- A Lir outage then recovery publishes the gap and nothing twice past the cursor.
- A restart resumes from the cursor.
- Events carry no secret.
- The heartbeat's absence is visible to a subscriber.
- A process test on the real `lugh-node` against a Lir broker.
