# Provenance

What Lugh's code was lifted from, and how it changed on the way in, as recorded at
the time (2026-10, phases P1 to P5). The paths are those of the layout then
(`src/`, `tests/`, `scripts/`); the move to the stack's layout (2026-11-03) put
them under `lugh/<subsystem>/`, `lugh/test/` and `tools/`. Since then, aligning
with Dannan has replaced several lifted pieces outright: the loggers, the clock
and random ports, secure memory, the byte codec, HKDF, AES-GCM, `Secret` and the
durable file write are Dannan's, and Lugh's copies are deleted
(`TODO/COMPLETED.md`, "Aligning with Dannan and Dagda"). The sealed store and
keyring are frozen until Dagda carries Lugh's spaces.


## From blackraven-admin

| Source | Here | Change |
|---|---|---|
| `src/loggers/*` | `src/loggers/` | namespace |
| `src/core/status.h` | `src/core/status.h` | namespace |
| `src/system/{clock,random,environment}.h` and adapters | `src/system/` | namespace |
| `src/network/cidr.{h,cpp}` | `src/network/cidr.{h,cpp}` | namespace |
| `src/api/http_server.{h,cpp}` | `src/http/http_server.{h,cpp}` | over `ssl_stream`, TLS 1.3 only; a handshake timeout; the security headers on every response; `Server: Lugh` |
| `src/api/router.{h,cpp}` | `src/http/router.{h,cpp}` | scopes in place of roles; a synchronous `CallerResolver` in place of the asynchronous authenticator, because every credential Lugh takes is checked in memory |
| `src/auth/caller.h` | `src/http/caller.h` | scopes, not roles |
| `src/api/rate_limiter.h` | `src/http/rate_limiter.h` | the `open` and `caller` policies |
| `src/api/client_address.{h,cpp}` | `src/http/client_address.{h,cpp}` | inverted: no proxy is trusted unless named; CloudFront's header is gone |
| `src/api/api_json.h` | `src/http/api_json.h` | namespace; `uint_field` dropped until wanted |
| `src/api/health_routes.{h,cpp}` | `src/http/health_routes.{h,cpp}` | says ok and nothing else: no version, no uptime; `/ready` added |
| `src/config.{h,cpp}`, `src/cli.h` | `src/config.{h,cpp}`, `src/cli.h` | the settings; the TLS pair is required |
| `src/main.cpp` | `src/main.cpp` | no account commands; refuses core dumps |
| `scripts/ioc-check.py` | `scripts/ioc-check.py` | adapter list |
| `tests/shutdown_test.py` | `tests/shutdown_test.py` | makes a certificate; speaks TLS |
| `tests/fakes/*`, `tests/mocks/*`, `tests/helpers/*` | `tests/` | namespace; `test_certificate.h` is new |
| `CMakeLists.txt`, `CMakePresets.json`, `.clang-format`, `.gitignore` | root | hardening, `-Werror` on, the `fuzz` preset |
| `deploy/*.service`, `deploy/host-setup.sh` | `deploy/` | names; `StateDirectory`; the TLS directory; no Redis |

## From AthenaSIP

| Source | Here | Change |
|---|---|---|
| `src/servers/tls_context.h` | `src/http/tls_context.{h,cpp}`, deleted 2026-11-15 | TLS 1.3 only, not 1.2 and up; `Result`, not a bool and a log line; the key is checked against the certificate at start. Replaced by Dannan's `listen::Certificates`, which checks the pair at load and on reload |

## From Macha

| Source | Here | Change |
|---|---|---|
| `src/storage/sealed_journal.{hpp,cpp}` | `src/store/log_format.{h,cpp}`, `src/store/sealed_store.cpp` | the frame (length, nonce, tag, AES-GCM), fsync per append, replay that cuts at the first frame that will not open; now with a checked frame header, the data key's epoch, a sealed file header, frames chained by tag, and `Status`, not exceptions |
| `src/storage/local_store.cpp`, pack recovery (`rebuild_pack_index`, `find_next_pack_header`) | `scan_log` in `src/store/log_format.cpp` | a torn tail told from damage by whether a valid header follows; damage now stops the open instead of being skipped, because a skipped record might be a revocation |
| `src/storage/local_store.cpp`, `compact_packs_locked` | `SealedStore::_compact` | rewrite the live records to a new file, sync, rename over; now one file per table, and every record sealed again under the current data key |
| `src/durable_file.cpp` | `SystemFiles::write` (P2) | temporary, fsync, rename, directory fsync |

Not lifted, deliberately (2026-10-18): the rest of `LocalStore` (loose object files, the
presence index, space accounting, the durability domain) and the ledger
(`src/ledger/`: the held ledger and its object trie, retention, availability). They serve
content-addressed objects placed on some nodes by a DHT: the ledger records which objects
a node holds, so a restart need not walk its disk. Lugh keys mutable records by table key
and holds every one on every node, so a table's log is itself the record of what is held.
P8 lifts the commit DAG and merge, which is the part of Macha's metadata Lugh does need.

## Written new

`core/secret.h`, the fuzz targets, and everything from P2 on that is not in a table above:
in P2, `core/secure_memory`, `core/secure_bytes.h`, `core/byte_io.h`, `crypto/`, `keys/`,
and the `Files` and `Console` ports; in P3, the `Store` interface, the table indexes and
`MemoryStore`; in P4, `audit/`, `directory/`, `authn/`, `crypto/hmac`, `core/encoding.h`
and `core/outcome.h`; in P5, `api/` (the routes in the shape of blackraven-admin's
`user_routes`), `authn/genesis`, `core/task.h` and `core/async_mutex.h`.
