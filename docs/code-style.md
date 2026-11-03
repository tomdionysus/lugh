# C++ code style

Lugh follows blackraven-admin (the maintainer, 2026-10-18): inversion of control, strong OO, the
AthenaSIP loggers, and whatever else in blackraven-admin, AthenaSIP, Macha or T.O.M.S is of
use. The maintainer owns the copyright on all four, so code is lifted freely and its licence headers
are stripped; what is lifted is restyled to this guide, never left in its source project's
style.

blackraven-admin's `docs/code-style.md` is the parent of this file. This file is those rules
as they apply here, the places this project deliberately differs, and the list of what is
lifted from where.

## The rules

- **Formatting**: `.clang-format` at the root, Google base, 160 columns, two-space indent,
  braces on the same line, `public:` indented one space. Run `clang-format -i` on the files
  you changed.
- **`#pragma once`**, never include guards.
- **Naming**: `PascalCase` types; `snake_case` functions, methods, variables and files;
  private and protected members and helpers prefixed `_` (`_logger`, `_handshake()`);
  constants `kName`; enumerators of an `enum class` lowercase (`Kind::web`). Setters put the
  verb last (`clock_set`, `middleware_add`).
- **Interfaces** are abstract classes named for the role, with no `I` prefix: `Logger`,
  `Clock`, `Random`, `Environment`, `Store`. An implementation is named for what it uses:
  `LoggerStdIO`, `SystemClock`, `SystemRandom`.
- **Namespaces**: `lugh::<subsystem>` (`loggers`, `system`, `network`, `http`, and then
  `oauth`, `api`, `ldap`, `authn`, `directory`, `tokens`, `audit`, `store`, `crypto`, `keys`,
  `cluster`). `Status`, `Result`, `Secret`, `Config` and `cli` sit in `lugh` itself.
  Anonymous namespaces for file-local helpers in `.cpp` files. **No `using namespace` in a
  header**, ever.
- **`lugh::http` is also Beast's vocabulary**: `http_types.h` brings `verb`, `status`,
  `field`, `error` and `to_string` into the namespace, so a route says `http::verb::get` and
  means ours and Beast's at once. Beast's other names stay spelled `beast::http::`.
- **Layout**: headers and sources side by side in `src/<subsystem>/`, one class per file
  pair, small classes header-only. Includes rooted at `src/` (`#include "http/router.h"`),
  never relative. The one `include/` directory, `include/lugh/`, is the client library's
  public face and arrives in P10; nothing of the service goes there.
- **Licence: GPLv3, as Dannan and Dagda** (the maintainer, 2026-11-03). `LICENSE` is the GPLv3 text.
  Every source file starts with this block, copied exactly (`#` in place of `//` in CMake,
  Python, shell and the unit file, after any `#!` line):

  ```
  //
  // Lugh - The Directory
  //
  // Copyright (C) 2026 Tom Cully <mail@tomcully.com>
  // Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
  //
  ```

  Code from a third party keeps its own notice.
- **Comments** are sparse, `//` only, and say why, not what. Match the density of the
  surrounding file. No Doxygen. No emoji, anywhere.

## Secrets

- **A secret is a `Secret`** (`core/secret.h`), never a `std::string`: a key, a password, a
  token, a client secret, a TOTP seed. `Secret` converts to nothing, so passing one to a
  log call, an error message or a JSON body does not compile. The bytes are reached by
  `reveal()`, spelled out at the call site, and only by the code that hashes, seals or
  compares them.
- **Comparisons of secrets are constant time**: `Secret::equals`, or `CRYPTO_memcmp` where
  the bytes are already out. Never `==` on the revealed strings.
- **Error messages carry paths and settings, never values**: "tls.key /x does not match"
  is fine; echoing what the caller sent is not. A refusal says what was wanted, not what
  was given, where what was given might be a credential.
- **Key material is `SecureBytes`** (`core/secure_bytes.h`), never a `std::vector` or a
  `std::string`: each block is pages of its own, locked into memory, kept out of core dumps
  on Linux and wiped when freed (`core/secure_memory.h`). `Secret` keeps its bytes the
  same way. A key is made where it will live: `Random::fill` into a `SecureBytes`, never
  `Random::bytes` and a copy.
- **OpenSSL's own secure heap is left off.** Its Argon2id takes the whole of its working
  memory from that heap once it exists, which would mean locking 64 MiB and more per hash.
  OpenSSL's private key numbers therefore sit in ordinary memory, wiped when freed.
- **Core dumps are off**, by `main` and by the unit.

## Inversion of control

- **Constructor injection.** A component takes its collaborators as
  `std::shared_ptr<Interface>` in its constructor and nothing else finds them. No
  singletons, no service locator, no function-static defaults.
- **One composition root**, `src/main.cpp`, hand-wired with `std::make_shared`. It is the
  only file that names a concrete implementation of a port, and the only one that touches
  the process (`setrlimit`, signals, threads).
- **Lifetimes**: `shared_ptr` with `enable_shared_from_this` for anything an async handler
  can outlive, capturing `self`; references only for what is guaranteed to outlive the
  borrower (an `io_context` owned by `main`).
- **Ports for everything outside the process**, each with a real adapter and a fake in
  `tests/`:

  | Port | Real | Fake | From |
  |---|---|---|---|
  | `loggers::Logger` | `LoggerStdIO`, `LoggerScoped` | `MockLogger` | blackraven-admin |
  | `system::Clock` | `SystemClock` | `ManualClock` | blackraven-admin |
  | `system::Random` | `SystemRandom` | `FixedRandom` | blackraven-admin |
  | `system::Environment` | `SystemEnvironment` | `MapEnvironment` | blackraven-admin |
  | `system::Files` | `SystemFiles` | `MemoryFiles` | new: the keyring and the store on disk; awaited |
  | `system::Console` | `SystemConsole` | `ScriptedConsole` | new: a passphrase typed without echo; awaited |
  | `store::Store` | `SealedStore` | `MemoryStore` | Macha's journal and packs, rewritten; the contract tests run against both |

  Nothing outside an adapter calls `std::getenv`, `std::chrono::system_clock`, `fork`/`exec`,
  `std::filesystem` writes, `RAND_bytes` or a socket it was not handed.
- **The IoC check**: a `ctest` that fails if a concrete adapter, a clock, `getenv`,
  `fork`/`exec`/`popen`, a thread, `RAND_bytes`, a `std::filesystem` write, a POSIX file
  call, a terminal call or the process's memory (`mlock`, `mmap`, `setrlimit`) is named
  outside `main.cpp` and the adapters (`scripts/ioc-check.py`). `core/secure_memory.cpp`
  counts as an adapter: it is the one place that locks memory.

## Errors

- **No exceptions across a component boundary.** Async and fallible operations answer
  `Status{ok, error}` or `Result<T>{ok, error, value}`; a parse that can fail answers
  `std::optional`. Whatever the API will turn into a status code answers
  `Outcome<T>{fault, message, value}` (`core/outcome.h`), whose `Fault` (`not_found`,
  `conflict`, `duplicate`, `invalid`, `refused`, `failed`) maps to one status each.
- **Exceptions only at startup** (bad config, a missing file, a port in use), caught in
  `main`, which logs and exits 1, and inside a parser or an OpenSSL wrapper, caught next to
  where they are thrown.
- **Async handlers are always posted, never called inline**, so a caller never re-enters
  itself.
- **Async all the way down.** Anything that waits, on a disk, a hash, a person or (from P8)
  the network, is a C++20 coroutine on Boost.Asio, `Task<T>` (`core/task.h`), and its
  caller `co_await`s it. Nothing holds a thread while it waits. That covers the store, the
  audit log, the directory, authn, the keyring, the files and console ports, and every
  route handler. What does not wait (the clock, randomness, the in-memory back-off, the
  record codecs, the cryptography short of Argon2id) stays a plain function.
- **What must block runs on a pool, awaited.** A regular file has no readiness to wait on,
  short of io_uring, and Argon2id is 64 MiB of work. `offload(executor, work)` runs it on a
  pool kept for it and resumes the caller on its own executor. There are two pools:
  `blocking` (files, the console), owned by `SystemFiles` and `SystemConsole` through
  `main`, and `hashing` (Argon2id), whose size bounds the memory sign-ins can take.
- **Never a `std::mutex` across a `co_await`.** State shared between coroutines is guarded
  by a `std::mutex` only for moments that await nothing; what must be held across a
  suspension (a table's write, the audit chain's next number, the keyring) is held with
  `AsyncMutex` (`core/async_mutex.h`), whose waiters hold no thread.
- **Arguments to a coroutine are owned**: `std::string`, not `std::string_view`; `Bytes` or
  `SecureBytes`, not a span; a `Secret` by value. A reference may outlive what it refers to
  across a suspension. A coroutine that steps a caller's state (a sign-in) takes it by
  value and hands back the next.
- **A forgotten `co_await` does not compile**: Asio's `awaitable` is `[[nodiscard]]`, and
  `-Werror` turns ignoring one into an error.
- **Route handlers are coroutines**, spawned by the router on the io_context once the
  credential, the limits and the scope have been checked in memory. At most 256 are in
  flight; past that a request is a `503 busy` with `Retry-After`, never a queue. A handler
  that throws is answered `500` once.
- One JSON error shape on the API, `{"error": {"code": "...", "message": "..."}}`
  (`http/api_json.h`). Codes are vocabulary and never change; messages are for a person.

## Logging

blackraven-admin's loggers, lifted as they are (`src/loggers/`):

- Every component wraps the injected logger in its own scope in its constructor:

  ```cpp
  HttpServer::HttpServer(std::shared_ptr<loggers::Logger> logger, ...)
      : _logger(std::make_shared<loggers::LoggerScoped>("http", std::move(logger))), ... {}
  ```

- Text to stderr for the journal by default; `log.format: json` for a shipper. `log.level`
  from config.
- The unscoped `LogLevel { DEBUG, INFO, WARN, ERROR }` is kept as it is, for compatibility
  with the lifted code. Nothing here may define a `DEBUG` or `ERROR` macro.
- What a scanner does (a failed TLS handshake, an unknown path) is logged at debug, so
  that a scanner cannot fill the journal. What a person does (a sign-in, an admin change)
  goes to the audit log (`audit/audit_log.h`), and is never only a log line. A component records
  its own changes, after making them; the audit log logs its own failures.

## Tests

- GoogleTest (1.17), one binary, `lugh_tests`, under `tests/` mirroring `src/`. Fakes in
  `tests/fakes/`, mocks in `tests/mocks/`, helpers in `tests/helpers/`, never in `src/`.
- Run the binary, not `ctest`, for the unit suite. `ctest` runs it plus the shutdown test,
  the IoC check and (under the `fuzz` preset) a short run of every fuzz target, and gates
  the install.
- A test that is not a coroutine runs one with `run(task)` (`tests/helpers/run.h`), on an
  io_context of its own; work handed to a pool (`tests/helpers/pools.h`, real threads) comes
  back to it. `tests/store/async_store_test.cpp` holds an append open and shows that
  nothing else waits for it.
- Route tests call the router's middleware directly with a request (`tests/helpers/route_call.h`,
  and `tests/helpers/api_rig.h` for the whole API over a `MemoryStore`). The API is also
  run end to end through the real binary by `tests/api_test.py`.
- HTTP tests start the real server on port 0, over TLS with a certificate made for the
  test (`tests/helpers/test_certificate.h`), and send real Beast requests. No certificate is
  ever committed: it would expire.
- Time through `ManualClock`, advanced by the test, never a real sleep.
- A test is written once, from what the behaviour must be (the RFCs, the architecture
  document), never from what the code happens to do, and with the cases that tell right
  from wrong.
- **Sanitisers run routinely here**, not only before a release: `--preset asan` and
  `--preset tsan` are part of finishing a phase. This differs from blackraven-admin
  deliberately, because Lugh is a security product.
- **Every parser Lugh owns gets a libFuzzer target** in `fuzz/`, built by the `fuzz` preset.
  The CLI parser was the first, then the keyring file, the table log's frames, and the
  directory's and authn's records with the text a person types (`fuzz/records_fuzz.cpp`); BER,
  JWT, JWKS, the OAuth form bodies and the LDAP filter grammar follow with the code that
  parses them.
- **Cryptography is tested against the published vectors**, not against itself: the GCM
  specification's AES-256 cases, RFC 5869 for HKDF, RFC 9106 for Argon2id, RFC 8032 for
  Ed25519, RFC 6979 for ES256, RFC 2202 and RFC 4231 for HMAC, RFC 4226 and RFC 6238 for
  TOTP, and RFC 4648 for base32 and base64url.

## Build

- CMake with the presets `debug`, `release`, `asan`, `tsan` and `fuzz`, a static library
  `lugh_core` from `src/` minus `main.cpp`, the executable, and the test binary behind
  `LUGH_BUILD_TESTING`.
- **Warnings are errors by default**: `-Wall -Wextra -Wpedantic -Werror`, plus Clang's
  `-Wthread-safety` as errors, as Macha has. `LUGH_WARNINGS_AS_ERRORS=OFF` is for getting a
  new compiler to build, not for leaving warnings in.
- **Hardening is on by default** (`LUGH_HARDEN`): `_FORTIFY_SOURCE=3` outside Debug,
  `_GLIBCXX_ASSERTIONS` and libc++'s fast hardening mode, `-fstack-protector-strong`,
  `-fstack-clash-protection` where the compiler has it, `-fcf-protection` on x86-64 and
  `-mbranch-protection=standard` on arm64, PIE everywhere, and `relro`, `now` and
  `noexecstack` on Linux. Each flag is probed under `-Werror` first, because Apple's clang
  accepts some and then warns that they did nothing.
- Sources listed explicitly, not globbed: a file added without a CMake edit should fail to
  link, not be found by accident.
- Precompiled headers for Asio, Beast and JSON.
- Boost 1.87 or newer (Beast, Asio and JSON, all header-only), yaml-cpp, OpenSSL 3,
  GoogleTest, Python 3 for the script tests. The targets are Ubuntu 26.04's apt (Boost 1.90,
  OpenSSL 3.5, GCC 15, CMake 4.2); development is on macOS with Homebrew.
- **Every dependency earns its place** (the maintainer, 2026-10-18). What blackraven-admin, AthenaSIP,
  Macha or T.O.M.S already use is approved, C++ and npm alike; anything else is asked for
  before it is added, never after. Prefer writing it by hand. In particular, no JWT, OAuth,
  LDAP or WebAuthn library: those parsers are the product, and they are fuzzed here.
- `cmake --install build-release` deploys, as blackraven-admin does: binary, config, docs,
  unit, host setup, restart. The dashboard joins in P7.
- The unit follows blackraven-admin's for hardening, and adds `StateDirectory`,
  `LimitCORE=0` and, from P2, `LoadCredentialEncrypted` for the master key.

## What is lifted, from where

### From blackraven-admin

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

### From AthenaSIP

| Source | Here | Change |
|---|---|---|
| `src/servers/tls_context.h` | `src/http/tls_context.{h,cpp}` | TLS 1.3 only, not 1.2 and up; `Result`, not a bool and a log line; the key is checked against the certificate at start |

### From Macha

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

### Written new

`core/secret.h`, the fuzz targets, and everything from P2 on that is not in a table above:
in P2, `core/secure_memory`, `core/secure_bytes.h`, `core/byte_io.h`, `crypto/`, `keys/`,
and the `Files` and `Console` ports; in P3, the `Store` interface, the table indexes and
`MemoryStore`; in P4, `audit/`, `directory/`, `authn/`, `crypto/hmac`, `core/encoding.h`
and `core/outcome.h`; in P5, `api/` (the routes in the shape of blackraven-admin's
`user_routes`), `authn/genesis`, `core/task.h` and `core/async_mutex.h`.
