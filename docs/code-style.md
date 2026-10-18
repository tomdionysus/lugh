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
- **Licence as T.O.M.S and blackraven-admin**: no licence file, no copyright or licence
  header on our own files, and `"private": true` in the dashboard's `package.json`. A file
  starts with `#pragma once` or its first include. AthenaSIP's GPLv3 header block and
  Macha's GPL-3.0-or-later block are removed from anything lifted from them. Code from a
  third party keeps its own notice.
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
- **Core dumps are off**, by `main` and by the unit, and the sealed store brings
  `mlock` and a wiping allocator in P2.

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
  | `system::WorkPool` (P4) | `ThreadWorkPool` | `InlineWorkPool` | blackraven-admin |
  | `store::Store` (P3) | the sealed table store | `MemoryStore` | Macha, rewritten |

  Nothing outside an adapter calls `std::getenv`, `std::chrono::system_clock`, `fork`/`exec`,
  `std::filesystem` writes, `RAND_bytes` or a socket it was not handed.
- **The IoC check**: a `ctest` that fails if a concrete adapter, a clock, `getenv`,
  `fork`/`exec`/`popen`, a thread, `RAND_bytes` or a `std::filesystem` write is named
  outside `main.cpp` and the adapters (`scripts/ioc-check.py`).

## Errors

- **No exceptions across a component boundary.** Async and fallible operations answer
  `Status{ok, error}` or `Result<T>{ok, error, value}`; a parse that can fail answers
  `std::optional`.
- **Exceptions only at startup** (bad config, a missing file, a port in use), caught in
  `main`, which logs and exits 1, and inside a parser or an OpenSSL wrapper, caught next to
  where they are thrown.
- **Async handlers are always posted, never called inline**, so a caller never re-enters
  itself.
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
  goes to the audit log, from P4, and is never only a log line.

## Tests

- GoogleTest (1.17), one binary, `lugh_tests`, under `tests/` mirroring `src/`. Fakes in
  `tests/fakes/`, mocks in `tests/mocks/`, helpers in `tests/helpers/`, never in `src/`.
- Run the binary, not `ctest`, for the unit suite. `ctest` runs it plus the shutdown test,
  the IoC check and (under the `fuzz` preset) a short run of every fuzz target, and gates
  the install.
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
  The CLI parser is the first; BER, JWT, JWKS, the OAuth form bodies, the LDAP filter grammar
  and the sealed record frames follow with the code that parses them.

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
| `src/api/router.{h,cpp}` | `src/http/router.{h,cpp}` | open routes only until the session model arrives; the authenticator and roles return with it |
| `src/api/rate_limiter.h` | `src/http/rate_limiter.h` | only the `open` policy for now |
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

Nothing yet. P3 lifts `src/storage/sealed_journal.*`, `src/storage/local_store.*` and the
ledger; P8 lifts membership and the metadata merge. Each goes in this table as it lands.

### Written new

`core/secret.h`, the fuzz targets, and everything from P2 on that is not in a table above.
