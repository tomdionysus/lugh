# Contributing to Lugh

## Read first

`TODO/ACTIVE.md` is the plan and `TODO/COMPLETED.md` is the record. Lugh is the
directory of a stack of three projects with one set of conventions: Dannan the
network layer (`../dannan`), Dagda the store (`../dagda`) and Lugh the directory
(`../lugh`). `../dagda/TODO/2026-11-03-stack.md` says what each owns. Dagda and
Lugh use Dannan as their network layer, Lugh uses Dagda as its datastore, and
no code is duplicated between the three (the maintainer, 2026-11-03). Until Dagda carries
Lugh's spaces, Lugh keeps its sealed store and keyring, frozen ("Keep the store
until Dagda"); they are deleted then.

`docs/architecture.md` says what Lugh is: users, groups, sign-in and the
second factor, OAuth 2 and OIDC, LDAP, and the API and dashboard that manage
them.

## Branches

- `main` is the last stable state. Nothing is committed to it directly; stable
  states reach it by merging `develop`.
- `develop` is where work happens.
- Work that needs isolation branches off `develop` as `feature/<short-name>` and
  merges back into `develop`.

## Tags and releases

- Tags are exactly `x.y.z` semver: annotated, no `v` prefix, no suffix, cut from
  `main`.
- The tag, the CMake `project(... VERSION ...)` and `--version` are the same
  number.

## Commits

- Subjects are short imperative prose. No emoji, no ticket prefixes.
- Keep unrelated changes in separate commits: a move, a rename, a fix and a feature
  are four commits. A commit that moves files does not change their content.
- A commit message ends with its last line of prose. No tool attribution trailers.

## Building and testing

```
cmake --preset debug && cmake --build build -j8
./build/lugh_tests
ctest --test-dir build
```

Lugh keeps CMake presets, the stack's one exception (the maintainer, 2026-11-04: "because
of auth"): `debug` (into `build/`), `release`, `asan`, `tsan` and `fuzz`, each into
`build-<preset>/` except `debug`. They carry the MacPorts paths.

Dannan is fetched from `../dannan` at the release tag `LUGH_DANNAN_TAG` names
(0.2.0), into the build tree, and linked as `dannan::dannan`; building Lugh never
touches the sibling checkout.

Run `lugh_tests` for the unit suite. `ctest` runs it too, beside what only a
whole process shows: the shutdown, `init` and API tests in `test/process/`,
which drive the real `lugh-node`. Everything runs on a
developer machine (MacPorts for every dependency on the laptop); there is no
hosted CI. `-DLUGH_BUILD_FUZZING=ON` builds the fuzz targets under a clang that
has libFuzzer.

Sanitizers run routinely in Lugh: every phase ends with `lugh_tests` and
`ctest` passing under AddressSanitizer with UndefinedBehaviorSanitizer
(`--preset asan`) and ThreadSanitizer (`--preset tsan`), both of which
instrument Dannan too.
This is Lugh's one stated exception to the stack's rule of sanitizers before a
release: Lugh holds every credential (the maintainer, 2026-11-04). Under ASan the test
binary turns off container-overflow detection (`lugh/test/sanitizer_options.cpp`):
GoogleTest from MacPorts is not instrumented, and where its copy of libc++'s
container code meets the instrumented one ASan reports an overflow that is not
one.

Tests write only inside the build tree: Dannan's `TempDir` (`build/test-tmp`),
and `TMPDIR` there for the process tests. Time is stepped (Dannan's
`SteppedTime` and `SteppedWall`), never slept. Cryptography Lugh owns is tested
against the published vectors (RFC 4226 and RFC 6238 for TOTP, RFC 4648 for
base32 and base64url); Dannan tests its own primitives against theirs.

Write tests from the design, the RFCs and `docs/architecture.md`, not from the
current behaviour.

## Dependencies

Dannan, Boost (Asio, Beast, JSON), OpenSSL 3 (the one Dannan links: one process,
one OpenSSL) and yaml-cpp, plus GoogleTest for the test build. Prefer writing
something by hand over adding a library, and say so if a dependency really is
the right call.

## Layout

One layout for all three projects (the maintainer, 2026-11-03: "identical styles,
conventions, and layouts"). For a project `<p>` (`dannan`, `dagda`, `lugh`):

```
CMakeLists.txt               the project, options <P>_BUILD_TESTING,
                             <P>_BUILD_FUZZING, <P>_WARNINGS_AS_ERRORS;
                             no presets
<p>/CMakeLists.txt           the library target <p>
<p>/include/<p>/             the public headers a consumer includes as
                             "<p>/x.h"
<p>/<subsystem>/x.h, x.cpp   everything else, header and source side by side,
                             included as "<p>/<subsystem>/x.h"
<p>/contract/                interfaces with declared waits and thread safety
<p>/test/                    GoogleTest: <subsystem>_<thing>_test.cpp, flat,
                             one binary <p>_tests; fixtures in
                             <p>/test/fixtures/ (header-only)
<p>/fuzz/                    libFuzzer targets, <format>_fuzz.cpp, one per
                             parser of untrusted bytes, built only with
                             <P>_BUILD_FUZZING and clang
tools/                       executables, <p>_<tool>.cpp building <p>-<tool>
test/compose/                multi-node beds (Docker), run by hand
docs/                        how it works
TODO/ACTIVE.md, COMPLETED.md the plan and the record
CLAUDE.md, CONTRIBUTING.md   the rules (CLAUDE.md is gitignored globally)
```

Lugh's own beside these: `test/process/`, the tests that drive the real
`lugh-node`; `config/`, the shipped configuration; `deploy/`, the systemd unit
and host preparation; and `CMakePresets.json`, which Dannan and Dagda do not have.

A file pair holds one component: a class and what serves only it. Names are
`snake_case` files, `PascalCase` types, `_member`s, namespaces
`<p>::<subsystem>`.

## Shared code

What more than one project needs lives once, in the lowest project that
needs it, and the others link it: Dannan's crypto primitives
(`identity/crypto.h`), `Secret` and secure memory (`identity/secure_memory.h`),
Argon2id, signing, durable files (`identity/durable_file.h`), the byte codec
(`net/codec.h`), the thread-safety contract and time sources (`contract/`),
logging (`status/log.h`) and the Status surface. A project that finds itself
writing something another has asks that project's session to add it there
instead. What only Lugh needs (TOTP, password policy, OAuth and OIDC, the HTTPS
server for now) stays Lugh's, and moves down if another project comes to need
it.

## Errors

An operation that could not happen throws (`std::invalid_argument` for a
caller's mistake, `std::runtime_error` or a named subclass such as
`net::DecodeError` for bytes or a system that refused). An operation that
happened returns its result, and one that happened on more than one node
returns its evidence (who answered, what failed and why), never a bare
boolean. A read that finds nothing succeeds with an empty value.

Lugh's `Result`, `Status` and `Outcome` returns are older than this rule and
move to it with the change to callback style. What a person or a client is told
is a different thing: the API's `Fault` maps each refusal to one status and one
message, and that stays.

## Secrets

- A secret is a `Secret` (Dannan's, with `text_secret` and `secret_text` in
  `lugh/core/secret.h` for what people type and read), never a `std::string`. It
  converts to nothing, so a log line, an error message or a JSON body cannot
  take one. Secrets compare with `==`, which is constant time.
- Key material and records holding secrets are `SecureBuffer`, made where they
  will live (`secure_random()`), never in ordinary memory and copied.
- Error messages carry paths and settings, never values: a refusal says what
  was wanted, not what was given, where what was given might be a credential.
- Core dumps and debugger attachment are refused (`harden_process()` in `main`,
  and the unit).

## Inversion of control

- A component takes its collaborators in its constructor, the node's `LogSink`
  and Dannan's time sources among them. No singletons, no service locator.
- One composition root, `tools/lugh_node.cpp`, names the concrete
  implementations and touches the process. The IoC check
  (`lugh/test/node_ioc_check_test.cpp`, in `lugh_tests`) fails if anything else
  names a clock, the environment, a thread, a process, a file write, a concrete
  sink or adapter, or a lock that is not Dannan's.

## Style

- Formatting is `.clang-format` (Google base, 160 columns): run `clang-format -i`
  on the files you changed. Two-space indent, `#pragma once`, braces on the same
  line, headers `.h`.
- `snake_case` for functions, methods, variables and files; `PascalCase` for
  types; private and protected members prefixed with `_`. Namespaces are
  `<project>::<subsystem>`.
- Every source file starts with the Lugh header block (`CLAUDE.md` has it).
- No emoji anywhere.
- Dependency injection over globals; the only process global is the io context.
- Each component logs through its own scoped logger.
- Thread-safety annotations on every guarded member; contracts declare their waits
  and thread safety beside each operation.
- Comments are sparse and explain intent, not mechanics.

## Plan

`TODO/ACTIVE.md` is the plan and `TODO/COMPLETED.md` is the record. Move items
across as they land.
