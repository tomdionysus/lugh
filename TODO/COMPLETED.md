# Complete

What shipped, newest first, with the date and why.

## 2026-11-03: Aligning with Dannan and Dagda (feature/dannan-alignment, in progress)

The maintainer, 2026-11-03: Lugh uses Dannan as its network and Dagda as its datastore, no code is
duplicated between the three, and all three share one style, set of conventions and
layout. Kept until Dagda carries Lugh's spaces: the sealed store and keyring ("Keep the
store until Dagda"). The stack and its seams are in `../dagda/TODO/2026-11-03-stack.md`.

- The GPLv3 header block ("Lugh - The Directory") and `LICENSE`; Dannan linked, pinned to a
  commit of `feature/wire-v1` until a tag carries its Context; MacPorts for every dependency.
- Dannan's layout: `lugh/<subsystem>/`, `lugh/test/` flat, `lugh/fuzz/`, `tools/` (the service
  is `lugh-node`), `test/process/`, `TODO/COMPLETED.md`.
- From Dannan in place of Lugh's own: SHA-256, the constant-time compare and hex
  (`dannan/identity/crypto.h`), Argon2id and its ceiling on stored costs
  (`dannan/identity/argon2.h`, `Argon2Costs::valid()`), and signing
  (`dannan/identity/signing.h`; Lugh's copy deleted, it had no user yet).
- Finding: the unit count went from 389 to 373. The tests that went were of what Lugh no
  longer owns: its SHA-256, compare and signing copies, and the RFC 9106 Argon2id vectors,
  all tested in Dannan against the same published vectors.
- The wall clock and the steady time source are Dannan's (`dannan/contract/`), and the tests
  step Dannan's `SteppedTime` and `SteppedWall`.
- Secure memory, the record codec, HKDF and AES-256-GCM are Dannan's: `SecureBuffer` on
  Dannan's locked pages, every record and file format written with Dannan's `Writer` and
  read with its `Reader` (`lugh/core/codec.h` holds only `SecureWriter` and
  `decode_whole`), the keyring's KEK from `hkdf_sha256_secret`, and `crypto/aead` reduced to
  the sealed-value framing (nonce, ciphertext, tag) over `aes_gcm_seal` and
  `aes_gcm_open_secure`. The keyring and table log formats keep their bytes. The node
  hardens itself with `harden_process()`. Lugh's `core/byte_io.h`, `core/secure_memory`
  and `crypto/hkdf` are deleted.
- Finding: the unit count went from 373 to 353, all of it what Lugh no longer owns: its
  byte codec, secure memory and HKDF tests, the GCM known-answer vectors and the Argon2
  ceiling (each tested in Dannan), and the test that a broken random source seals nothing,
  since Dannan draws the nonce itself and Lugh cannot inject that failure any more.
- The warning that key material could not be locked into memory reads Dannan's
  process-wide count, `unlocked_secure_allocations()`, added at Lugh's request (Dannan
  6d173c1, which Lugh is now pinned to); the node also warns when `harden_process()` falls
  short.
- `Secret` is Dannan's: move-only, on locked pages, compared in constant time with `==`.
  `lugh/core/secret.h` keeps only the redaction text and the text on either side of a
  secret (`text_secret`, which wipes the string it is given, and `secret_text`). A secret
  read a character at a time is built in a `SecureBuffer` and handed over. Where a caller
  still needs a secret it passes on, the copy is written out at the call site.
- Finding: the unit count went from 353 to 351: the copy and growth tests of Lugh's
  `Secret`, which no longer exist to test.
- Randomness is Dannan's: `random_bytes` for what is not secret (ids, salts) and
  `Secret::random` for what is, through `secure_random()` in `lugh/core/secure_bytes.h`
  when it must land in a `SecureBuffer`. The `Random` port, `SystemRandom` and the test
  doubles `FixedRandom` and `CountingRandom` are deleted, as is the `random` argument of
  every constructor and of `hash_password`, `make_file_header` and `Keyring::rotate`. A
  failed generator throws: a route that meets one answers 500, and a start or `init` that
  meets one stops.
- Finding: the unit count went from 351 to 347. The four tests that went made the random
  source fail and saw a user, a factor, root's password or a keyring refused; with Dannan
  drawing the bytes, a test cannot make it fail. The tests that relied on two rigs drawing
  different bytes now draw from the real generator.
- Logging is Dannan's (`dannan/status/log.h`): the node has one `LogSink`, made in
  `tools/lugh_node.cpp` by `console_sink(format, level)` (text, or JSON lines through
  Dannan's `JsonSink`, added at Lugh's request), and each component takes the sink and
  scopes its own `ScopedLogger` ("store", "audit", "authn" and so on), as a Dannan component
  takes `Context::logger(scope)`. `log.level` and `log.format` are read with Dannan's
  `parse_log_level` and `parse_log_format`, so `all` is now a level. The tests record
  through `RecordingSink`. Lugh's `loggers/` (from blackraven-admin) is deleted, and the IoC
  check refuses a concrete sink outside the composition root. Dannan is pinned to ca8a565.
- Finding: the unit count went from 347 to 338: the tests of `LoggerScoped` and
  `LoggerStdIO`, whose behaviour is now Dannan's and tested there.
- Every lock is Dannan's (`dannan/contract/thread_safety.h`): `Mutex` under `Lock`, the
  state it guards `DANNAN_GUARDED_BY` it and a helper called with it held
  `DANNAN_REQUIRES` it, in the library and the test fixtures alike, so clang's analysis
  (`-Werror=thread-safety`) checks every access. A table's state lock in the sealed store
  is an `IoMutex`, since a record that does not open is logged with it held. Opening a
  table and loading its keys now take that lock around the state they touch, though
  nothing else can see the table yet, so the analysis can prove every access. The IoC
  check refuses a standard lock outside the composition root.
- The tests write only inside the build tree, as Dannan's do: `TempDirectory` is Dannan's
  `TempDir` (under `build/test-tmp`) with a `write()` helper, and ctest gives the process
  tests `TMPDIR` there. Before, both used the system temp directory.
- HMAC-SHA-256 is Dannan's, and Lugh had no caller of its own copy; HMAC-SHA-1, which only
  TOTP uses, moved into `authn/totp.cpp`. `crypto/hmac` is deleted. Finding: the unit count
  went from 338 to 335, the HMAC known-answer tests; HMAC-SHA-1 is still checked through
  RFC 4226's and RFC 6238's vectors.
- `CONTRIBUTING.md` from Dannan's, section for section, with Lugh's own rules on secrets
  and inversion of control beside them, and a local `CLAUDE.md` (gitignored, as Dannan's
  is) from Dannan's. `docs/code-style.md` is gone: its rules are in `CONTRIBUTING.md`, and
  its tables of what was lifted from where are `docs/provenance.md`. Following the rule
  The maintainer set for all the source repositories, sanitizers now run before a release rather
  than routinely, which `code-style.md` had made a deliberate Lugh exception.
- Dannan's warning set on every target: `-Wshadow -Wconversion -Wno-sign-conversion` beside
  `-Wall -Wextra -Wpedantic`, under `-Werror`. The library and the node were already
  clean; three tests were not (a shadowed name twice, a narrowing in a loop).
- `SystemFiles::write` is Dannan's `durable_replace_file`, or `durable_create_file` when an
  existing file must not be replaced (added at Lugh's request; it ends in `link()`, so of
  two inits racing exactly one makes the keyring, and Dannan's own key custody had the
  same race, now closed). Lugh's temporary, sync, rename and link code is deleted. Dannan
  is pinned to bd2f720. Finding: a write now makes the directories its file needs, where
  Lugh's refused; the test says so. At Lugh's request Dannan makes them 0700, one level at
  a time, as Lugh's own did (Dannan 7f02e58, Lugh's pin), and the test checks it.
- The rules follow the maintainer's decisions of 2026-11-04: Lugh keeps its presets (the `fuzz`
  preset's option is fixed: `LUGH_BUILD_FUZZING`, not the old `LUGH_FUZZ`) and runs the
  sanitizers routinely, its two exceptions to the stack. The stale `build-asan` and
  `build-tsan` trees from the old layout were deleted and built afresh. Under ASan and UBSan
  and under TSan, `lugh_tests` (335) and `ctest` (5) pass. Finding: ASan stopped the test
  binary as GoogleTest registered its tests, with a false container overflow where
  MacPorts' uninstrumented GoogleTest meets libc++'s annotated containers; the ASan test
  binary now turns container-overflow detection off (`lugh/test/sanitizer_options.cpp`),
  every other check on.
- Dannan is pinned to its first release tag, 0.2.0 (`LUGH_DANNAN_TAG`), in place of a
  commit, and linked as `dannan::dannan`, the name an installed Dannan exports. Under the
  debug build, ASan with UBSan, and TSan, `lugh_tests` (335) and `ctest` (5) pass.
- No Python (the maintainer, 2026-11-04), first part: the IoC check is a GoogleTest test,
  `lugh/test/node_ioc_check_test.cpp`, in `lugh_tests`, and `tools/lugh_ioc_check.py` and
  its ctest entry are gone. The same patterns and adapters; the one lookbehind is written
  without one, as `std::regex` has none. Each pattern now proves it catches an example of
  what it forbids, and that some of Lugh's own calls (`_time.now()`, `boost::asio::write`,
  Dannan's `Lock`) are not caught; a `getenv` planted in a library file was named and failed
  it. A plain-text prefilter keeps the scan near 0.2 s in a debug build. Unit count 335 to
  339; `ctest` 5 to 4.
- No Python, second part: the shutdown, `init` and API process tests are GoogleTest tests in
  `lugh_tests` (`node_process_shutdown_test.cpp`, `node_process_init_test.cpp`,
  `node_process_api_test.cpp`), check for check what the Python ones did, over a fixture
  (`lugh/test/fixtures/node_process.h`) on Dannan's `ChildProcess`. Dannan gave
  `ChildProcess` an environment, standard input, a pseudo-terminal, raw reads and any signal
  for them (ca029bb, Lugh's pin until the next tag; the pin is now `LUGH_DANNAN_REF`, a tag
  or a commit). The certificate is made in-process rather than by the `openssl` command,
  and every request and wait has a deadline. `test/process/` and the ctest entries are gone;
  `ctest` runs `lugh_tests` alone. Seven tests where there were three scripts: 339 to 346,
  passing in the debug, ASan and TSan builds.
- Callback style, first piece: `lugh/core/completion.h`, the one place that keeps Dannan's
  promise for an operation's answer (posted to the caller's executor exactly once, the
  answer or the deadline's, never inline), with five tests, run twenty times under TSan
  with no report. `Executor` moved there from `core/task.h`. The design for the rest is in
  `TODO/ACTIVE.md`. 346 to 351.
- Callback style, the audit log: `open`, `record`, `entries` and `verify` take Dannan's
  shape. The async lock held across numbering and writing is now a queue on the log, one
  write in flight, each entry numbered only once the one before has settled, so the chain
  keeps no gaps and no forks; a caller past its deadline is told the entry may yet be
  recorded, and it keeps its turn. `entries` answers `failed` on a store failure or the
  deadline rather than a short page. The frozen store is reached through
  `lugh/store/store_calls.h`; the layers not yet converted reach the log through the
  temporary bridge `lugh/core/awaited.h`; the tests through `wait_for` and
  `lugh/test/fixtures/audit_calls.h`. A new test has 100 callers on four threads record at
  once: one intact chain of 100, no TSan report in five runs. 351 to 352.
- Callback style, the directory: all twenty operations take Dannan's shape, each one
  `Completion` over steps that each start the next (names checked free, the record put,
  the change audited, memberships tidied in turn). A read answers `Outcome`, `failed` and
  never "absent" when the store fails or the deadline passes; a coroutine caller in
  transition gets the value through `awaited_value`, which throws for a read that could
  not happen (the router answers 500), and the dependents' `forget` (still coroutines) is
  run through `spawned`. The 77 calls from the routes, authn, the node and the tests were
  rewritten by rule, not by hand: the operation's answer type from a table, a deadline
  added, and `std::nullopt` where `expected` had been left to its default. A new test reads
  and writes through a store slower than the deadline: the read is `failed`, the write says
  it may yet be made. 352 to 353, in the debug, ASan and TSan builds.
- Callback style, the policies and the passwords. The step helpers (`answering`, `refusing`,
  `in_turn`, and `on_pool` for blocking work) are `lugh/core/steps.h`. Argon2id runs on the
  hashing pool through `on_pool`, the password held in a `shared_ptr` where a step needs it,
  since a `Secret` is not copied; `verify` and `has_password` answer `failed` rather than
  a false "no" when the store fails or the deadline passes. The directory's `Dependent`
  takes the callback shape; factors, not yet converted, answers it by running its
  coroutine through `spawned`. 353, in the debug, ASan and TSan builds.

## 2026-10-18: P5, the management API (not committed)

- **`/api/v1`** (`src/api/`, [docs/api.md](../docs/api.md)): users (list, find by name or address, create, read, change, disable, remove), their groups and factors, removing a factor, resetting them all, enrolment links; groups and their members; the global and per-group assurance levels; the audit log a page at a time, and a walk of its whole chain.
- **Scoped permissions**: `lugh:directory.read`, `lugh:directory.write`, `lugh:credentials.write`, `lugh:policies.write`, `lugh:audit.read`. Every route declares its scope in the router, after blackraven-admin's role-checked routes: `401` with `WWW-Authenticate` for no credential, `403` for a missing scope, and callers limited per caller once known and per address until then.
- **ETags**: a user or group carries its version as a strong ETag; `PATCH` and `DELETE` need `If-Match` (`428` without, `412` stale, `*` to skip). Policies and memberships are idempotent `PUT`s and `DELETE`s, with no version.
- **Errors**: one shape, a `Fault` mapped to one status each, and unknown or mistyped body fields refused, never ignored.
- **Genesis** (`authn/genesis`), replacing a bootstrap credential at the maintainer's word: there are no static credentials, tokens, keys or settings. `lugh init` on a cluster's first node makes `root`, in `administrators`, with a random 144-bit password shown once on standard error and kept only as its hash; it is the one credential a cluster is born with. Root's first sign-in goes from that password to enrolment, once (`EnrolmentLinks::first_sign_in_*`); then root signs in as anyone does. Genesis refuses a directory with anyone in it. A person no longer needs an email address (root has none).
- **Async all the way down** (the maintainer: "it should all be async"; a first pass that put blocking work on a pool behind the routes was not enough). Every operation that waits is a C++20 coroutine on Boost.Asio (`Task<T>`, `core/task.h`): the `Store` interface and `SealedStore`, the `Files` and `Console` ports, the keyring manager, the audit log, the directory, passwords, factors, policies, enrolment links, genesis, the authenticator and every route handler. `SystemFiles` and `SystemConsole` run their system calls on a `blocking` pool, and Argon2id runs on a `hashing` pool of two threads, both through `offload()`; the caller is suspended and holds no thread. The store holds each table's writes in order with an `AsyncMutex` (`core/async_mutex.h`) across the synced append, and its state with a `std::mutex` only for moments; readers never wait on the disk, and a write is invisible until it is durable. The router spawns each handler as a coroutine, with at most 256 in flight (`503 busy` past that), and answers a handler that throws `500`, once. Startup and `lugh init` are coroutines on the io_context. The `WorkPool` lifted earlier in P5 is gone. Sign-in steps take the `SignIn` by value and hand back the next, recovery codes travel as `Secret`, and a value written to the store is `SecureBytes`. Asio's `awaitable` is `[[nodiscard]]`, so a forgotten `co_await` is a compile error; it caught two in the tests.
- **Until P6 nothing opens the API**: no caller resolves, and every route answers 401. The routes are tested through a fixed-caller fake (`tests/fakes/fixed_callers.h`).
- **Tests**: 389 unit tests, among them a store whose append is held open (and which fails if the table's write lock is taken away), showing a read of that table and a write to another finish meanwhile, the held write invisible until it lands, and a second writer queued behind it without a thread; concurrent writers through a router on a real thread pool (64 creations at once; 32 racing for one name, one winning; 16 racing adds making one membership); the router spawning handlers rather than answering inline, refusing at its in-flight limit, and answering a throwing handler once; `offload` and `AsyncMutex` themselves; every route over the API rig, the router's scope, 401, 403 and per-caller limits, and genesis with root's first sign-in; the `init` ctest now checks genesis shows root's password once, on standard error only and nowhere on disk; a new `api` ctest runs the real binary after genesis and finds the API closed to every credential presented, root's password included. A new fuzz target over the route table, query, percent-encoding, `If-Match` and body checks (`fuzz/api_request_fuzz.cpp`), run here under ASan with a stand-in driver: 300,005 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P4, directory and authentication (not committed)

- **Directory** (`src/directory/`): users (person or service; enrolled; disabled), groups and memberships over the store, with names and addresses checked and folded to lower case and unique through the store's indexes, display names checked as printable UTF-8, and every write made against the version read, so the API's ETags have something to check. Removing a user removes their memberships and, through `Dependent`, their password and factors; the name is then free for someone new under a new ID.
- **Audit** (`src/audit/`): the `audit` table, one hash-chained record per entry, with `verify()` naming the first entry missing, altered or out of order. Every change the directory and authn make is recorded, with who made it and from where.
- **Passwords** (`authn/passwords`): Argon2id hashes in `credentials`, with their costs stored so a hash under old costs is made again at the next sign-in. At least 12 characters, at most 256 bytes, not the user's own name or address, and not on the local breached list (`authn.breached_passwords`, held as SHA-256 hashes, case folded). An unknown user costs the same hash as a known one.
- **Second factors** (`authn/factors`, `authn/totp`): TOTP (RFC 6238: SHA-1, six digits, 30 seconds, one step either way), confirmed by a code before it counts, with the last step stored so a code works once, even with two sign-ins racing; ten recovery codes of 80 bits, Argon2id-hashed, with a four-character selector so a guess costs one hash.
- **Policy** (`authn/policy`): `pwd`, `mfa`, `phr`, global and per group, the strictest winning, `mfa` by default (open question 9).
- **Enrolment** (`authn/enrolment_links`): one-time links in `grants`, stored as the SHA-256 of the token, 72 hours, spent by a conditional removal so they work once, and a new link ending the old.
- **Sign-in** (`authn/authenticator`): the password, then a TOTP or recovery code; or a link, a new password, and a TOTP factor enrolled, which ends with the recovery codes. Enrolment starts only from a link, never from a password alone. Refusals all look the same. Five wrong codes end a sign-in, a sign-in lasts 15 minutes, and failures back off per account and per address (`authn/backoff.h`), answered before any hashing. The last factor cannot be removed while policy needs one, and an administrator's reset means enrolling again from a new link.
- **Also**: `crypto/hmac` (HMAC-SHA-1 for TOTP, HMAC-SHA-256), `core/encoding.h` (hex, base32, base64url), `core/outcome.h` (results with a fault the API will map to a status), `field()` in `ByteWriter`/`ByteReader`. `main` opens the audit log and builds the directory and authn after the store; nothing reaches them over HTTP until P5 and P6.
- **Deferred**: `WorkPool` moves to P6, with the first route that hashes a password. Session revocation, re-authentication before a factor change, and telling the user about one need sessions (P6).
- **Tests**: 345 unit tests, among them the RFC vectors for HMAC (2202, 4231), HOTP and TOTP (4226, 6238) and base32/base64url (4648), and the whole sign-in run through over a MemoryStore with a ManualClock. Mutating the replay check, enrolment from a password, link expiry, the last-factor rule, the breached list or the audit chain each fails tests. A new fuzz target over every record parser and the text a person types (`fuzz/records_fuzz.cpp`), run here under ASan with a stand-in driver: 400,010 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P3, the store on one node (not committed)

- **Store** (`src/store/`): `Store`, the interface (get, find by a unique index, list, put and remove with an optional expected version, final removals with kept tombstones, per-record versions), `SealedStore` on disk, and `MemoryStore` in `tests/fakes/`. One log per table under `<state>/store/`, after Macha's sealed journal: a file header sealed under the table's data key, so a wrong keyring is refused before any frame is judged; one AES-256-GCM frame per change, bound to the table, the epoch and the previous frame's tag, so frames cannot move between tables or files, be reordered, dropped from the middle or replayed; every write synced before it is acknowledged, and cut back off the file if it fails part way.
- **Recovery**: a torn tail (nothing that looks like a frame after the break) is cut at open and logged; damage with frames after it stops the open, naming the file and the byte, after Macha's pack recovery but failing closed. A table whose failed write could not be cut back refuses writes until restart.
- **Compaction and keys**: a table more than half superseded past 1 MiB is rewritten whole under its current data key and renamed over the old, after Macha's pack compaction. `rotate()` makes a new data key epoch, saves the keyring before anything is sealed under it, and compacts. The first open of a table makes its data key.
- **Indexes**: declared per table, derived from the record value, unique, rebuilt at every open.
- **Not lifted from Macha**, and why: the rest of `LocalStore` and the ledger, which serve content-addressed objects placed by a DHT (`code-style.md`, "From Macha").
- **Ports**: `Files` gained `append`, `truncate` and `remove`. `crypto::sha256`, and 16- and 64-bit fields in `ByteReader`/`ByteWriter`.
- **Service**: `main` opens the store's 14 tables after the keyring and before it listens.
- **Tests**: 247 unit tests, among them a contract suite run against `SealedStore` and `MemoryStore` alike, every truncation of a log, damage, reordering, replay, a log moved to another table, another keyring, a failed write, a failed cut-back, compaction (and a failed one), rotation (and one whose keyring cannot be saved), and a torn tail on a real disk. The table log has a fuzz target (`fuzz/store_log_fuzz.cpp`), run here under ASan with a stand-in driver. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P2, crypto and keys (not committed)

- **Crypto** (`src/crypto/`, one thin layer over OpenSSL 3): AES-256-GCM seal and open with associated data and a random nonce from the `Random` port; HKDF-SHA256; Argon2id (OpenSSL 3.2+) with RFC 9106's second recommendation as the default and bounds on stored costs; ES256 and Ed25519 signing keys with PKCS#8 export and import, raw public keys (the uncompressed P-256 point, for a JWK) with an on-curve check, and JOSE-form signatures; constant-time comparison. Each is tested against its published vectors: the GCM specification's AES-256 cases, RFC 5869, RFC 9106, RFC 8032 and RFC 6979.
- **Memory**: `SecureBytes` and `Secret` hold their bytes in `core/secure_memory`, pages of their own that are locked into memory, kept out of core dumps on Linux and wiped when freed. Not OpenSSL's secure heap, because OpenSSL's Argon2id then takes its whole 64 MiB from that heap and fails; found by the init test. `Random` gained `fill`, so a key is made where it lives.
- **Keys** (`src/keys/`): the keyring file (`<state>/keyring`): a header saying where the master key comes from, then the data keys sealed whole under a KEK derived from the master key by HKDF, salted with the keyring's random id, with the header as associated data. Data keys per name and epoch, rotation, adding a key made elsewhere (for P8's join), and re-keying under a new master key. Written atomically (temporary, fsync, rename or link, directory fsync) and never replaced by init. The format's two parsers have a fuzz target (`fuzz/keyring_fuzz.cpp`), which also checks every parse writes back to the same bytes.
- **Master key**: from the systemd credential `lugh-master-key` in `$CREDENTIALS_DIRECTORY`, or from a passphrase of 16 characters or more typed at start and stretched by Argon2id. `lugh init` writes a new key to standard output for `systemd-creds encrypt`, refusing a terminal, and saves the keyring only once the key has gone; `lugh init --passphrase` asks twice. The service opens the keyring before it listens, and will not start without it.
- **Ports**: `system::Files` (`SystemFiles`, `MemoryFiles`) and `system::Console` (`SystemConsole`, `ScriptedConsole`). The IoC check now also refuses POSIX file calls, terminal calls and the process's memory outside the adapters.
- **Config and CLI**: `state.directory` (`LUGH_STATE_DIRECTORY`, `--state-directory`), the `init` command and `--passphrase`. `init` needs no TLS pair.
- **Deploy**: the unit passes `--state-directory /var/lib/lugh`, loads `LoadCredentialEncrypted=lugh-master-key:/etc/credstore.encrypted/lugh-master-key`, and sets `LimitMEMLOCK=16M`. `host-setup.sh` makes `/var/lib/lugh` (0700, lugh) and `/etc/credstore.encrypted` (0700), and warns while the credential is missing. `scripts/dev-init.sh` makes a development keyring and credential under `config/dev/`.
- **Tests**: 185 unit tests; a new `init` ctest that runs the real binary through init and start with a credential, with a passphrase, with each wrong, and with a terminal on standard output; the shutdown test now runs init first. All green under `debug`, `release`, `asan` and `tsan`.
- **Docs**: `architecture.md` (encryption at rest as built), `code-style.md` (key material, OpenSSL's secure heap, the new ports, the IoC rules, the test vectors), `README.md` (running with a keyring, and `lugh init` on a node).

## 2026-10-18: P1, skeleton (committed as `700092b`)

- **Build**: CMake 3.23+ with the presets `debug`, `release`, `asan`, `tsan` and `fuzz`; `lugh_core` (static), `lugh` and `lugh_tests`; `-Wall -Wextra -Wpedantic -Werror` and Clang's thread-safety errors on by default; hardening on by default (`_FORTIFY_SOURCE=3` outside Debug and sanitizers, `_GLIBCXX_ASSERTIONS`, libc++ fast hardening, `-fstack-protector-strong`, `-fstack-clash-protection` where it exists, CET or PAC/BTI by architecture, PIE, and `relro`/`now`/`noexecstack` on Linux), each flag probed under `-Werror` first because Apple's clang accepts some and then warns they did nothing. Boost 1.87+, OpenSSL 3, yaml-cpp, GoogleTest, Python 3.
- **Service**: Beast over TLS 1.3 and nothing older, with no plaintext listener and the TLS pair required by the config loader; a handshake timeout; the security headers (HSTS, nosniff, CSP, Referrer-Policy) set on every response after the middleware; `Server: Lugh` and no version anywhere a stranger can read it. The router with open routes, path parameters, 404/405 and per-address rate limits; `/health` and `/ready` saying ok and nothing else. `ClientAddress` trusts no proxy unless `proxy.trusted_networks` names it. Layered config (file, `secrets.yaml`, `LUGH_*`, CLI) with unknown keys warned and bad values refused naming their source. `Secret` (`core/secret.h`): a type that converts to nothing, so a secret cannot reach a log line, with wiping and constant-time comparison. Ports `Clock`, `Random`, `Environment` with system adapters. Core dumps refused by `main`.
- **Tests**: 89 unit tests; the shutdown test (makes its own certificate, speaks TLS, SIGTERM and SIGINT exit 0 within 5 s); the IoC check. All green under `debug`, `asan` and `tsan`. HTTP tests run the real server on port 0 over TLS with an in-process self-signed certificate (`tests/helpers/test_certificate.h`), and prove TLS 1.3 is negotiated, TLS 1.2 and plaintext are refused, and the headers are present. End to end: `scripts/dev-cert.sh` then `./build/lugh --config config/config.yaml`; `curl -sk` sees `{"status":"ok"}`, `--tls-max 1.2` fails the handshake, `http://` gets nothing.
- **Fuzz**: `fuzz/cli_fuzz.cpp` and the `fuzz` preset with a short ctest run per target. Not built here (Apple's clang has no libFuzzer).
- **Deploy**: `deploy/lugh.service` (user `lugh`, `CAP_NET_BIND_SERVICE` only, `StateDirectory=lugh`, `LimitCORE=0`, blackraven-admin's sandbox) and `deploy/host-setup.sh` (user, config and TLS directory permissions). `cmake --install` installs binary, config, docs and unit, runs host setup and restarts.
- **Docs**: `docs/code-style.md` (the rules, the Secrets section, IoC, errors, logging, tests, build, and the lifted-from tables: blackraven-admin for nearly all of it, AthenaSIP's `tls_context` for TLS), `README.md`, `.gitignore` (build trees, `config/dev/`, `*.pem`, `*.cred`, `secrets.yaml`, `CLAUDE.local.md`).

## 2026-10-18: P0, initial architecture (not committed)

- **Docs**: `docs/architecture.md` sets out the design as understood: the OAuth 2/OIDC, management API, LDAP and C++ library surfaces; the store built on Macha's sealed journal, packs and replication; the T.O.M.S styling for the dashboard; blackraven-admin's conventions; the security model; and the open questions.
- **TODO**: `ACTIVE.md` and `COMPLETE.md` created, with the phase plan P1 to P12.
