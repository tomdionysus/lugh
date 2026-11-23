#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

cmake_minimum_required(VERSION 3.24)

# The tag, `lugh-node --version`, the package and the README's Status carry this version. Bump
# them together.
project(lugh
    VERSION 0.6.0
    DESCRIPTION "Lugh"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Executables at the top of the build tree: ./build/lugh_tests, ./build/lugh-node.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# Off, only lugh_client is built: what a relying party that fetches Lugh into its own build
# wants (Lir's Lugh plugin). The tests and fuzz targets need the node, so they go with it.
option(LUGH_BUILD_NODE "Build lugh-node, its library, its tests and its install; off builds lugh_client alone" ON)
include(CMakeDependentOption)
cmake_dependent_option(LUGH_BUILD_TESTING "Build the test binary and register the tests" ON "LUGH_BUILD_NODE" OFF)
option(LUGH_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
option(LUGH_HARDEN "Compiler and linker hardening on every target" ON)
cmake_dependent_option(LUGH_BUILD_FUZZING "Build the libFuzzer targets in lugh/fuzz; needs a clang that ships libFuzzer" OFF "LUGH_BUILD_NODE" OFF)
# Campaigns hunt with ASan and UBSan. Off, a target is libFuzzer alone: for measuring a target's
# own memory and speed, which ASan's allocator and shadow hide.
cmake_dependent_option(LUGH_FUZZ_SANITIZERS "Build the fuzz build with ASan and UBSan" ON "LUGH_BUILD_FUZZING" OFF)
# Line and branch coverage of Lugh's own targets (gcov), for the CI's report: the stack keeps it
# near 100% (the maintainer, 2026-11-20).
option(LUGH_COVERAGE "Instrument Lugh's targets for coverage" OFF)
# On: build against the installed Dannan (libdannan-dev), and for the tests the installed Dagda
# (libdagda-dev) and Lir (liblir-dev, or Lir fetched for the tests alone when it is not
# installed). The Debian package builds so, depending on those packages rather than carrying
# copies (the stack's packaging convention). Off: each is fetched at its pin.
option(LUGH_SYSTEM_DEPENDENCIES "Build against the installed Dannan, Dagda and Lir" OFF)
# local: /usr/local, and `cmake --install` prepares the host and restarts the service. debian:
# the package's paths (/usr, /etc/lugh, /usr/share/lugh), the host left to the package's scripts.
set(LUGH_INSTALL_LAYOUT "local" CACHE STRING "local or debian")
set_property(CACHE LUGH_INSTALL_LAYOUT PROPERTY STRINGS local debian)
set(LUGH_SANITIZE "none" CACHE STRING "none, address (with undefined) or thread")
set_property(CACHE LUGH_SANITIZE PROPERTY STRINGS none address thread)

include(CheckCXXCompilerFlag)
include(CheckPIESupported)

# Boost 1.83 is Dannan's floor (Debian's, so the build nodes build with it), and Lugh's must be the one
# Dannan is built with; Asio, Beast and JSON are all used header-only, and Boost.JSON's definitions
# are Dannan's, compiled once in libdannan (dannan/json/json.h).
find_package(Boost 1.83 REQUIRED CONFIG)
find_package(Threads REQUIRED)

# TLS, AEAD, Argon2id, signatures and randomness all come from OpenSSL 3, the same one
# Dannan links: one process, one OpenSSL. On the laptop that is MacPorts', as everything is
# (the presets say where).
find_package(OpenSSL 3.0 REQUIRED)

# Dannan, the network layer Lugh hosts on, at a release tag, or at a commit while Lugh needs
# something not yet tagged: from the sibling checkout, cloned into the build tree, so
# building Lugh never touches ../dannan. Linked as dannan::dannan, the name an installed
# Dannan exports too (find_package(dannan CONFIG)). Now: 0.12.0 (libdannan.so.0.12): Boost.JSON's
# compiled part (dannan/json/json.h), the stack's TSan suppressions (DANNAN_TSAN_SUPPRESSIONS), and
# what P8.1 takes: health checks, the node-program helper, keyed limits and the stored password.
set(LUGH_DANNAN_REPOSITORY "${CMAKE_CURRENT_SOURCE_DIR}/../dannan" CACHE PATH "Dannan's repository")
# Not a cache variable: a moved pin must take effect without clearing the build tree.
set(LUGH_DANNAN_REF "0.12.0")
# Dagda, the store P8 moves Lugh onto, the same way: a release tag of the sibling checkout,
# cloned into the build tree. Only the node needs it; lugh_client never does. Now: 0.4.0, on Dannan
# 0.11.1 (slice 1's change notice, Space::covers, and repair's memory fixes).
set(LUGH_DAGDA_REPOSITORY "${CMAKE_CURRENT_SOURCE_DIR}/../dagda" CACHE PATH "Dagda's repository")
set(LUGH_DAGDA_REF "0.4.0")
# Lir's MQTT codec, the stack's one, for lugh::client_topics: only lir::mqtt is built
# (LIR_BUILD_SERVER off). Now: 0.2.0, on Dannan 0.10.2 like Lugh; its codec's API is 0.1.0's.
set(LUGH_LIR_REPOSITORY "${CMAKE_CURRENT_SOURCE_DIR}/../lir" CACHE STRING "Lir's repository, a path or a URL")
set(LUGH_LIR_REF "0.2.0")
# A sanitizer instruments Dannan too: half an instrumented process reports nothing true.
if (LUGH_SANITIZE STREQUAL "address")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif (LUGH_SANITIZE STREQUAL "thread")
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()
# A fuzz build instruments every object, Dannan's too, for coverage and, as a rule, ASan and UBSan:
# with only the target's own file instrumented, libFuzzer sees no edge inside a parser and ASan
# no read past a buffer there (P12's first campaigns ran so). The targets add libFuzzer's main.
if (LUGH_BUILD_FUZZING)
    if (LUGH_FUZZ_SANITIZERS)
        set(LUGH_FUZZ_INSTRUMENT "-fsanitize=fuzzer-no-link,address,undefined")
        set(LUGH_FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        set(LUGH_FUZZ_INSTRUMENT "-fsanitize=fuzzer-no-link")
        set(LUGH_FUZZ_FLAGS "-fsanitize=fuzzer")
    endif()
    add_compile_options(${LUGH_FUZZ_INSTRUMENT} -fno-omit-frame-pointer)
    add_link_options(${LUGH_FUZZ_INSTRUMENT})
endif()
include(FetchContent)
# A sanitizer build instruments every library in the process, so it builds Dannan, Dagda and Lir
# from source with its flags (above); an installed library is built without them.
if (LUGH_SYSTEM_DEPENDENCIES AND NOT LUGH_SANITIZE STREQUAL "none")
    message(FATAL_ERROR "LUGH_SANITIZE=${LUGH_SANITIZE} needs Dannan, Dagda and Lir built from source: turn LUGH_SYSTEM_DEPENDENCIES off")
endif()
if (LUGH_SYSTEM_DEPENDENCIES)
    if (NOT TARGET dannan::dannan)
        find_package(dannan ${LUGH_DANNAN_REF} CONFIG REQUIRED)
    endif()
    # The node itself links neither Dagda nor Lir yet: the tests' cluster rig and topic checks do.
    # Dagda's package matches its release exactly (no release promises another's ABI yet): the pin.
    if (LUGH_BUILD_TESTING AND NOT TARGET dagda::dagda)
        find_package(dagda ${LUGH_DAGDA_REF} EXACT CONFIG REQUIRED)
    endif()
    if (LUGH_BUILD_TESTING AND NOT TARGET lir::mqtt)
        find_package(lir ${LUGH_LIR_REF} CONFIG QUIET)
        if (NOT lir_FOUND)
            FetchContent_Declare(lir GIT_REPOSITORY "${LUGH_LIR_REPOSITORY}" GIT_TAG "${LUGH_LIR_REF}" EXCLUDE_FROM_ALL)
            set(LIR_BUILD_SERVER OFF CACHE BOOL "" FORCE)
            set(LIR_BUILD_TESTING OFF CACHE BOOL "" FORCE)
            FetchContent_MakeAvailable(lir)
        endif()
    endif()
else()
    # Fetched into another build (lugh_client in a relying party), Lugh takes the Dannan that build
    # already has: one process, one Dannan. The consumer's pin must be one Lugh's commit is tested on.
    if (NOT TARGET dannan::dannan)
        # OVERRIDE_FIND_PACKAGE: Dagda's find_package(dannan) takes this one, not an installed one.
        FetchContent_Declare(dannan GIT_REPOSITORY "${LUGH_DANNAN_REPOSITORY}" GIT_TAG "${LUGH_DANNAN_REF}" OVERRIDE_FIND_PACKAGE)
        set(DANNAN_BUILD_TESTING OFF CACHE BOOL "" FORCE)
        # Dannan's own switch for its targets (docs/building.md), beside the global flags above.
        if (NOT LUGH_SANITIZE STREQUAL "none")
            set(DANNAN_SANITIZE "${LUGH_SANITIZE}" CACHE STRING "" FORCE)
        endif()
        # Lugh links the library; Dannan's tools (dannan-node, dannan-ca, ...) are neither built nor installed.
        set(DANNAN_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(dannan)
    endif()
    # Until Dagda has a switch for its tools (asked of Dagda, 2026-11-20), they are built, and an
    # install carries dagda-migrate with the library. EXCLUDE_FROM_ALL would leave dagda-migrate unbuilt
    # and fail the install.
    if (LUGH_BUILD_NODE AND NOT TARGET dagda::dagda)
        FetchContent_Declare(dagda GIT_REPOSITORY "${LUGH_DAGDA_REPOSITORY}" GIT_TAG "${LUGH_DAGDA_REF}")
        set(DAGDA_BUILD_TESTING OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(dagda)
    endif()
    # Lir fetched into Lugh, or Lugh fetched into Lir: either way one lir::mqtt. Only the node's
    # build (its tests) fetches it; a relying party that fetches lugh_client alone needs no Lir, and
    # a broker that does already has lir::mqtt, which builds lugh::client_topics.
    if (LUGH_BUILD_NODE AND NOT TARGET lir::mqtt)
        FetchContent_Declare(lir GIT_REPOSITORY "${LUGH_LIR_REPOSITORY}" GIT_TAG "${LUGH_LIR_REF}")
        set(LIR_BUILD_SERVER OFF CACHE BOOL "" FORCE)
        set(LIR_BUILD_TESTING OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(lir)
    endif()
endif()

# ---------------------------------------------------------------- hardening
#
# Every target, on by default. Each flag is tried first, because the set differs by
# compiler and architecture, and a flag the compiler does not know would fail the build
# under -Werror rather than protect anything.

check_pie_supported(LANGUAGES CXX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LUGH_HARDEN_COMPILE "")
set(LUGH_HARDEN_LINK "")

if (LUGH_HARDEN)
    # _FORTIFY_SOURCE needs optimisation, and glibc says so with a warning that -Werror
    # turns into an error, so it is off in Debug and on everywhere else. The sanitizers
    # define it to 0 themselves, because their own checks replace it, so it is off there too,
    # and in a fuzz build, which is a sanitizer build.
    if (LUGH_SANITIZE STREQUAL "none" AND NOT LUGH_BUILD_FUZZING)
        # Undefined first: a distribution's own flags (dpkg's hardening) may already set it lower.
        list(APPEND LUGH_HARDEN_COMPILE "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>" "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
    endif()
    list(APPEND LUGH_HARDEN_COMPILE
        -D_GLIBCXX_ASSERTIONS
        -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST
    )

    # Probed under -Werror: Apple's clang accepts -fstack-clash-protection and then warns
    # that it did nothing, which -Werror on the real build would turn into a failure.
    set(CMAKE_REQUIRED_FLAGS "-Werror")
    foreach(flag -fstack-protector-strong -fstack-clash-protection)
        string(MAKE_C_IDENTIFIER "${flag}" name)
        check_cxx_compiler_flag("${flag}" LUGH_HAS${name})
        if (LUGH_HAS${name})
            list(APPEND LUGH_HARDEN_COMPILE "${flag}")
        endif()
    endforeach()
    unset(CMAKE_REQUIRED_FLAGS)

    # Control-flow protection is an architecture's own: CET on x86-64, PAC and BTI on arm64.
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        list(APPEND LUGH_HARDEN_COMPILE -fcf-protection)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        list(APPEND LUGH_HARDEN_COMPILE -mbranch-protection=standard)
    endif()

    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND LUGH_HARDEN_LINK -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
    endif()
endif()

# The same flags on every target, PRIVATE: they govern how a target's own sources compile,
# not how anything linking it does.
function(lugh_flags target)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
    if (LUGH_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE -Wthread-safety -Werror=thread-safety)
    endif()

    target_compile_options(${target} PRIVATE ${LUGH_HARDEN_COMPILE})
    target_link_options(${target} PRIVATE ${LUGH_HARDEN_LINK})

    if (LUGH_COVERAGE)
        target_compile_options(${target} PRIVATE --coverage -O0)
        target_link_options(${target} PRIVATE --coverage)
    endif()

    if (LUGH_SANITIZE STREQUAL "address")
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    elseif (LUGH_SANITIZE STREQUAL "thread")
        target_compile_options(${target} PRIVATE -fsanitize=thread)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
endfunction()

# Where an installed node's files are, by layout: the binary's default --config is the installed
# config, so `lugh-node` finds it with no flags.
if (LUGH_INSTALL_LAYOUT STREQUAL "debian")
    set(LUGH_CONFDIR  "/etc/lugh")
    set(LUGH_SHAREDIR "/usr/share/lugh")
    set(LUGH_DOCDIR   "/usr/share/doc/lugh")
    set(LUGH_UNITDIR  "lib/systemd/system")
elseif (LUGH_INSTALL_LAYOUT STREQUAL "local")
    set(LUGH_CONFDIR  "/usr/local/etc/lugh")
    set(LUGH_SHAREDIR "/usr/local/share/lugh")
    set(LUGH_DOCDIR   "/usr/local/share/lugh/docs")
    set(LUGH_UNITDIR  "/etc/systemd/system")
else()
    message(FATAL_ERROR "LUGH_INSTALL_LAYOUT is local or debian, not ${LUGH_INSTALL_LAYOUT}")
endif()
set(LUGH_BINARY "${CMAKE_INSTALL_PREFIX}/bin/lugh-node")

configure_file(lugh/include/lugh/version.h.in "${PROJECT_BINARY_DIR}/generated/lugh/version.h")

add_subdirectory(lugh)
if (NOT LUGH_BUILD_NODE)
    return()
endif()
add_subdirectory(tools)

# ------------------------------------------------------------------- tests
#
# One GoogleTest binary, lugh_tests, holds every test: the units, the IoC check, and the
# process tests that run the real lugh-node (node_process_*). ctest runs it, and gates the
# install.

if (LUGH_BUILD_TESTING)
    enable_testing()
    find_package(GTest REQUIRED)
    add_subdirectory(lugh/test)
    add_test(NAME unit COMMAND lugh_tests)
endif()

# -------------------------------------------------------------------- fuzz

if (LUGH_BUILD_FUZZING)
    add_subdirectory(lugh/fuzz)
endif()

# ----------------------------------------------------------------- install
#
# Two layouts (LUGH_INSTALL_LAYOUT). local: `sudo cmake --install build-release` is the whole
# deployment of a node built in place: binary, config, docs, the dashboard, the systemd unit, host
# preparation and a restart; run ctest first, and stop if it fails. debian: the files alone, at
# the package's paths, for debian/rules; the package's scripts make the user and set what may
# read what, and the service is installed disabled.
#
# The config and the unit go where the layout says whatever CMAKE_INSTALL_PREFIX is, so neither
# layout is a relocatable package.

install(TARGETS lugh-node RUNTIME DESTINATION bin)

install(FILES config/config.yaml DESTINATION "${LUGH_CONFDIR}")
install(DIRECTORY docs/ DESTINATION "${LUGH_DOCDIR}")

# The unit, its paths the layout's.
configure_file(deploy/lugh.service.in "${PROJECT_BINARY_DIR}/lugh.service" @ONLY)

# The dashboard (P7), built first with `npm ci && npm run build` at the top (the npm workspace of
# dashboard/ and @lugh/admin-ui in lugh/ui). Vite fingerprints
# its assets, so the installed copy is removed before the new one goes in; root's, read-only to
# the service. Turn LUGH_INSTALL_DASHBOARD off to install without one.
option(LUGH_INSTALL_DASHBOARD "Install the dashboard's build" ON)
set(LUGH_DASHBOARD_BUILD "${CMAKE_CURRENT_SOURCE_DIR}/dashboard/build/client")
if (LUGH_INSTALL_DASHBOARD)
    install(CODE "
        if (NOT EXISTS \"${LUGH_DASHBOARD_BUILD}/index.html\")
            message(FATAL_ERROR \"The dashboard is not built: run 'npm ci && npm run build' at the top of the tree first, or configure with -DLUGH_INSTALL_DASHBOARD=OFF\")
        endif()
        file(REMOVE_RECURSE \"\$ENV{DESTDIR}${LUGH_SHAREDIR}/dashboard\")
    ")
    install(DIRECTORY "${LUGH_DASHBOARD_BUILD}/" DESTINATION "${LUGH_SHAREDIR}/dashboard"
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
            FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()

install(FILES man/lugh-node.8 DESTINATION share/man/man8)

if (LUGH_INSTALL_LAYOUT STREQUAL "debian")
    install(FILES "${PROJECT_BINARY_DIR}/lugh.service" DESTINATION "${LUGH_UNITDIR}")
    return()
endif()

option(LUGH_INSTALL_SYSTEM "Install the systemd unit and prepare the host" ON)

if (LUGH_INSTALL_SYSTEM)
    install(FILES "${PROJECT_BINARY_DIR}/lugh.service" DESTINATION "${LUGH_UNITDIR}")

    install(CODE "
        if (NOT \"\$ENV{LUGH_SKIP_SYSTEM}\")
            # Dannan's shared library went into the prefix's lib directory with the node: the
            # loader's cache must know it before lugh-node can run (found by the first test install
            # on the build nodes, 2026-11-16).
            find_program(LDCONFIG ldconfig PATHS /usr/sbin /sbin)
            if (LDCONFIG)
                execute_process(COMMAND \${LDCONFIG})
            endif()
            find_program(SYSTEMCTL systemctl)
            if (SYSTEMCTL)
                message(STATUS \"Preparing the host\")
                execute_process(
                    COMMAND \"${CMAKE_CURRENT_SOURCE_DIR}/deploy/host-setup.sh\"
                    RESULT_VARIABLE setup_result
                )
                if (NOT setup_result EQUAL 0)
                    message(FATAL_ERROR \"host-setup.sh failed (\${setup_result})\")
                endif()

                message(STATUS \"Reloading systemd and restarting lugh\")
                execute_process(COMMAND \${SYSTEMCTL} daemon-reload)
                execute_process(COMMAND \${SYSTEMCTL} enable lugh.service)
                execute_process(COMMAND \${SYSTEMCTL} restart lugh.service)
            else()
                message(STATUS \"systemctl not found; skipping service installation\")
            endif()
        endif()
    ")
endif()
