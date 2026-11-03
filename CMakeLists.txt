#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

cmake_minimum_required(VERSION 3.23)

# The root README carries this version in italics under its title. Bump both.
project(lugh
    VERSION 0.1.0
    DESCRIPTION "Lugh"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(LUGH_BUILD_TESTING "Build the test binary and register the tests" ON)
option(LUGH_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
option(LUGH_HARDEN "Compiler and linker hardening on every target" ON)
option(LUGH_FUZZ "Build the libFuzzer targets; needs a clang that ships libFuzzer" OFF)
set(LUGH_SANITIZE "none" CACHE STRING "none, address (with undefined) or thread")
set_property(CACHE LUGH_SANITIZE PROPERTY STRINGS none address thread)

include(CheckCXXCompilerFlag)
include(CheckPIESupported)

# Boost 1.87 is the floor Dannan and AthenaSIP share, and Lugh's must be the one Dannan is
# built with; Asio, Beast and JSON are all used header-only, and Boost.JSON's definitions
# are compiled once, in src/boost_json.cpp.
find_package(Boost 1.87 REQUIRED CONFIG)
find_package(Threads REQUIRED)
find_package(yaml-cpp REQUIRED)

# TLS, AEAD, Argon2id, signatures and randomness all come from OpenSSL 3, the same one
# Dannan links: one process, one OpenSSL. On the laptop that is MacPorts', as everything is
# (the presets say where).
find_package(OpenSSL 3.0 REQUIRED)

# Dannan, the network layer Lugh hosts on (and Dagda, the store, built beside it). From
# the sibling checkout, pinned to one commit and cloned into the build tree, so building
# Lugh never touches ../dannan. Its Context exists only on feature/wire-v1 so far, which
# has no tag; the pin moves to a tag once one carries it (the maintainer, 2026-11-03).
set(LUGH_DANNAN_REPOSITORY "${CMAKE_CURRENT_SOURCE_DIR}/../dannan" CACHE PATH "Dannan's repository")
set(LUGH_DANNAN_COMMIT "785e393afe963a40a4878e2f16869ce6c022b0a0" CACHE STRING "The Dannan commit Lugh builds against")
# A sanitizer instruments Dannan too: half an instrumented process reports nothing true.
if (LUGH_SANITIZE STREQUAL "address")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif (LUGH_SANITIZE STREQUAL "thread")
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()
include(FetchContent)
FetchContent_Declare(dannan GIT_REPOSITORY "${LUGH_DANNAN_REPOSITORY}" GIT_TAG "${LUGH_DANNAN_COMMIT}")
set(DANNAN_BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(dannan)

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
    # define it to 0 themselves, because their own checks replace it, so it is off there too.
    if (LUGH_SANITIZE STREQUAL "none")
        list(APPEND LUGH_HARDEN_COMPILE "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
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
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if (LUGH_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target} PRIVATE -Wthread-safety -Werror=thread-safety)
    endif()

    target_compile_options(${target} PRIVATE ${LUGH_HARDEN_COMPILE})
    target_link_options(${target} PRIVATE ${LUGH_HARDEN_LINK})

    if (LUGH_SANITIZE STREQUAL "address")
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    elseif (LUGH_SANITIZE STREQUAL "thread")
        target_compile_options(${target} PRIVATE -fsanitize=thread)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()
endfunction()

configure_file(src/build_version.h.in "${CMAKE_CURRENT_BINARY_DIR}/generated/build_version.h")

# ------------------------------------------------------------------- core
#
# The service minus main(), linked by the executable, the tests and the fuzz targets.
# Listed, not globbed: a file added without a line here should fail to link, not be found
# by accident.

add_library(lugh_core STATIC
    src/api/audit_routes.cpp
    src/api/group_routes.cpp
    src/api/policy_routes.cpp
    src/api/user_routes.cpp
    src/audit/audit_log.cpp
    src/authn/authenticator.cpp
    src/authn/enrolment_links.cpp
    src/authn/factors.cpp
    src/authn/genesis.cpp
    src/authn/password_hash.cpp
    src/authn/passwords.cpp
    src/authn/policy.cpp
    src/authn/totp.cpp
    src/boost_json.cpp
    src/config.cpp
    src/core/secure_memory.cpp
    src/crypto/aead.cpp
    src/crypto/argon2.cpp
    src/crypto/digest.cpp
    src/crypto/hkdf.cpp
    src/crypto/hmac.cpp
    src/crypto/signing.cpp
    src/directory/directory.cpp
    src/directory/records.cpp
    src/http/client_address.cpp
    src/http/health_routes.cpp
    src/http/http_server.cpp
    src/http/router.cpp
    src/http/tls_context.cpp
    src/keys/keyring.cpp
    src/keys/keyring_format.cpp
    src/keys/keyring_manager.cpp
    src/loggers/logger_scoped.cpp
    src/loggers/logger_stdio.cpp
    src/network/cidr.cpp
    src/store/log_format.cpp
    src/store/sealed_store.cpp
    src/system/system_clock.cpp
    src/system/system_console.cpp
    src/system/system_environment.cpp
    src/system/system_files.cpp
    src/system/system_random.cpp
)

target_include_directories(lugh_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(lugh_core
    PUBLIC
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        yaml-cpp::yaml-cpp
)

# Every source parses the same Boost headers before a line of ours; precompiling them is
# what keeps a build of many small files from being slower than a few large ones.
target_precompile_headers(lugh_core
    PRIVATE
        <boost/asio.hpp>
        <boost/beast.hpp>
        <boost/json.hpp>
)

lugh_flags(lugh_core)

# -------------------------------------------------------------- executable

add_executable(lugh src/main.cpp)
target_link_libraries(lugh PRIVATE lugh_core)
lugh_flags(lugh)

# ------------------------------------------------------------------- tests
#
# One GoogleTest binary, mirroring src/. Run it directly for the unit suite: ctest runs it
# too, beside the shutdown test and the IoC check, and gates the install.

if (LUGH_BUILD_TESTING)
    enable_testing()
    find_package(GTest REQUIRED)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    add_executable(lugh_tests
        tests/api/audit_routes_test.cpp
        tests/api/concurrency_test.cpp
        tests/api/group_routes_test.cpp
        tests/api/policy_routes_test.cpp
        tests/api/user_routes_test.cpp
        tests/audit/audit_log_test.cpp
        tests/authn/authenticator_test.cpp
        tests/authn/backoff_test.cpp
        tests/authn/enrolment_links_test.cpp
        tests/authn/factors_test.cpp
        tests/authn/genesis_test.cpp
        tests/authn/passwords_test.cpp
        tests/authn/policy_test.cpp
        tests/authn/totp_test.cpp
        tests/cli_test.cpp
        tests/config_test.cpp
        tests/core/async_test.cpp
        tests/core/byte_io_test.cpp
        tests/core/encoding_test.cpp
        tests/core/secret_test.cpp
        tests/core/secure_memory_test.cpp
        tests/crypto/aead_test.cpp
        tests/crypto/argon2_test.cpp
        tests/crypto/compare_test.cpp
        tests/crypto/digest_test.cpp
        tests/crypto/hkdf_test.cpp
        tests/crypto/hmac_test.cpp
        tests/crypto/signing_test.cpp
        tests/directory/directory_test.cpp
        tests/directory/records_test.cpp
        tests/http/client_address_test.cpp
        tests/http/health_routes_test.cpp
        tests/http/http_server_test.cpp
        tests/http/rate_limiter_test.cpp
        tests/http/router_test.cpp
        tests/http/tls_context_test.cpp
        tests/keys/keyring_format_test.cpp
        tests/keys/keyring_manager_test.cpp
        tests/keys/keyring_test.cpp
        tests/loggers/logger_scoped_test.cpp
        tests/loggers/logger_stdio_test.cpp
        tests/network/cidr_test.cpp
        tests/store/async_store_test.cpp
        tests/store/log_format_test.cpp
        tests/store/sealed_store_test.cpp
        tests/store/store_contract_test.cpp
        tests/system/system_files_test.cpp
    )

    target_include_directories(lugh_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(lugh_tests PRIVATE lugh_core GTest::gtest_main)
    target_precompile_headers(lugh_tests
        PRIVATE
            <boost/asio.hpp>
            <boost/beast.hpp>
            <boost/json.hpp>
            <gtest/gtest.h>
    )
    lugh_flags(lugh_tests)

    add_test(NAME unit COMMAND lugh_tests)

    # The real binary stops on SIGTERM and SIGINT, promptly and with status 0.
    add_test(NAME shutdown
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/shutdown_test.py $<TARGET_FILE:lugh>)

    # `lugh init` and the start that follows it, with a credential and with a passphrase.
    add_test(NAME init
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/init_test.py $<TARGET_FILE:lugh>)

    # /api/v1 through the real binary: after genesis, nothing opens it until P6.
    add_test(NAME api
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/api_test.py $<TARGET_FILE:lugh>)

    # Outside main.cpp and the adapters, nothing names a clock, the environment, a thread,
    # a process or a file write.
    add_test(NAME ioc
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/ioc-check.py ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# -------------------------------------------------------------------- fuzz
#
# One libFuzzer target per parser we own. Apple's clang does not ship libFuzzer, so on a Mac
# this needs Homebrew's: CXX=$(brew --prefix llvm)/bin/clang++ cmake --preset fuzz.

if (LUGH_FUZZ)
    check_cxx_compiler_flag(-fsanitize=fuzzer LUGH_HAS_FUZZER)
    if (NOT LUGH_HAS_FUZZER)
        message(FATAL_ERROR "LUGH_FUZZ is on but ${CMAKE_CXX_COMPILER} has no libFuzzer (-fsanitize=fuzzer)")
    endif()

    function(lugh_fuzz_target name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE lugh_core)
        target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
        lugh_flags(${name})

        # A short run under ctest, so a fuzz target that no longer builds or crashes at once
        # is caught like any other test. Campaigns run the binary by hand.
        add_test(NAME fuzz_${name} COMMAND ${name} -runs=2000 -max_total_time=10)
    endfunction()

    lugh_fuzz_target(fuzz_cli fuzz/cli_fuzz.cpp)
    lugh_fuzz_target(fuzz_keyring fuzz/keyring_fuzz.cpp)
    lugh_fuzz_target(fuzz_store_log fuzz/store_log_fuzz.cpp)
    lugh_fuzz_target(fuzz_records fuzz/records_fuzz.cpp)
    lugh_fuzz_target(fuzz_api_request fuzz/api_request_fuzz.cpp)
endif()

# ----------------------------------------------------------------- install
#
# `sudo cmake --install build-release` is the whole deployment: binary, config, docs, the
# systemd unit, host preparation, and a restart. Run ctest first, and stop if it fails. The
# dashboard joins in P7.
#
# Absolute destinations are deliberate: the unit belongs in /etc and the config in
# /usr/local/etc whatever CMAKE_INSTALL_PREFIX says, so this is not a relocatable package.
#
# Turn LUGH_INSTALL_SYSTEM off to install the files without touching systemd or the host.

option(LUGH_INSTALL_SYSTEM "Install the systemd unit and prepare the host" ON)

set(LUGH_CONFDIR  "/usr/local/etc/lugh")
set(LUGH_SHAREDIR "/usr/local/share/lugh")
set(LUGH_UNITDIR  "/etc/systemd/system")

install(TARGETS lugh RUNTIME DESTINATION bin)

install(FILES config/config.yaml DESTINATION "${LUGH_CONFDIR}")
install(DIRECTORY docs/ DESTINATION "${LUGH_SHAREDIR}/docs")

if (LUGH_INSTALL_SYSTEM)
    install(FILES deploy/lugh.service DESTINATION "${LUGH_UNITDIR}")

    install(CODE "
        if (NOT \"\$ENV{LUGH_SKIP_SYSTEM}\")
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
