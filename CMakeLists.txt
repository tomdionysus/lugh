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
# Executables at the top of the build tree: ./build/lugh_tests, ./build/lugh-node.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

option(LUGH_BUILD_TESTING "Build the test binary and register the tests" ON)
option(LUGH_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
option(LUGH_HARDEN "Compiler and linker hardening on every target" ON)
option(LUGH_BUILD_FUZZING "Build the libFuzzer targets in lugh/fuzz; needs a clang that ships libFuzzer" OFF)
set(LUGH_SANITIZE "none" CACHE STRING "none, address (with undefined) or thread")
set_property(CACHE LUGH_SANITIZE PROPERTY STRINGS none address thread)

include(CheckCXXCompilerFlag)
include(CheckPIESupported)

# Boost 1.87 is the floor Dannan and AthenaSIP share, and Lugh's must be the one Dannan is
# built with; Asio, Beast and JSON are all used header-only, and Boost.JSON's definitions
# are compiled once, in lugh/http/boost_json.cpp.
find_package(Boost 1.87 REQUIRED CONFIG)
find_package(Threads REQUIRED)
find_package(yaml-cpp REQUIRED)

# TLS, AEAD, Argon2id, signatures and randomness all come from OpenSSL 3, the same one
# Dannan links: one process, one OpenSSL. On the laptop that is MacPorts', as everything is
# (the presets say where).
find_package(OpenSSL 3.0 REQUIRED)

# Dannan, the network layer Lugh hosts on, at a release tag, or at a commit while Lugh needs
# something not yet tagged: from the sibling checkout, cloned into the build tree, so
# building Lugh never touches ../dannan. Linked as dannan::dannan, the name an installed
# Dannan exports too (find_package(dannan 0.3 CONFIG)). Now: 0.3.0 and the shared
# percent-encoding (32f163b), until the next tag carries it.
set(LUGH_DANNAN_REPOSITORY "${CMAKE_CURRENT_SOURCE_DIR}/../dannan" CACHE PATH "Dannan's repository")
# Not a cache variable: a moved pin must take effect without clearing the build tree.
set(LUGH_DANNAN_REF "32f163b0727b58628c260f5706a67b9868448315")
# A sanitizer instruments Dannan too: half an instrumented process reports nothing true.
if (LUGH_SANITIZE STREQUAL "address")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif (LUGH_SANITIZE STREQUAL "thread")
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()
include(FetchContent)
FetchContent_Declare(dannan GIT_REPOSITORY "${LUGH_DANNAN_REPOSITORY}" GIT_TAG "${LUGH_DANNAN_REF}")
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
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
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

configure_file(lugh/include/lugh/version.h.in "${PROJECT_BINARY_DIR}/generated/lugh/version.h")

add_subdirectory(lugh)
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

install(TARGETS lugh-node RUNTIME DESTINATION bin)

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
