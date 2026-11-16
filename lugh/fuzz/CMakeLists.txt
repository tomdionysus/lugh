#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# One libFuzzer target per parser of untrusted bytes, <format>_fuzz.cpp, built only with
# LUGH_BUILD_FUZZING and a clang that ships libFuzzer. Apple's clang does not.
# A fuzz target, compiled and linked: a plain flag check links a main() of its own, which
# libFuzzer's main collides with, so it fails even where libFuzzer is installed.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
check_cxx_source_compiles("
#include <cstddef>
#include <cstdint>
extern \"C\" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
" LUGH_HAS_FUZZER)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
if (NOT LUGH_HAS_FUZZER)
    message(FATAL_ERROR "LUGH_BUILD_FUZZING is on but ${CMAKE_CXX_COMPILER} has no libFuzzer (-fsanitize=fuzzer)")
endif()

function(lugh_fuzz_target name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE lugh)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    lugh_flags(${name})

    # A short run under ctest, so a target that no longer builds or crashes at once is
    # caught like any other test. Campaigns run the binary by hand.
    add_test(NAME fuzz_${name} COMMAND ${name} -runs=2000 -max_total_time=10)
endfunction()

lugh_fuzz_target(fuzz_keyring keyring_fuzz.cpp)
lugh_fuzz_target(fuzz_store_log store_log_fuzz.cpp)
lugh_fuzz_target(fuzz_records records_fuzz.cpp)
lugh_fuzz_target(fuzz_api_request api_request_fuzz.cpp)
lugh_fuzz_target(fuzz_scope scope_fuzz.cpp)
lugh_fuzz_target(fuzz_jws jws_fuzz.cpp)
lugh_fuzz_target(fuzz_client client_fuzz.cpp)
lugh_fuzz_target(fuzz_form form_fuzz.cpp)
lugh_fuzz_target(fuzz_ber ber_fuzz.cpp)
lugh_fuzz_target(fuzz_filter filter_fuzz.cpp)
lugh_fuzz_target(fuzz_dn dn_fuzz.cpp)
lugh_fuzz_target(fuzz_envelope envelope_fuzz.cpp)
lugh_fuzz_target(fuzz_webauthn webauthn_fuzz.cpp)
