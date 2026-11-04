#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# One libFuzzer target per parser of untrusted bytes, <format>_fuzz.cpp, built only with
# LUGH_BUILD_FUZZING and a clang that ships libFuzzer. Apple's clang does not.
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-fsanitize=fuzzer LUGH_HAS_FUZZER)
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
