#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# One binary, lugh_tests, flat: <subsystem>_<thing>_test.cpp, with header-only fixtures
# in lugh/test/fixtures/, included as "lugh/test/fixtures/x.h".
add_executable(lugh_tests
    api_app_routes_test.cpp
    api_audit_routes_test.cpp
    api_concurrency_test.cpp
    api_group_routes_test.cpp
    api_policy_routes_test.cpp
    api_scope_routes_test.cpp
    api_user_routes_test.cpp
    apps_app_test.cpp
    apps_test.cpp
    audit_log_test.cpp
    authn_authenticator_test.cpp
    authn_backoff_test.cpp
    authn_enrolment_links_test.cpp
    authn_factors_test.cpp
    authn_genesis_test.cpp
    authn_passwords_test.cpp
    authn_policy_test.cpp
    authn_totp_test.cpp
    core_async_test.cpp
    core_encoding_test.cpp
    core_completion_test.cpp
    core_secret_test.cpp
    crypto_aead_test.cpp
    crypto_argon2_test.cpp
    directory_records_test.cpp
    directory_test.cpp
    http_client_address_test.cpp
    http_health_routes_test.cpp
    http_rate_limiter_test.cpp
    http_router_test.cpp
    http_server_test.cpp
    http_tls_context_test.cpp
    keys_keyring_format_test.cpp
    keys_keyring_manager_test.cpp
    keys_keyring_test.cpp
    network_cidr_test.cpp
    scopes_grants_test.cpp
    scopes_scope_test.cpp
    scopes_topic_scope_test.cpp
    node_cli_test.cpp
    node_config_test.cpp
    node_ioc_check_test.cpp
    node_process_api_test.cpp
    node_process_init_test.cpp
    node_process_shutdown_test.cpp
    store_async_test.cpp
    store_contract_test.cpp
    store_log_format_test.cpp
    store_sealed_store_test.cpp
    system_files_test.cpp
)

target_link_libraries(lugh_tests PRIVATE lugh GTest::gtest_main)
if (LUGH_SANITIZE STREQUAL "address")
    target_sources(lugh_tests PRIVATE sanitizer_options.cpp)
endif()
# Tests write only inside the build tree (Dannan's TempDir).
target_compile_definitions(lugh_tests PRIVATE DANNAN_TEST_TEMP_ROOT="${PROJECT_BINARY_DIR}/test-tmp")
# The IoC check reads the source tree.
target_compile_definitions(lugh_tests PRIVATE LUGH_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
# The process tests (node_process_*) run the real lugh-node, built first. Dannan's
# ChildProcess puts a child on a pseudo-terminal, which is libutil's on Linux.
add_dependencies(lugh_tests lugh-node)
target_compile_definitions(lugh_tests PRIVATE LUGH_NODE_BINARY="$<TARGET_FILE:lugh-node>")
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(lugh_tests PRIVATE util)
endif()
target_precompile_headers(lugh_tests
    PRIVATE
        <boost/asio.hpp>
        <boost/beast.hpp>
        <boost/json.hpp>
        <gtest/gtest.h>
)
lugh_flags(lugh_tests)
