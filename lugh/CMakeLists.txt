#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# The library: the service minus its main(), linked by lugh-node, the tests and the fuzz
# targets. Listed, not globbed: a file added without a line here should fail to link, not
# be found by accident. Included from the repository root as "lugh/<subsystem>/x.h".
add_library(lugh STATIC
    api/audit_routes.cpp
    api/group_routes.cpp
    api/policy_routes.cpp
    api/user_routes.cpp
    audit/audit_log.cpp
    authn/authenticator.cpp
    authn/enrolment_links.cpp
    authn/factors.cpp
    authn/genesis.cpp
    authn/password_hash.cpp
    authn/passwords.cpp
    authn/policy.cpp
    authn/totp.cpp
    crypto/aead.cpp
    crypto/hmac.cpp
    directory/directory.cpp
    directory/records.cpp
    http/boost_json.cpp
    http/client_address.cpp
    http/health_routes.cpp
    http/http_server.cpp
    http/router.cpp
    http/tls_context.cpp
    keys/keyring.cpp
    keys/keyring_format.cpp
    keys/keyring_manager.cpp
    loggers/logger_scoped.cpp
    loggers/logger_stdio.cpp
    network/cidr.cpp
    node/config.cpp
    store/log_format.cpp
    store/sealed_store.cpp
    system/system_console.cpp
    system/system_environment.cpp
    system/system_files.cpp
)

target_include_directories(lugh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
)

target_link_libraries(lugh
    PUBLIC
        dannan
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        yaml-cpp::yaml-cpp
)

# Every source parses the same Boost headers before a line of ours; precompiling them is
# what keeps a build of many small files from being slower than a few large ones.
target_precompile_headers(lugh
    PRIVATE
        <boost/asio.hpp>
        <boost/beast.hpp>
        <boost/json.hpp>
)

lugh_flags(lugh)
