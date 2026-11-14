#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

# lugh_client (P10): what a relying party links to verify Lugh's tokens and speak to a Lugh
# cluster, exported as lugh::client. It depends on Dannan, Boost and OpenSSL and nothing of
# the node's, and it carries Boost.JSON's definitions for every target that links it (the maintainer,
# 2026-11-14), so they live in this library and not in an object library that would drop out.
add_library(lugh_client STATIC
    client/access_token.cpp
    client/api_client.cpp
    client/boost_json.cpp
    client/dpop.cpp
    client/https.cpp
    client/id_token.cpp
    client/jose.cpp
    client/key_source.cpp
    client/oauth_client.cpp
    client/testing.cpp
    client/verifier.cpp
)
add_library(lugh::client ALIAS lugh_client)

target_include_directories(lugh_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
)

target_link_libraries(lugh_client
    PUBLIC
        dannan::dannan
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

lugh_flags(lugh_client)

if (NOT LUGH_BUILD_NODE)
    return()
endif()

# The library: the service minus its main(), linked by lugh-node, the tests and the fuzz
# targets. Listed, not globbed: a file added without a line here should fail to link, not
# be found by accident. Included from the repository root as "lugh/<subsystem>/x.h".
add_library(lugh STATIC
    api/app_password_routes.cpp
    api/app_routes.cpp
    api/audit_routes.cpp
    api/key_routes.cpp
    api/ldap_routes.cpp
    api/me_routes.cpp
    api/group_routes.cpp
    api/policy_routes.cpp
    api/scope_routes.cpp
    api/session_routes.cpp
    api/user_routes.cpp
    apps/app.cpp
    apps/apps.cpp
    audit/audit_log.cpp
    authn/app_passwords.cpp
    authn/authenticator.cpp
    authn/enrolment_links.cpp
    authn/factors.cpp
    authn/genesis.cpp
    authn/password_hash.cpp
    authn/passwords.cpp
    authn/policy.cpp
    authn/totp.cpp
    crypto/aead.cpp
    directory/directory.cpp
    directory/records.cpp
    directory/posix_numbers.cpp
    http/client_address.cpp
    http/forms.cpp
    http/health_routes.cpp
    http/http_server.cpp
    http/outbound.cpp
    http/router.cpp
    http/tls_context.cpp
    ldap/authz.cpp
    ldap/ber.cpp
    ldap/connection.cpp
    ldap/dn.cpp
    ldap/filter.cpp
    ldap/ldap_server.cpp
    ldap/messages.cpp
    ldap/operations.cpp
    ldap/tree.cpp
    ldap/writes.cpp
    merge/record_merge.cpp
    keys/keyring.cpp
    keys/keyring_format.cpp
    keys/keyring_manager.cpp
    network/cidr.cpp
    scopes/grants.cpp
    scopes/scope.cpp
    scopes/topic_scope.cpp
    node/config.cpp
    oauth/client_auth.cpp
    oauth/consents.cpp
    oauth/device_grants.cpp
    oauth/dpop.cpp
    oauth/backchannel.cpp
    oauth/flow_routes.cpp
    oauth/logout_routes.cpp
    oauth/issuer.cpp
    oauth/metadata_routes.cpp
    oauth/refresh_tokens.cpp
    oauth/request.cpp
    store/log_format.cpp
    session/pre_sessions.cpp
    session/session_callers.cpp
    session/sessions.cpp
    signin/html.cpp
    signin/pages.cpp
    signin/qr.cpp
    store/sealed_store.cpp
    system/system_console.cpp
    system/system_files.cpp
    tokens/signing_keys.cpp
)

target_include_directories(lugh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
)

target_link_libraries(lugh
    PUBLIC
        lugh_client
        dannan::dannan
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
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
