//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string_view>

#include "lugh/client/scopes.h"

// The checks a broker makes against a client's TopicGrants (lugh::client_topics). MQTT's topic
// rules (validity, matching, coverage and shared filters) are lir::mqtt's, the stack's one MQTT
// codec, so this library links it and lugh_client does not (the stack's placement plan, L3).
// Pure and from memory, like TopicGrants, so any thread may ask.
namespace lugh::client {

// Whether the grants let a client PUBLISH to `topic`: a `retain` grant for a retained message,
// a `pub` grant for any other. False for a topic that is not a valid MQTT topic name.
bool may_publish(const TopicGrants& grants, std::string_view topic, bool retained);

// Whether the grants let a client SUBSCRIBE to `filter`: some `sub` grant covers it, or the
// filter inside `$share/<group>/` for a shared one. False for a filter that is not valid.
bool may_subscribe(const TopicGrants& grants, std::string_view filter);

}  // namespace lugh::client
