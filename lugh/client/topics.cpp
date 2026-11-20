//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/topics.h"

#include <algorithm>
#include <string>

#include "lir/mqtt/topic.h"

namespace lugh::client {

bool may_publish(const TopicGrants& grants, std::string_view topic, bool retained) {
  if (!lir::mqtt::valid_topic_name(topic)) return false;
  const auto& granted = retained ? grants.retain() : grants.publish();
  return std::ranges::any_of(granted, [&](const std::string& filter) { return lir::mqtt::matches(filter, topic); });
}

bool may_subscribe(const TopicGrants& grants, std::string_view filter) {
  std::string inner{filter};
  if (lir::mqtt::is_shared(filter)) {
    auto shared = lir::mqtt::parse_shared(filter);
    if (!shared) return false;
    inner = std::move(shared->filter);
  }
  if (!lir::mqtt::valid_topic_filter(inner)) return false;
  return std::ranges::any_of(grants.subscribe(), [&](const std::string& granted) { return lir::mqtt::covers(granted, inner); });
}

}  // namespace lugh::client
