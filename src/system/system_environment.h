#pragma once

#include "system/environment.h"

namespace lugh::system {

class SystemEnvironment : public Environment {
 public:
  std::optional<std::string> get(const std::string& name) const override;
};

}  // namespace lugh::system
