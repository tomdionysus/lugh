//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/policy.h"

#include <algorithm>

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
// A group's policy cleared: a removal would be final, and the group may set one again.
constexpr std::uint8_t kNone = 0;

}  // namespace

std::string_view acr(Assurance assurance) {
  switch (assurance) {
    case Assurance::pwd:
      return "urn:lugh:acr:pwd";
    case Assurance::mfa:
      return "urn:lugh:acr:mfa";
    case Assurance::phr:
      return "urn:lugh:acr:phr";
  }
  return "urn:lugh:acr:pwd";
}

std::optional<Assurance> assurance_from_acr(std::string_view text) {
  for (const auto level : {Assurance::pwd, Assurance::mfa, Assurance::phr}) {
    if (acr(level) == text) return level;
  }
  return std::nullopt;
}

Policies::Policies(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit)
    : _store(std::move(store)), _directory(std::move(directory)), _audit(std::move(audit)) {}

Task<Assurance> Policies::global() const { co_return (co_await _read("global")).value_or(kDefault); }

Task<Outcome<>> Policies::global_set(audit::Actor actor, Assurance level) { co_return co_await _write(std::move(actor), "global", level, "global"); }

Task<std::optional<Assurance>> Policies::group(std::string group_id) const { co_return co_await _read("group/" + group_id); }

Task<Outcome<>> Policies::group_set(audit::Actor actor, std::string group_id, std::optional<Assurance> level) {
  if (!co_await _directory->group(group_id)) co_return Outcome<>::failure(Fault::not_found, "no such group");
  co_return co_await _write(std::move(actor), "group/" + group_id, level, group_id);
}

Task<Assurance> Policies::required(std::string user_id) const {
  auto level = co_await global();
  for (const auto& group_id : co_await _directory->groups_of(std::move(user_id))) {
    if (const auto own = co_await group(group_id)) level = std::max(level, *own);
  }
  co_return level;
}

Task<std::optional<Assurance>> Policies::_read(std::string key) const {
  const auto record = co_await _store->get(kTable, std::move(key));
  if (!record || record->value.size() != 2 || record->value[0] != kFormat) co_return std::nullopt;
  const auto level = record->value[1];
  if (level < static_cast<std::uint8_t>(Assurance::pwd) || level > static_cast<std::uint8_t>(Assurance::phr)) co_return std::nullopt;
  co_return static_cast<Assurance>(level);
}

Task<Outcome<>> Policies::_write(audit::Actor actor, std::string key, std::optional<Assurance> level, std::string subject) {
  SecureBuffer value{kFormat, level ? static_cast<std::uint8_t>(*level) : kNone};
  const auto written = co_await _store->put(kTable, std::move(key), std::move(value));
  if (!written.ok()) co_return Outcome<>::failure(directory::fault_of(written.error), written.message);
  co_await _audit->record(audit::Event{"policy.set", actor.id, std::move(subject), actor.source, level ? std::string(acr(*level)) : "none"});
  co_return Outcome<>::success();
}

}  // namespace lugh::authn
