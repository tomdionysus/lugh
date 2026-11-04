//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/apps/apps.h"

#include <algorithm>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/scopes/scope.h"

namespace lugh::apps {

namespace {

constexpr const char* kReadLate = "the applications were not read within the deadline";
constexpr const char* kChangeLate = "the applications did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);
constexpr std::size_t kIdBytes = 16;

std::string join_words(const std::vector<std::string>& words) {
  std::string out;
  for (const auto& word : words) out += (out.empty() ? "" : " ") + word;
  return out;
}

}  // namespace

Apps::Apps(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
           std::shared_ptr<audit::AuditLog> audit, Executor hashing, Settings settings)
    : _calls(std::move(store)), _wall(wall), _directory(std::move(directory)), _audit(std::move(audit)), _hashing(std::move(hashing)), _settings(settings) {}

Outcome<> Apps::references_ok(const std::vector<std::string>& registered, const std::string& own, const std::vector<std::string>& scopes,
                              const std::vector<std::string>& audiences) {
  const auto known = [&](std::string_view prefix) { return prefix == own || std::find(registered.begin(), registered.end(), prefix) != registered.end(); };
  for (const auto& scope : scopes) {
    const auto kind = scopes::grantable(scope);
    if (kind.ok() && kind.value == scopes::Kind::application && !known(*scopes::prefix_of(scope)))
      return Outcome<>::failure(Fault::invalid, "no registered api has the prefix of " + scope);
  }
  for (const auto& audience : audiences) {
    if (audience != scopes::kLughPrefix && !known(audience)) return Outcome<>::failure(Fault::invalid, "no registered api has the audience " + audience);
  }
  return Outcome<>::success();
}

void Apps::_read(std::string client_id, Executor executor, Done<Outcome<std::optional<App>>> done) const {
  using Answer = Outcome<std::optional<App>>;
  _calls.get_settled(kTable, client_id, std::move(executor), [client_id, done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    if (!record.value) return done(Answer::success(std::nullopt));
    auto app = decode(record.value->value);
    if (!app) return done(Answer::failure(Fault::failed, "the application " + client_id + " does not decode"));
    app->client_id = client_id;
    app->version = record.value->version;
    done(Answer::success(std::move(app)));
  });
}

void Apps::_all(Executor executor, Done<Outcome<std::vector<App>>> done) const {
  using Answer = Outcome<std::vector<App>>;
  _calls.list_settled(kTable, std::move(executor), [done = std::move(done)](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return done(Answer::from(records));
    std::vector<App> out;
    for (const auto& record : records.value) {
      auto app = decode(record.value);
      if (!app) return done(Answer::failure(Fault::failed, "the application " + record.key + " does not decode"));
      app->client_id = record.key;
      app->version = record.version;
      out.push_back(std::move(*app));
    }
    done(Answer::success(std::move(out)));
  });
}

void Apps::_new_secret(Executor executor, Done<Outcome<std::pair<Secret, ClientSecret>>> done) const {
  using Answer = Outcome<std::pair<Secret, ClientSecret>>;
  const auto raw = secure_random(kSecretBytes);
  if (raw.empty()) return done(Answer::failure(Fault::failed, "no randomness for a client secret"));
  auto secret = std::make_shared<Secret>(text_secret(encoding::base64url(raw)));
  on_pool(
      _hashing, [secret, costs = _settings.secret_costs] { return authn::hash_password(secret->reveal(), costs); }, executor,
      [secret, done = std::move(done)](Result<authn::PasswordHash> hashed) {
        if (!hashed.ok) return done(Answer::failure(Fault::failed, hashed.error));
        done(Answer::success({Secret(secret->reveal()), ClientSecret{std::move(hashed.value), 0}}));
      });
}

void Apps::create(audit::Actor actor, App draft, Deadline deadline, Executor executor, Done<Outcome<Made>> done) {
  using Answer = Outcome<Made>;
  auto answer = answering<Made>(deadline, executor, std::move(done), kChangeLate);
  if (!draft.client_id.empty() || !draft.secrets.empty() || !draft.access.empty() || !draft.roles.empty() || draft.state != State::enabled)
    return answer->finish(Answer::failure(Fault::invalid, "a new application has no client_id, secret, access or roles yet, and is enabled"));
  if (const auto ok = validate(draft, _settings.allow_client_secrets); !ok.ok()) return answer->finish(Answer::from(ok));

  auto self = shared_from_this();
  auto app = std::make_shared<App>(std::move(draft));
  _all(executor, [=](Outcome<std::vector<App>> all) {
    if (!all.ok()) return answer->finish(Answer::from(all));
    std::vector<std::string> registered;
    for (const auto& one : all.value) {
      if (!one.prefix.empty() && one.prefix == app->prefix)
        return answer->finish(Answer::failure(Fault::duplicate, "the scope prefix " + app->prefix + " is taken, or was, and is never used again"));
      if (one.kind == Kind::api && one.state != State::removed) registered.push_back(one.prefix);
    }
    auto scopes_and_own = app->scopes;
    scopes_and_own.insert(scopes_and_own.end(), app->client_scopes.begin(), app->client_scopes.end());
    if (const auto ok = references_ok(registered, app->prefix, scopes_and_own, app->audiences); !ok.ok()) return answer->finish(Answer::from(ok));

    // Not a secret: public, random so it cannot be guessed or reused.
    const auto id = dannan::identity::random_bytes(kIdBytes);
    if (id.empty()) return answer->finish(Answer::failure(Fault::failed, "no randomness for a client_id"));
    app->client_id = "app_" + encoding::base64url(id);
    app->created = app->updated = self->_wall.unix_ms() / 1000;

    const auto write = [=](std::optional<Secret> secret) {
      auto shown = std::make_shared<std::optional<Secret>>(std::move(secret));
      self->_put(actor, *app, 0, "app.create", app->name, executor, [answer, shown](Outcome<App> made) {
        if (!made.ok()) return answer->finish(Answer::from(made));
        answer->finish(Answer::success(Made{std::move(made.value), std::move(*shown)}));
      });
    };
    if (app->auth != ClientAuth::client_secret_basic) return write(std::nullopt);
    self->_new_secret(executor, [=](Outcome<std::pair<Secret, ClientSecret>> made) mutable {
      if (!made.ok()) return answer->finish(Answer::from(made));
      app->secrets = {std::move(made.value.second)};
      write(std::move(made.value.first));
    });
  });
}

void Apps::app(std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<App>>> done) const {
  using Answer = Outcome<std::optional<App>>;
  auto answer = answering<std::optional<App>>(deadline, executor, std::move(done), kReadLate);
  _read(std::move(client_id), executor, [answer](Answer found) {
    if (found.ok() && found.value && found.value->state == State::removed) found.value.reset();
    answer->finish(std::move(found));
  });
}

void Apps::apps(Deadline deadline, Executor executor, Done<Outcome<std::vector<App>>> done) const {
  using Answer = Outcome<std::vector<App>>;
  auto answer = answering<std::vector<App>>(deadline, executor, std::move(done), kReadLate);
  _all(executor, [answer](Answer all) {
    if (all.ok()) std::erase_if(all.value, [](const App& one) { return one.state == State::removed; });
    answer->finish(std::move(all));
  });
}

void Apps::prefixes(Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  _all(executor, [answer](Outcome<std::vector<App>> all) {
    if (!all.ok()) return answer->finish(Answer::from(all));
    std::vector<std::string> out;
    for (const auto& one : all.value) {
      if (one.kind == Kind::api && one.state != State::removed) out.push_back(one.prefix);
    }
    std::sort(out.begin(), out.end());
    answer->finish(Answer::success(std::move(out)));
  });
}

void Apps::_change(audit::Actor actor, std::string client_id, std::optional<std::uint64_t> expected, std::string action,
                   std::function<Outcome<bool>(App&, std::string& detail)> change, Executor executor, Done<Outcome<App>> done) {
  using Answer = Outcome<App>;
  auto self = shared_from_this();
  _read(client_id, executor, [=](Outcome<std::optional<App>> found) {
    if (!found.ok()) return done(Answer::from(found));
    if (!found.value || found.value->state == State::removed) return done(Answer::failure(Fault::not_found, "no such application"));
    if (expected && *expected != found.value->version) return done(Answer::failure(Fault::conflict, "the application has changed since it was read"));
    auto app = std::move(*found.value);
    const auto version = app.version;
    std::string detail;
    const auto changed = change(app, detail);
    if (!changed.ok()) return done(Answer::from(changed));
    if (!changed.value) return done(Answer::success(std::move(app)));
    app.updated = self->_wall.unix_ms() / 1000;
    self->_put(actor, std::move(app), version, action, detail, executor, done);
  });
}

void Apps::replace(audit::Actor actor, App changed, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor, Done<Outcome<App>> done) {
  using Answer = Outcome<App>;
  auto answer = answering<App>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  auto wanted = std::make_shared<App>(std::move(changed));
  // The references are checked against the registered apis first, then the change is made
  // against the version read.
  _all(executor, [=](Outcome<std::vector<App>> all) {
    if (!all.ok()) return answer->finish(Answer::from(all));
    std::vector<std::string> registered;
    for (const auto& one : all.value) {
      if (one.kind == Kind::api && one.state != State::removed) registered.push_back(one.prefix);
    }
    self->_change(
        actor, wanted->client_id, expected, "app.update",
        [=](App& app, std::string& detail) -> Outcome<bool> {
          if (wanted->state == State::removed) return Outcome<bool>::failure(Fault::invalid, "an application is removed with DELETE");
          App next = *wanted;
          next.client_id = app.client_id;
          next.version = app.version;
          next.kind = app.kind;
          next.prefix = app.prefix;
          next.secrets = app.secrets;
          next.access = app.access;
          next.roles = app.roles;
          next.created = app.created;
          next.updated = app.updated;
          // A secret is not made by changing the method: rotating it is its own route.
          if (next.auth == ClientAuth::client_secret_basic && app.auth != ClientAuth::client_secret_basic)
            return Outcome<bool>::failure(Fault::invalid, "to move to client_secret_basic, make a new application or ask for a secret");
          if (next.auth != ClientAuth::client_secret_basic) next.secrets.clear();
          if (const auto ok = validate(next, self->_settings.allow_client_secrets); !ok.ok()) return Outcome<bool>::from(ok);
          auto scopes_and_own = next.scopes;
          scopes_and_own.insert(scopes_and_own.end(), next.client_scopes.begin(), next.client_scopes.end());
          if (const auto ok = references_ok(registered, next.prefix, scopes_and_own, next.audiences); !ok.ok()) return Outcome<bool>::from(ok);
          if (encode(next) == encode(app)) return Outcome<bool>::success(false);
          detail = next.state == app.state ? "changed" : (next.state == State::disabled ? "disabled" : "enabled");
          app = std::move(next);
          return Outcome<bool>::success(true);
        },
        executor, [answer](Answer made) { answer->finish(std::move(made)); });
  });
}

void Apps::access_set(audit::Actor actor, std::string client_id, std::string group_id, bool allowed, Deadline deadline, Executor executor,
                      Done<Outcome<App>> done) {
  using Answer = Outcome<App>;
  auto answer = answering<App>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _directory->group(group_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> group) {
    if (!group.ok()) return answer->finish(Answer::from(group));
    if (!group.value && allowed) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    self->_change(
        actor, client_id, std::nullopt, allowed ? "app.access.add" : "app.access.remove",
        [=](App& app, std::string& detail) -> Outcome<bool> {
          const auto at = std::find(app.access.begin(), app.access.end(), group_id);
          if ((at != app.access.end()) == allowed) return Outcome<bool>::success(false);
          if (allowed) {
            if (app.access.size() >= kMostListed) return Outcome<bool>::failure(Fault::invalid, "access: at most 256 groups");
            app.access.push_back(group_id);
            std::sort(app.access.begin(), app.access.end());
          } else {
            app.access.erase(at);
          }
          detail = group_id;
          return Outcome<bool>::success(true);
        },
        executor, [answer](Answer made) { answer->finish(std::move(made)); });
  });
}

void Apps::roles_set(audit::Actor actor, std::string client_id, std::string group_id, std::vector<std::string> roles, Deadline deadline, Executor executor,
                     Done<Outcome<App>> done) {
  using Answer = Outcome<App>;
  auto answer = answering<App>(deadline, executor, std::move(done), kChangeLate);
  std::sort(roles.begin(), roles.end());
  roles.erase(std::unique(roles.begin(), roles.end()), roles.end());
  auto self = shared_from_this();
  _directory->group(group_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> group) {
    if (!group.ok()) return answer->finish(Answer::from(group));
    if (!group.value && !roles.empty()) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    self->_change(
        actor, client_id, std::nullopt, "app.roles.set",
        [=](App& app, std::string& detail) -> Outcome<bool> {
          auto at = std::find_if(app.roles.begin(), app.roles.end(), [&](const RoleMapping& one) { return one.group_id == group_id; });
          if (roles.empty()) {
            if (at == app.roles.end()) return Outcome<bool>::success(false);
            app.roles.erase(at);
          } else if (at != app.roles.end()) {
            if (at->roles == roles) return Outcome<bool>::success(false);
            at->roles = roles;
          } else {
            app.roles.push_back(RoleMapping{group_id, roles});
            std::sort(app.roles.begin(), app.roles.end(), [](const RoleMapping& a, const RoleMapping& b) { return a.group_id < b.group_id; });
          }
          if (const auto ok = validate(app, true); !ok.ok()) return Outcome<bool>::from(ok);
          detail = group_id + ": " + join_words(roles);
          return Outcome<bool>::success(true);
        },
        executor, [answer](Answer made) { answer->finish(std::move(made)); });
  });
}

void Apps::secret_rotate(audit::Actor actor, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<Made>> done) {
  using Answer = Outcome<Made>;
  auto answer = answering<Made>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _new_secret(executor, [=](Outcome<std::pair<Secret, ClientSecret>> made) {
    if (!made.ok()) return answer->finish(Answer::from(made));
    auto shown = std::make_shared<Secret>(Secret(made.value.first.reveal()));
    auto fresh = std::make_shared<ClientSecret>(made.value.second);
    self->_change(
        actor, client_id, std::nullopt, "app.secret.rotate",
        [=](App& app, std::string& detail) -> Outcome<bool> {
          if (app.auth != ClientAuth::client_secret_basic) return Outcome<bool>::failure(Fault::refused, "this application does not use a client secret");
          const auto now = self->_wall.unix_ms() / 1000;
          std::vector<ClientSecret> kept;
          for (auto& one : app.secrets) {
            // The current one keeps working for the overlap; one already rotated goes.
            if (one.expires == 0) kept.push_back(ClientSecret{one.hash, now + static_cast<std::uint64_t>(self->_settings.secret_overlap.count())});
          }
          kept.insert(kept.begin(), *fresh);
          app.secrets = std::move(kept);
          detail = "the previous secret works for " + std::to_string(self->_settings.secret_overlap.count()) + " seconds more";
          return Outcome<bool>::success(true);
        },
        executor,
        [answer, shown](Outcome<App> changed) {
          if (!changed.ok()) return answer->finish(Answer::from(changed));
          answer->finish(Answer::success(Made{std::move(changed.value), Secret(shown->reveal())}));
        });
  });
}

void Apps::remove(audit::Actor actor, std::string client_id, std::optional<std::uint64_t> expected, Deadline deadline, Executor executor,
                  Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  _change(
      actor, std::move(client_id), expected, "app.remove",
      [](App& app, std::string& detail) -> Outcome<bool> {
        app.state = State::removed;
        app.secrets.clear();
        detail = app.name;
        return Outcome<bool>::success(true);
      },
      executor, [answer](Outcome<App> removed) { answer->finish(removed.ok() ? Answer::success() : Answer::from(removed)); });
}

void Apps::_put(audit::Actor actor, App app, std::uint64_t expected, std::string action, std::string detail, Executor executor, Done<Outcome<App>> done) {
  using Answer = Outcome<App>;
  const auto client_id = app.client_id;
  _calls.put_settled(kTable, client_id, encode(app), expected, executor,
                     [audit = _audit, actor, app = std::move(app), action = std::move(action), detail = std::move(detail), executor,
                      done = std::move(done)](store::Write written) mutable {
                       if (!written.ok()) {
                         if (written.error == store::StoreError::duplicate)
                           return done(Answer::failure(Fault::duplicate, "the scope prefix " + app.prefix + " is taken, or was, and is never used again"));
                         return done(Answer::failure(directory::fault_of(written.error), written.message));
                       }
                       app.version = written.version;
                       const auto subject = app.client_id;
                       // A failure is logged by the audit log itself; the change has been made.
                       audit->record(audit::Event{std::move(action), actor.id, subject, actor.source, std::move(detail)}, kStepDeadline, executor,
                                     [app = std::move(app), done = std::move(done)](Status) mutable { done(Answer::success(std::move(app))); });
                     });
}

}  // namespace lugh::apps
