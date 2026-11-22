//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/authz.h"

#include <algorithm>
#include <chrono>

namespace lugh::ldap {

namespace {

constexpr Deadline kStepDeadline = std::chrono::seconds(30);
// One message for every refusal: RFC 4513 section 6.1 asks that a client learn no more than this.
constexpr const char* kRefused = "invalid credentials";

BindAnswer refused() { return BindAnswer{{ResultCode::invalid_credentials, "", kRefused}, std::nullopt}; }
BindAnswer unavailable() { return BindAnswer{{ResultCode::unavailable, "", "the request could not be completed"}, std::nullopt}; }

std::vector<std::string> cut_to(const std::vector<std::string>& wanted, const std::vector<std::string>& held) {
  std::vector<std::string> out;
  for (const auto& scope : wanted) {
    if (std::find(held.begin(), held.end(), scope) != held.end()) out.push_back(scope);
  }
  return out;
}

}  // namespace

bool password_alone_enough(const authn::Step& step) {
  if (step.kind != authn::Step::Kind::next) return false;
  const auto& reached = step.sign_in;
  return reached.stage == authn::SignIn::Stage::complete || (reached.stage == authn::SignIn::Stage::second_factor && reached.required == authn::Assurance::pwd);
}

Binder::Binder(std::shared_ptr<Tree> tree, std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Authenticator> authenticator,
               std::shared_ptr<authn::AppPasswords> app_passwords, std::shared_ptr<scopes::Grants> grants, std::shared_ptr<audit::AuditLog> audit)
    : _tree(std::move(tree)),
      _directory(std::move(directory)),
      _authenticator(std::move(authenticator)),
      _app_passwords(std::move(app_passwords)),
      _grants(std::move(grants)),
      _audit(std::move(audit)) {}

void Binder::bind(std::string name, Secret password, std::string address, Deadline deadline, Executor executor, Done<BindAnswer> done) {
  auto answer = Completion<BindAnswer>::start(deadline, executor, std::move(done), [] { return unavailable(); });
  auto held = std::make_shared<Secret>(std::move(password));

  // A name that cannot be anyone's is still a guess at someone's, and costs what one does.
  const auto parsed = parse_dn(name);
  const auto place = parsed ? _tree->locate(*parsed) : Place{};
  const bool person = place.kind == Place::Kind::person;
  const bool service = place.kind == Place::Kind::service;
  const auto login = person || service ? place.name : "?" + name;

  auto self = shared_from_this();
  // RFC 4513 section 5.1.2: never taken for an anonymous bind.
  if (held->reveal().empty()) return answer->finish(BindAnswer{{ResultCode::inappropriate_authentication, "", "a bind needs a password"}, std::nullopt});
  if (!person && !service) return _password(login, name, held, address, executor, answer);

  _directory->user_by_name(place.name, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(unavailable());
    const auto wanted = service ? directory::Kind::service : directory::Kind::person;
    auto user = found.value;
    // Under the wrong container is no such entry, and the same refusal as any other.
    if (user && user->kind != wanted) user.reset();

    auto shaped = authn::AppPasswords::normal(secret_text(*held));
    if (!user) return self->_password("?" + name, name, held, address, executor, answer);
    if (!shaped) return self->_password(login, self->_tree->dn_of(*user), held, address, executor, answer);

    // A waiting account costs nothing, and an app password is no way round the wait.
    if (self->_authenticator->waiting_for(user->id, "ldap:" + address)) return answer->finish(refused());
    self->_app_passwords->verify(user->id, std::move(*shaped), address, kStepDeadline, executor, [=](Outcome<authn::AppPasswordMatch> match) {
      if (undecided(match.fault)) return answer->finish(unavailable());
      if (!match.ok()) return self->_password(login, self->_tree->dn_of(*user), held, address, executor, answer);
      self->_grants->effective(user->id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> held_scopes) {
        if (!held_scopes.ok()) return answer->finish(unavailable());
        Bound bound;
        bound.dn = self->_tree->dn_of(*user);
        // A simple bind is a password, whichever kind: pwd.
        bound.caller = http::Caller{http::Caller::Kind::user, user->id, cut_to(match.value.app_password.scopes, held_scopes.value),
                                    std::string(authn::acr(authn::Assurance::pwd))};
        bound.app_password = match.value.app_password.id;
        bound.app_password_scopes = match.value.app_password.scopes;
        self->_audit->record(audit::Event{"ldap.bind", user->id, user->id, "ldap:" + address, "app password " + match.value.app_password.id}, kStepDeadline,
                             executor, [answer, bound](Status) { answer->finish(BindAnswer{{ResultCode::success, "", ""}, bound}); });
      });
    });
  });
}

void Binder::_password(std::string name, std::string dn, std::shared_ptr<Secret> password, std::string address, Executor executor,
                       std::shared_ptr<Completion<BindAnswer>> answer) {
  auto self = shared_from_this();
  _authenticator->password(std::move(name), std::move(*password), "ldap:" + address, kStepDeadline, executor, [=](authn::Step step) {
    if (step.kind == authn::Step::Kind::failed) return answer->finish(unavailable());
    if (!password_alone_enough(step)) return answer->finish(refused());
    const auto user_id = step.sign_in.user_id;
    self->_grants->effective(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> scopes) {
      if (!scopes.ok()) return answer->finish(unavailable());
      Bound bound;
      bound.dn = dn;
      bound.caller = http::Caller{http::Caller::Kind::user, user_id, scopes.value, std::string(authn::acr(authn::Assurance::pwd))};
      answer->finish(BindAnswer{{ResultCode::success, "", ""}, bound});
    });
  });
}

void Binder::current(Bound bound, Deadline deadline, Executor executor, Done<Outcome<std::optional<Bound>>> done) const {
  using Answer = Outcome<std::optional<Bound>>;
  auto answer = Completion<Answer>::start(deadline, executor, std::move(done),
                                          [] { return Answer::failure(Fault::timed_out, "the bound user could not be read in time"); });
  auto self = shared_from_this();
  const auto user_id = bound.caller.id;
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer->finish(Answer::from(user));
    if (!user.value || user.value->disabled) return answer->finish(Answer::success(std::nullopt));
    const auto with_scopes = [=] {
      self->_grants->effective(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> scopes) {
        if (!scopes.ok()) return answer->finish(Answer::from(scopes));
        auto out = bound;
        out.dn = self->_tree->dn_of(*user.value);
        out.caller.scopes = bound.app_password ? cut_to(bound.app_password_scopes, scopes.value) : scopes.value;
        answer->finish(Answer::success(std::move(out)));
      });
    };
    if (!bound.app_password) return with_scopes();
    self->_app_passwords->list(user_id, kStepDeadline, executor, [=](Outcome<std::vector<authn::AppPasswordInfo>> listed) {
      if (!listed.ok()) return answer->finish(Answer::from(listed));
      const auto kept = std::any_of(listed.value.begin(), listed.value.end(), [&](const authn::AppPasswordInfo& one) { return one.id == *bound.app_password; });
      if (!kept) return answer->finish(Answer::success(std::nullopt));
      with_scopes();
    });
  });
}

}  // namespace lugh::ldap
