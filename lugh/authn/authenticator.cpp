//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/authenticator.h"

#include "lugh/core/steps.h"

namespace lugh::authn {

namespace {

std::string account_key(std::string_view login) { return "account:" + std::string(login); }
std::string address_key(std::string_view source) { return "address:" + std::string(source); }

Step waiting(std::chrono::seconds wait, SignIn sign_in = {}) {
  auto step = Step::of(Step::Kind::wait, std::move(sign_in));
  step.retry_after = wait;
  return step;
}

}  // namespace

Authenticator::Authenticator(std::shared_ptr<dannan::status::LogSink> log, const dannan::contract::TimeSource& time,
                             std::shared_ptr<directory::Directory> directory, std::shared_ptr<Passwords> passwords, std::shared_ptr<Factors> factors,
                             std::shared_ptr<Policies> policies, std::shared_ptr<EnrolmentLinks> links, std::shared_ptr<audit::AuditLog> audit,
                             Settings settings)
    : _logger(std::move(log), "authn"),
      _time(time),
      _directory(std::move(directory)),
      _passwords(std::move(passwords)),
      _factors(std::move(factors)),
      _policies(std::move(policies)),
      _links(std::move(links)),
      _audit_log(std::move(audit)),
      _settings(std::move(settings)),
      _accounts(_settings.account),
      _addresses(_settings.address) {}

namespace {

// What each component is given for one step of a sign-in.
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

// A step's one answer: `failed` when the deadline passes.
std::shared_ptr<Completion<Step>> stepping(Deadline deadline, Executor executor, Done<Step> done) {
  return Completion<Step>::start(deadline, std::move(executor), std::move(done), [] { return Step::of(Step::Kind::failed); });
}

Done<Step> to(std::shared_ptr<Completion<Step>> answer) {
  return [answer](Step step) { answer->finish(std::move(step)); };
}

}  // namespace

void Authenticator::password(std::string login, Secret password, std::string source, Deadline deadline, Executor executor, Done<Step> done,
                             Assurance at_least) {
  auto answer = stepping(deadline, executor, std::move(done));
  // Held where every step can reach it: a Secret is not copied.
  auto held = std::make_shared<Secret>(std::move(password));
  auto self = shared_from_this();
  _directory->user_by_login(login, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(Step::of(Step::Kind::failed));
    const auto user = found.value;
    // An unknown name backs off under its own key, as a real one would, so the answers to
    // guesses at names and at passwords look the same.
    const auto account = account_key(user ? user->id : "?" + login);
    const auto address = address_key(source);

    // Before any hashing: a waiting caller costs nothing.
    if (const auto wait = self->_waiting(account, address)) return answer->finish(waiting(*wait));

    // Once the user, and whether they may go on, are known.
    const auto then_factor = [=](SignIn sign_in) {
      self->_factors->has_second_factor(user->id, kStepDeadline, executor, [=](Outcome<bool> has_factor) mutable {
        if (!has_factor.ok()) return answer->finish(Step::of(Step::Kind::failed));
        if (!user->enrolled || (!has_factor.value && sign_in.required > Assurance::pwd)) {
          // Enrolment starts from a link, never from a password alone, or a stolen password
          // would be enough to enrol the thief's own authenticator.
          return self->_record("signin.password.refused", "anonymous", user->id, source, "not enrolled", executor,
                               [answer] { answer->finish(Step::of(Step::Kind::refused)); });
        }
        self->_record("signin.password.accepted", user->id, user->id, source, {}, executor, [=]() mutable {
          if (!has_factor.value) return self->_complete(std::move(sign_in), source, executor, to(answer));
          sign_in.stage = SignIn::Stage::second_factor;
          answer->finish(Step::of(Step::Kind::next, std::move(sign_in)));
        });
      });
    };

    const auto judged = [=](bool right) {
      std::string why;
      if (!user) {
        why = "unknown";
      } else if (user->kind != directory::Kind::person) {
        why = "a service";
      } else if (user->disabled) {
        why = "disabled";
      } else if (!right) {
        why = "wrong password";
      }
      if (!why.empty()) {
        self->_failed(account, address);
        // Whoever typed it is not known to be the user.
        return self->_record("signin.password.refused", "anonymous", user ? user->id : "", source, why, executor,
                             [answer] { answer->finish(Step::of(Step::Kind::refused)); });
      }
      self->_accounts.succeeded(account);

      self->_policies->required(user->id, kStepDeadline, executor, [=](Outcome<Assurance> required) {
        if (!required.ok()) return answer->finish(Step::of(Step::Kind::failed));
        SignIn sign_in;
        sign_in.user_id = user->id;
        sign_in.required = std::max(required.value, at_least);
        sign_in.started = self->_time.now();
        sign_in.amr = {"pwd"};
        if (user->enrolled) return then_factor(std::move(sign_in));
        self->_links->first_sign_in_allowed(user->id, kStepDeadline, executor, [=](Outcome<bool> allowed) mutable {
          if (!allowed.ok()) return answer->finish(Step::of(Step::Kind::failed));
          if (!allowed.value) return then_factor(std::move(sign_in));
          // Root's first sign-in, with the password genesis made.
          sign_in.stage = SignIn::Stage::enrolment;
          self->_record("signin.password.accepted", user->id, user->id, source, "first sign-in", executor,
                        [answer, sign_in] { answer->finish(Step::of(Step::Kind::next, sign_in)); });
        });
      });
    };

    // The password is checked whatever else is wrong, so the time taken says nothing.
    if (user) {
      return self->_passwords->verify(user->id, Secret(held->reveal()), kStepDeadline, executor, [=](Outcome<bool> right) {
        if (!right.ok()) return answer->finish(Step::of(Step::Kind::failed));
        judged(right.value);
      });
    }
    self->_passwords->spend(Secret(held->reveal()), kStepDeadline, executor, [=](Outcome<>) { judged(false); });
  });
}

void Authenticator::totp(SignIn sign_in, std::string code, std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  if (!_live(sign_in, SignIn::Stage::second_factor)) return answer->finish(Step::of(Step::Kind::ended, std::move(sign_in)));
  // A code is not phishing-resistant: where phr is required, only a WebAuthn credential will do.
  if (sign_in.required == Assurance::phr) return _code_refused(std::move(sign_in), source, "signin.totp.refused", executor, to(answer));
  const auto account = account_key(sign_in.user_id);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) return answer->finish(waiting(*wait, std::move(sign_in)));

  auto self = shared_from_this();
  _factors->totp_check(sign_in.user_id, std::move(code), kStepDeadline, executor, [=](Outcome<> checked) mutable {
    if (checked.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed, std::move(sign_in)));
    if (!checked.ok()) {
      self->_failed(account, address);
      return self->_code_refused(std::move(sign_in), source, "signin.totp.refused", executor, to(answer));
    }
    self->_accounts.succeeded(account);
    sign_in.amr.push_back("otp");
    self->_complete(std::move(sign_in), source, executor, to(answer));
  });
}

void Authenticator::recovery(SignIn sign_in, Secret code, std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  if (!_live(sign_in, SignIn::Stage::second_factor)) return answer->finish(Step::of(Step::Kind::ended, std::move(sign_in)));
  if (sign_in.required == Assurance::phr) return _code_refused(std::move(sign_in), source, "signin.recovery.refused", executor, to(answer));
  const auto account = account_key(sign_in.user_id);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) return answer->finish(waiting(*wait, std::move(sign_in)));

  auto self = shared_from_this();
  _factors->recovery_use(sign_in.user_id, std::move(code), kStepDeadline, executor, [=](Outcome<std::size_t> used) mutable {
    if (used.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed, std::move(sign_in)));
    if (!used.ok()) {
      self->_failed(account, address);
      return self->_code_refused(std::move(sign_in), source, "signin.recovery.refused", executor, to(answer));
    }
    self->_accounts.succeeded(account);
    const auto left = used.value;
    self->_record("signin.recovery.used", sign_in.user_id, sign_in.user_id, source, std::to_string(left) + " left", executor, [=]() mutable {
      sign_in.amr.push_back("otp");
      self->_complete(std::move(sign_in), source, executor, [answer, left](Step step) {
        step.recovery_left = left;
        answer->finish(std::move(step));
      });
    });
  });
}

void Authenticator::redeem(Secret token, Secret password, std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  const auto address = address_key(source);
  if (const auto wait = _addresses.wait(address, _time.now())) return answer->finish(waiting(*wait));

  // Held where every step can reach them: a Secret is not copied.
  auto link = std::make_shared<Secret>(std::move(token));
  auto chosen = std::make_shared<Secret>(std::move(password));
  auto self = shared_from_this();

  const auto refused = [=](const std::optional<directory::User>& user, bool linked) {
    self->_addresses.failed(address, self->_time.now());
    self->_record("enrolment.refused", "anonymous", user ? user->id : "", source, linked ? "the user cannot enrol" : "no such link", executor,
                  [answer] { answer->finish(Step::of(Step::Kind::refused)); });
  };

  _links->peek(Secret(link->reveal()), kStepDeadline, executor, [=](Outcome<std::string> peeked) {
    if (peeked.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed));
    if (!peeked.ok()) return refused(std::nullopt, false);
    self->_directory->user(peeked.value, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
      if (!found.ok()) return answer->finish(Step::of(Step::Kind::failed));
      const auto user = found.value;
      if (!user || user->disabled || user->enrolled || user->kind != directory::Kind::person) return refused(user, true);

      // The password first: one that is refused must not cost the person their link.
      if (const auto acceptable = self->_passwords->acceptable(*chosen, *user); !acceptable.ok()) return answer->finish(Step::of(Step::Kind::refused));

      const audit::Actor actor{user->id, source};
      self->_links->spend(Secret(link->reveal()), actor, kStepDeadline, executor, [=](Outcome<std::string> spent) {
        if (!spent.ok()) return answer->finish(Step::of(spent.fault == Fault::failed ? Step::Kind::failed : Step::Kind::refused));
        self->_passwords->set(actor, *user, Secret(chosen->reveal()), kStepDeadline, executor, [=](Outcome<> set) {
          if (!set.ok()) {
            self->_logger.error("enrolment of " + user->id + ": the link is spent and the password was not set: " + set.message);
            return answer->finish(Step::of(Step::Kind::failed));
          }
          self->_policies->required(user->id, kStepDeadline, executor, [=](Outcome<Assurance> required) {
            if (!required.ok()) return answer->finish(Step::of(Step::Kind::failed));
            SignIn sign_in;
            sign_in.user_id = user->id;
            sign_in.stage = SignIn::Stage::enrolment;
            sign_in.required = required.value;
            sign_in.started = self->_time.now();
            sign_in.amr = {"pwd"};
            answer->finish(Step::of(Step::Kind::next, std::move(sign_in)));
          });
        });
      });
    });
  });
}

void Authenticator::enrol_begin(SignIn sign_in, std::string source, Deadline deadline, Executor executor, Done<Outcome<TotpSetup>> done) {
  using Answer = Outcome<TotpSetup>;
  auto answer = answering<TotpSetup>(deadline, executor, std::move(done), "enrolment did not answer within the deadline");
  if (!_live(sign_in, SignIn::Stage::enrolment)) return answer->finish(Answer::failure(Fault::refused, "the sign-in is over"));
  auto self = shared_from_this();
  _directory->user(sign_in.user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    const auto& user = *found.value;
    self->_factors->totp_begin(audit::Actor{user.id, source}, user.id, self->_settings.issuer, user.name, kStepDeadline, executor,
                               [answer](Answer setup) { answer->finish(std::move(setup)); });
  });
}

void Authenticator::enrol_confirm(SignIn sign_in, std::string factor_id, std::string code, std::string source, Deadline deadline, Executor executor,
                                  Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  if (!_live(sign_in, SignIn::Stage::enrolment)) return answer->finish(Step::of(Step::Kind::ended, std::move(sign_in)));
  const audit::Actor actor{sign_in.user_id, source};
  auto self = shared_from_this();
  _factors->totp_confirm(actor, sign_in.user_id, std::move(factor_id), std::move(code), kStepDeadline, executor, [=](Outcome<> confirmed) mutable {
    if (confirmed.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed, std::move(sign_in)));
    if (!confirmed.ok()) return self->_code_refused(std::move(sign_in), source, "enrolment.totp.refused", executor, to(answer));
    sign_in.amr.push_back("otp");
    self->_enrolled(std::move(sign_in), source, executor, to(answer));
  });
}

namespace {

// RFC 8176's methods for a WebAuthn ceremony: a synced passkey is a software key, any other a
// hardware one; "user" when the authenticator verified the user.
void push_webauthn_methods(SignIn& sign_in, bool backed_up, bool user_verified) {
  sign_in.amr.push_back(backed_up ? "swk" : "hwk");
  if (user_verified) sign_in.amr.push_back("user");
}

}  // namespace

void Authenticator::webauthn(SignIn sign_in, std::string credential_id, webauthn::Expected expected, Bytes client_data_json, Bytes authenticator_data,
                             Bytes signature, std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  if (!_live(sign_in, SignIn::Stage::second_factor)) return answer->finish(Step::of(Step::Kind::ended, std::move(sign_in)));
  const auto account = account_key(sign_in.user_id);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) return answer->finish(waiting(*wait, std::move(sign_in)));

  auto self = shared_from_this();
  _factors->webauthn_check(sign_in.user_id, std::move(expected), std::move(credential_id), std::move(client_data_json), std::move(authenticator_data),
                           std::move(signature), kStepDeadline, executor, [=](Outcome<webauthn::Asserted> checked) mutable {
                             if (checked.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed, std::move(sign_in)));
                             if (!checked.ok()) {
                               self->_failed(account, address);
                               return self->_code_refused(std::move(sign_in), source, "signin.webauthn.refused", executor, to(answer));
                             }
                             self->_accounts.succeeded(account);
                             push_webauthn_methods(sign_in, checked.value.backed_up, checked.value.user_verified);
                             self->_complete(std::move(sign_in), source, executor, to(answer));
                           });
}

void Authenticator::passkey(std::string user_handle, std::string credential_id, webauthn::Expected expected, Bytes client_data_json, Bytes authenticator_data,
                            Bytes signature, std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  // A passkey stands for the password too, so the user must have been verified.
  expected.user_verification = true;
  // An unknown handle backs off under its own key, as an unknown name does.
  const auto account = account_key(user_handle.empty() ? "?" : user_handle);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) return answer->finish(waiting(*wait));

  auto self = shared_from_this();
  const auto refused = [=](std::string subject, std::string why) {
    self->_failed(account, address);
    self->_record("signin.passkey.refused", "anonymous", std::move(subject), source, std::move(why), executor,
                  [answer] { answer->finish(Step::of(Step::Kind::refused)); });
  };
  _directory->user(user_handle, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(Step::of(Step::Kind::failed));
    const auto user = found.value;
    if (!user) return refused("", "unknown");
    if (user->kind != directory::Kind::person) return refused(user->id, "a service");
    if (user->disabled) return refused(user->id, "disabled");
    if (!user->enrolled) return refused(user->id, "not enrolled");
    self->_factors->webauthn_check(user->id, expected, credential_id, client_data_json, authenticator_data, signature, kStepDeadline, executor,
                                   [=](Outcome<webauthn::Asserted> checked) {
                                     if (checked.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed));
                                     if (!checked.ok()) return refused(user->id, checked.message);
                                     self->_accounts.succeeded(account);
                                     self->_policies->required(user->id, kStepDeadline, executor, [=](Outcome<Assurance> required) {
                                       if (!required.ok()) return answer->finish(Step::of(Step::Kind::failed));
                                       SignIn sign_in;
                                       sign_in.user_id = user->id;
                                       sign_in.required = required.value;
                                       sign_in.started = self->_time.now();
                                       push_webauthn_methods(sign_in, checked.value.backed_up, checked.value.user_verified);
                                       self->_complete(std::move(sign_in), source, executor, to(answer));
                                     });
                                   });
  });
}

void Authenticator::enrol_webauthn(SignIn sign_in, std::string name, webauthn::Expected expected, Bytes client_data_json, Bytes attestation_object,
                                   std::string source, Deadline deadline, Executor executor, Done<Step> done) {
  auto answer = stepping(deadline, executor, std::move(done));
  if (!_live(sign_in, SignIn::Stage::enrolment)) return answer->finish(Step::of(Step::Kind::ended, std::move(sign_in)));
  const audit::Actor actor{sign_in.user_id, source};
  // Required, so the ceremony refused anything the authenticator did not verify.
  const bool verified = expected.user_verification;
  auto self = shared_from_this();
  _factors->webauthn_register(actor, sign_in.user_id, std::move(name), std::move(expected), std::move(client_data_json), std::move(attestation_object),
                              kStepDeadline, executor, [=](Outcome<FactorInfo> registered) mutable {
                                if (registered.fault == Fault::failed) return answer->finish(Step::of(Step::Kind::failed, std::move(sign_in)));
                                if (!registered.ok())
                                  return self->_code_refused(std::move(sign_in), source, "enrolment.webauthn.refused", executor, to(answer));
                                push_webauthn_methods(sign_in, registered.value.backed_up, verified);
                                self->_enrolled(std::move(sign_in), source, executor, to(answer));
                              });
}

void Authenticator::_enrolled(SignIn sign_in, std::string source, Executor executor, Done<Step> done) {
  const audit::Actor actor{sign_in.user_id, source};
  auto self = shared_from_this();
  _factors->recovery_generate(actor, sign_in.user_id, kStepDeadline, executor, [=](Outcome<std::vector<Secret>> codes) mutable {
    if (!codes.ok()) return done(Step::of(Step::Kind::failed, std::move(sign_in)));
    auto kept = std::make_shared<std::vector<Secret>>(std::move(codes.value));
    self->_directory->enrolled_set(actor, sign_in.user_id, true, kStepDeadline, executor, [=](Outcome<directory::User> enrolled) mutable {
      if (!enrolled.ok()) return done(Step::of(Step::Kind::failed, std::move(sign_in)));
      self->_links->first_sign_in_spend(sign_in.user_id, kStepDeadline, executor, [=](Outcome<>) mutable {
        self->_complete(std::move(sign_in), source, executor, [done, kept](Step step) {
          step.recovery_codes = std::move(*kept);
          done(std::move(step));
        });
      });
    });
  });
}

void Authenticator::remove_factor(audit::Actor actor, std::string user_id, std::string factor_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), "the factor was not removed within the deadline; it may yet be");
  auto self = shared_from_this();
  _factors->list(user_id, kStepDeadline, executor, [=](Outcome<std::vector<FactorInfo>> factors) {
    if (!factors.ok()) return answer->finish(Answer::from(factors));
    const FactorInfo* target = nullptr;
    // A second factor of their own: a confirmed TOTP secret or a WebAuthn credential.
    const auto second = [](const FactorInfo& factor) { return factor.confirmed && (factor.kind == FactorKind::totp || factor.kind == FactorKind::webauthn); };
    std::size_t seconds = 0;
    for (const auto& factor : factors.value) {
      if (factor.id == factor_id) target = &factor;
      if (second(factor)) ++seconds;
    }
    if (target == nullptr) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));

    const auto removing = [=] {
      self->_factors->remove(actor, user_id, factor_id, kStepDeadline, executor, [answer](Answer removed) { answer->finish(std::move(removed)); });
    };
    const bool last = second(*target) && seconds == 1;
    if (!last) return removing();
    self->_policies->required(user_id, kStepDeadline, executor, [=](Outcome<Assurance> required) {
      if (!required.ok()) return answer->finish(Answer::from(required));
      if (required.value > Assurance::pwd)
        return answer->finish(Answer::failure(Fault::refused, "the user's last second factor cannot be removed while their policy requires one"));
      removing();
    });
  });
}

void Authenticator::reset_factors(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), "the reset did not finish within the deadline; it may yet");
  auto self = shared_from_this();
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    const auto id = found.value->id;
    // Not enrolled first: if removing the factors then fails, the user is already held at
    // enrolment and cannot sign in on what is left.
    self->_directory->enrolled_set(actor, id, false, kStepDeadline, executor, [=](Outcome<directory::User> unenrolled) {
      if (!unenrolled.ok()) return answer->finish(Answer::from(unenrolled));
      self->_factors->forget(actor, id, kStepDeadline, executor, [answer](Status forgotten) {
        if (!forgotten.ok) return answer->finish(Answer::failure(Fault::failed, forgotten.error));
        answer->finish(Answer::success());
      });
    });
  });
}

bool Authenticator::_live(SignIn& sign_in, SignIn::Stage stage) const {
  if (sign_in.stage != stage) return false;
  if (_time.now() - sign_in.started > _settings.lifetime) {
    sign_in.stage = SignIn::Stage::ended;
    return false;
  }
  return true;
}

std::optional<std::chrono::seconds> Authenticator::waiting_for(const std::string& user_id, const std::string& source) const {
  return _waiting(account_key(user_id), address_key(source));
}

std::optional<std::chrono::seconds> Authenticator::_waiting(const std::string& account, const std::string& address) const {
  const auto now = _time.now();
  const auto by_account = _accounts.wait(account, now);
  const auto by_address = _addresses.wait(address, now);
  if (by_account && by_address) return std::max(*by_account, *by_address);
  return by_account ? by_account : by_address;
}

void Authenticator::_failed(const std::string& account, const std::string& address) {
  const auto now = _time.now();
  _accounts.failed(account, now);
  _addresses.failed(address, now);
}

void Authenticator::_code_refused(SignIn sign_in, std::string source, std::string action, Executor executor, Done<Step> done) {
  ++sign_in.wrong_codes;
  auto self = shared_from_this();
  _record(std::move(action), sign_in.user_id, sign_in.user_id, source, std::to_string(sign_in.wrong_codes) + " wrong", executor, [=]() mutable {
    if (sign_in.wrong_codes < self->_settings.most_wrong_codes) return done(Step::of(Step::Kind::refused, std::move(sign_in)));
    sign_in.stage = SignIn::Stage::ended;
    self->_record("signin.ended", sign_in.user_id, sign_in.user_id, source, "too many wrong codes", executor,
                  [done, sign_in]() mutable { done(Step::of(Step::Kind::ended, std::move(sign_in))); });
  });
}

void Authenticator::_complete(SignIn sign_in, std::string source, Executor executor, Done<Step> done) {
  // A WebAuthn credential is phishing-resistant: with a password, or alone when it verified the
  // user (which passkey() requires). A TOTP or recovery code is a second factor.
  bool otp = false;
  bool webauthn = false;
  for (const auto& method : sign_in.amr) {
    otp = otp || method == "otp";
    webauthn = webauthn || method == "hwk" || method == "swk";
  }
  sign_in.reached = webauthn ? Assurance::phr : otp ? Assurance::mfa : Assurance::pwd;
  sign_in.stage = SignIn::Stage::complete;
  const auto reached = std::string(acr(sign_in.reached));
  const auto user_id = sign_in.user_id;
  _record("signin.complete", user_id, user_id, std::move(source), reached, std::move(executor),
          [done = std::move(done), sign_in = std::move(sign_in)]() mutable { done(Step::of(Step::Kind::next, std::move(sign_in))); });
}

void Authenticator::_record(std::string action, std::string actor, std::string subject, std::string source, std::string detail, Executor executor, Then then) {
  // A failure is logged by the audit log itself; what it records has happened.
  _audit_log->record(audit::Event{std::move(action), std::move(actor), std::move(subject), std::move(source), std::move(detail)}, kStepDeadline,
                     std::move(executor), [then = std::move(then)](Status) { then(); });
}

}  // namespace lugh::authn
