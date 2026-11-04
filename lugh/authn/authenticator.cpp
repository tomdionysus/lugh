//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/authenticator.h"

#include "lugh/core/awaited.h"

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

Task<Step> Authenticator::password(std::string login, Secret password, std::string source) {
  const auto user = co_await _directory->user_by_login(login);
  // An unknown name backs off under its own key, as a real one would, so the answers to
  // guesses at names and at passwords look the same.
  const auto account = account_key(user ? user->id : "?" + login);
  const auto address = address_key(source);

  // Before any hashing: a waiting caller costs nothing.
  if (const auto wait = _waiting(account, address)) co_return waiting(*wait);

  // The password is checked whatever else is wrong, so the time taken says nothing.
  bool right = false;
  if (user) {
    right = co_await _passwords->verify(user->id, std::move(password));
  } else {
    co_await _passwords->spend(std::move(password));
  }

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
    _failed(account, address);
    // Whoever typed it is not known to be the user.
    co_await _audit("signin.password.refused", "anonymous", user ? user->id : "", source, why);
    co_return Step::of(Step::Kind::refused);
  }
  _accounts.succeeded(account);

  SignIn sign_in;
  sign_in.user_id = user->id;
  sign_in.required = co_await _policies->required(user->id);
  sign_in.started = _time.now();
  sign_in.amr = {"pwd"};

  if (!user->enrolled && co_await _links->first_sign_in_allowed(user->id)) {
    // Root's first sign-in, with the password genesis made.
    sign_in.stage = SignIn::Stage::enrolment;
    co_await _audit("signin.password.accepted", user->id, user->id, source, "first sign-in");
    co_return Step::of(Step::Kind::next, std::move(sign_in));
  }
  const bool has_factor = co_await _factors->has_second_factor(user->id);
  if (!user->enrolled || (!has_factor && sign_in.required > Assurance::pwd)) {
    // Enrolment starts from a link, never from a password alone, or a stolen password
    // would be enough to enrol the thief's own authenticator.
    co_await _audit("signin.password.refused", "anonymous", user->id, source, "not enrolled");
    co_return Step::of(Step::Kind::refused);
  }
  co_await _audit("signin.password.accepted", user->id, user->id, source);

  if (!has_factor) co_return co_await _complete(std::move(sign_in), std::move(source));
  sign_in.stage = SignIn::Stage::second_factor;
  co_return Step::of(Step::Kind::next, std::move(sign_in));
}

Task<Step> Authenticator::totp(SignIn sign_in, std::string code, std::string source) {
  if (!_live(sign_in, SignIn::Stage::second_factor)) co_return Step::of(Step::Kind::ended, std::move(sign_in));
  const auto account = account_key(sign_in.user_id);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) co_return waiting(*wait, std::move(sign_in));

  const auto checked = co_await _factors->totp_check(sign_in.user_id, std::move(code));
  if (checked.fault == Fault::failed) co_return Step::of(Step::Kind::failed, std::move(sign_in));
  if (!checked.ok()) {
    _failed(account, address);
    co_return co_await _code_refused(std::move(sign_in), std::move(source), "signin.totp.refused");
  }

  _accounts.succeeded(account);
  sign_in.amr.push_back("otp");
  co_return co_await _complete(std::move(sign_in), std::move(source));
}

Task<Step> Authenticator::recovery(SignIn sign_in, Secret code, std::string source) {
  if (!_live(sign_in, SignIn::Stage::second_factor)) co_return Step::of(Step::Kind::ended, std::move(sign_in));
  const auto account = account_key(sign_in.user_id);
  const auto address = address_key(source);
  if (const auto wait = _waiting(account, address)) co_return waiting(*wait, std::move(sign_in));

  const auto used = co_await _factors->recovery_use(sign_in.user_id, std::move(code));
  if (used.fault == Fault::failed) co_return Step::of(Step::Kind::failed, std::move(sign_in));
  if (!used.ok()) {
    _failed(account, address);
    co_return co_await _code_refused(std::move(sign_in), std::move(source), "signin.recovery.refused");
  }

  _accounts.succeeded(account);
  co_await _audit("signin.recovery.used", sign_in.user_id, sign_in.user_id, source, std::to_string(used.value) + " left");
  sign_in.amr.push_back("otp");
  auto step = co_await _complete(std::move(sign_in), std::move(source));
  step.recovery_left = used.value;
  co_return step;
}

Task<Step> Authenticator::redeem(Secret token, Secret password, std::string source) {
  const auto address = address_key(source);
  if (const auto wait = _addresses.wait(address, _time.now())) co_return waiting(*wait);

  const auto peeked = co_await _links->peek(Secret(token.reveal()));
  const auto user = peeked.ok() ? co_await _directory->user(peeked.value) : std::nullopt;
  if (!user || user->disabled || user->enrolled || user->kind != directory::Kind::person) {
    _addresses.failed(address, _time.now());
    co_await _audit("enrolment.refused", "anonymous", user ? user->id : "", source, peeked.ok() ? "the user cannot enrol" : "no such link");
    co_return Step::of(Step::Kind::refused);
  }

  // The password first: one that is refused must not cost the person their link.
  if (const auto acceptable = _passwords->acceptable(password, *user); !acceptable.ok()) co_return Step::of(Step::Kind::refused);

  const audit::Actor actor{user->id, source};
  const auto spent = co_await _links->spend(std::move(token), actor);
  if (!spent.ok()) co_return Step::of(spent.fault == Fault::failed ? Step::Kind::failed : Step::Kind::refused);

  if (const auto set = co_await _passwords->set(actor, *user, std::move(password)); !set.ok()) {
    _logger.error("enrolment of " + user->id + ": the link is spent and the password was not set: " + set.message);
    co_return Step::of(Step::Kind::failed);
  }

  SignIn sign_in;
  sign_in.user_id = user->id;
  sign_in.stage = SignIn::Stage::enrolment;
  sign_in.required = co_await _policies->required(user->id);
  sign_in.started = _time.now();
  sign_in.amr = {"pwd"};
  co_return Step::of(Step::Kind::next, std::move(sign_in));
}

Task<Outcome<TotpSetup>> Authenticator::enrol_begin(SignIn sign_in, std::string source) {
  using Answer = Outcome<TotpSetup>;
  if (!_live(sign_in, SignIn::Stage::enrolment)) co_return Answer::failure(Fault::refused, "the sign-in is over");
  const auto user = co_await _directory->user(sign_in.user_id);
  if (!user) co_return Answer::failure(Fault::not_found, "no such user");
  co_return co_await _factors->totp_begin(audit::Actor{user->id, std::move(source)}, user->id, _settings.issuer, user->name);
}

Task<Step> Authenticator::enrol_confirm(SignIn sign_in, std::string factor_id, std::string code, std::string source) {
  if (!_live(sign_in, SignIn::Stage::enrolment)) co_return Step::of(Step::Kind::ended, std::move(sign_in));
  const audit::Actor actor{sign_in.user_id, source};

  const auto confirmed = co_await _factors->totp_confirm(actor, sign_in.user_id, std::move(factor_id), std::move(code));
  if (confirmed.fault == Fault::failed) co_return Step::of(Step::Kind::failed, std::move(sign_in));
  if (!confirmed.ok()) co_return co_await _code_refused(std::move(sign_in), std::move(source), "enrolment.totp.refused");

  auto codes = co_await _factors->recovery_generate(actor, sign_in.user_id);
  if (!codes.ok()) co_return Step::of(Step::Kind::failed, std::move(sign_in));
  if (const auto enrolled = co_await _directory->enrolled_set(actor, sign_in.user_id, true); !enrolled.ok()) {
    co_return Step::of(Step::Kind::failed, std::move(sign_in));
  }
  co_await _links->first_sign_in_spend(sign_in.user_id);

  sign_in.amr.push_back("otp");
  auto step = co_await _complete(std::move(sign_in), std::move(source));
  step.recovery_codes = std::move(codes.value);
  co_return step;
}

Task<Outcome<>> Authenticator::remove_factor(audit::Actor actor, std::string user_id, std::string factor_id) {
  using Answer = Outcome<>;
  const auto factors = co_await _factors->list(user_id);
  const FactorInfo* target = nullptr;
  std::size_t confirmed_totp = 0;
  for (const auto& factor : factors) {
    if (factor.id == factor_id) target = &factor;
    if (factor.kind == FactorKind::totp && factor.confirmed) ++confirmed_totp;
  }
  if (target == nullptr) co_return Answer::failure(Fault::not_found, "no such factor");

  const bool last = target->kind == FactorKind::totp && target->confirmed && confirmed_totp == 1;
  if (last && co_await _policies->required(user_id) > Assurance::pwd) {
    co_return Answer::failure(Fault::refused, "the user's last second factor cannot be removed while their policy requires one");
  }
  co_return co_await _factors->remove(std::move(actor), std::move(user_id), std::move(factor_id));
}

Task<Outcome<>> Authenticator::reset_factors(audit::Actor actor, std::string user_id) {
  using Answer = Outcome<>;
  const auto user = co_await _directory->user(user_id);
  if (!user) co_return Answer::failure(Fault::not_found, "no such user");

  // Not enrolled first: if removing the factors then fails, the user is already held at
  // enrolment and cannot sign in on what is left.
  const auto unenrolled = co_await _directory->enrolled_set(actor, user->id, false);
  if (!unenrolled.ok()) co_return Answer::from(unenrolled);
  if (const auto forgotten = co_await _factors->forget(actor, user->id); !forgotten.ok) co_return Answer::failure(Fault::failed, forgotten.error);
  co_return Answer::success();
}

bool Authenticator::_live(SignIn& sign_in, SignIn::Stage stage) const {
  if (sign_in.stage != stage) return false;
  if (_time.now() - sign_in.started > _settings.lifetime) {
    sign_in.stage = SignIn::Stage::ended;
    return false;
  }
  return true;
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

Task<Step> Authenticator::_code_refused(SignIn sign_in, std::string source, std::string action) {
  ++sign_in.wrong_codes;
  co_await _audit(std::move(action), sign_in.user_id, sign_in.user_id, source, std::to_string(sign_in.wrong_codes) + " wrong");
  if (sign_in.wrong_codes >= _settings.most_wrong_codes) {
    sign_in.stage = SignIn::Stage::ended;
    co_await _audit("signin.ended", sign_in.user_id, sign_in.user_id, source, "too many wrong codes");
    co_return Step::of(Step::Kind::ended, std::move(sign_in));
  }
  co_return Step::of(Step::Kind::refused, std::move(sign_in));
}

Task<Step> Authenticator::_complete(SignIn sign_in, std::string source) {
  bool otp = false;
  for (const auto& method : sign_in.amr) otp = otp || method == "otp";
  sign_in.reached = otp ? Assurance::mfa : Assurance::pwd;
  sign_in.stage = SignIn::Stage::complete;
  co_await _audit("signin.complete", sign_in.user_id, sign_in.user_id, std::move(source), std::string(acr(sign_in.reached)));
  co_return Step::of(Step::Kind::next, std::move(sign_in));
}

Task<void> Authenticator::_audit(std::string action, std::string actor, std::string subject, std::string source, std::string detail) {
  co_await awaited<Status>([&](Executor executor, Done<Status> done) {
    _audit_log->record(audit::Event{std::move(action), std::move(actor), std::move(subject), std::move(source), std::move(detail)}, kTransitionDeadline,
                       std::move(executor), std::move(done));
  });
}

}  // namespace lugh::authn
