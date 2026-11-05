//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/operations.h"

#include <algorithm>

#include "lugh/scopes/scope.h"

namespace lugh::ldap {

namespace {

bool operational(std::string_view folded) {
  return folded == "entryuuid" || folded == "createtimestamp" || folded == "modifytimestamp" || folded == "lughentryversion";
}

// Whether the caller may see this entry: everyone bound sees the fixed tree, which says nothing,
// and themselves; the rest needs directory.read.
Tree::Visible visible_to(const Bound& bound) {
  const bool reads = bound.caller.has_scope(scopes::kDirectoryRead);
  const auto own = parse_dn(bound.dn);
  const auto own_normal = own ? std::optional<Dn>(normalised(*own)) : std::nullopt;
  return [reads, own_normal](const Entry& entry) {
    if (reads) return true;
    const auto is_leaf = entry.attributes.count("uid") > 0 || entry.attributes.count("entryuuid") > 0;
    if (!is_leaf) return true;
    const auto dn = parse_dn(entry.dn);
    return dn && own_normal && normalised(*dn) == *own_normal;
  };
}

Filter present(std::string attribute) {
  Filter out;
  out.kind = Filter::Kind::present;
  out.attribute = std::move(attribute);
  return out;
}

}  // namespace

std::vector<Attribute> attributes_for(const Entry& entry, const std::vector<std::string>& requested, bool types_only) {
  const auto wanted_all = [&](std::string_view which) { return std::find(requested.begin(), requested.end(), which) != requested.end(); };
  const bool only_none = requested.size() == 1 && requested.front() == "1.1";
  const bool users = requested.empty() || wanted_all("*");
  const bool operationals = wanted_all("+");
  std::vector<std::string> named;
  for (const auto& one : requested) named.push_back(fold(one));

  std::vector<Attribute> out;
  if (only_none) return out;
  for (const auto& [name, values] : entry.attributes) {
    const bool chosen = (operational(name) ? operationals : users) || std::find(named.begin(), named.end(), name) != named.end();
    if (!chosen) continue;
    const auto spelled = entry.spelled.find(name);
    Attribute attribute;
    attribute.type = spelled == entry.spelled.end() ? name : spelled->second;
    if (!types_only) attribute.values = values;
    out.push_back(std::move(attribute));
  }
  return out;
}

Operations::Operations(std::shared_ptr<Tree> tree, Settings settings) : _tree(std::move(tree)), _settings(std::move(settings)) {}

Entry Operations::_root_dse() const {
  Entry entry;
  // RFC 4512 section 5.1: no attributes are required of it, but a client asks (objectClass=*).
  entry.add("objectClass", "top");
  entry.add("namingContexts", _tree->base_text());
  entry.add("supportedLDAPVersion", "3");
  for (const auto& one : _settings.controls) entry.add("supportedControl", one);
  for (const auto& one : _settings.extensions) entry.add("supportedExtension", one);
  entry.add("vendorName", "Lugh");
  entry.add("vendorVersion", _settings.vendor_version);
  return entry;
}

void Operations::search(const std::optional<Bound>& bound, SearchRequest request, std::optional<PagedResults> paged, Executor executor,
                        Done<SearchAnswer> done) const {
  const auto refuse = [&](ResultCode code, const std::string& message) {
    answer_now<SearchAnswer>(executor, done, SearchAnswer{{code, "", message}, {}, std::nullopt});
  };

  const auto base = parse_dn(request.base);
  if (!base) return refuse(ResultCode::invalid_dn_syntax, "the base is not a distinguished name");

  if (base->empty()) {
    if (request.scope != Scope::base) return refuse(ResultCode::no_such_object, "no such entry");
    const auto root = _root_dse();
    SearchAnswer out;
    if (request.filter.evaluate(root) == Match::yes) out.entries.push_back({"", attributes_for(root, request.attributes, request.types_only)});
    return answer_now<SearchAnswer>(executor, done, std::move(out));
  }
  if (!bound) return refuse(ResultCode::insufficient_access_rights, "bind first");

  // RFC 2696 section 3: a size of zero with a cookie gives the search up.
  if (paged && paged->size == 0 && !paged->cookie.empty()) {
    return answer_now<SearchAnswer>(executor, done, SearchAnswer{{}, {}, PagedResults{0, ""}});
  }

  const auto server_most = _settings.most_results;
  const std::size_t client_most = request.size_limit > 0 ? static_cast<std::size_t>(request.size_limit) : server_most;
  std::size_t most = std::min(client_most, server_most);
  if (paged && paged->size > 0) most = std::min(most, static_cast<std::size_t>(paged->size));

  const auto limit = request.time_limit > 0 ? std::min(std::chrono::seconds(request.time_limit), _settings.time_limit) : _settings.time_limit;

  Tree::Walk walk;
  walk.base = *base;
  walk.scope = request.scope;
  walk.filter = std::move(request.filter);
  walk.visible = visible_to(*bound);
  walk.most = most;
  walk.after = paged ? paged->cookie : std::string();

  const auto requested = std::move(request.attributes);
  const auto types_only = request.types_only;
  const bool is_paged = paged.has_value();
  _tree->walk(std::move(walk), limit, executor, [requested, types_only, is_paged, done](Listed listed) {
    SearchAnswer out;
    out.result = {listed.code, "", listed.message};
    for (const auto& entry : listed.entries) out.entries.push_back({entry.dn, attributes_for(entry, requested, types_only)});
    if (is_paged) {
      out.paged = PagedResults{0, listed.next};
    } else if (listed.code == ResultCode::success && !listed.next.empty()) {
      out.result = {ResultCode::size_limit_exceeded, "", "more entries match than may be answered"};
    }
    done(std::move(out));
  });
}

void Operations::compare(const std::optional<Bound>& bound, CompareRequest request, Executor executor, Done<Result> done) const {
  if (!bound) return answer_now<Result>(executor, done, Result{ResultCode::insufficient_access_rights, "", "bind first"});
  const auto base = parse_dn(request.entry);
  if (!base) return answer_now<Result>(executor, done, Result{ResultCode::invalid_dn_syntax, "", "not a distinguished name"});

  Tree::Walk walk;
  walk.base = *base;
  walk.scope = Scope::base;
  walk.filter = present("objectclass");
  walk.visible = visible_to(*bound);
  walk.most = 1;

  Filter asked;
  asked.kind = Filter::Kind::equal;
  asked.attribute = fold(request.attribute);
  asked.value = request.value;
  _tree->walk(std::move(walk), _settings.time_limit, executor, [asked, done](Listed listed) {
    if (listed.code != ResultCode::success) return done(Result{listed.code, "", listed.message});
    if (listed.entries.empty()) return done(Result{ResultCode::no_such_object, "", "no such entry"});
    switch (asked.evaluate(listed.entries.front())) {
      case Match::yes:
        return done(Result{ResultCode::compare_true, "", ""});
      case Match::no:
        return done(Result{ResultCode::compare_false, "", ""});
      case Match::undefined:
        return done(Result{ResultCode::no_such_attribute, "", "the entry has no such attribute"});
    }
  });
}

std::string Operations::who_am_i(const std::optional<Bound>& bound) { return bound ? "dn:" + bound->dn : std::string(); }

}  // namespace lugh::ldap
