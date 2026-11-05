//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "lugh/ldap/ber.h"
#include "lugh/ldap/dn.h"
#include "lugh/ldap/filter.h"
#include "lugh/ldap/messages.h"

using namespace lugh::ldap;

namespace {

using Raw = std::vector<unsigned char>;

ber::Bytes view(const std::string& text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }
std::string text_of(const Raw& raw) { return {raw.begin(), raw.end()}; }

// A hand-built element, independent of ber::Writer, for lengths under 128.
std::string tlv(unsigned char tag, const std::string& content) {
  std::string out;
  out.push_back(static_cast<char>(tag));
  out.push_back(static_cast<char>(content.size()));
  return out + content;
}
std::string octets(const std::string& text) { return tlv(0x04, text); }
std::string one(int value) { return std::string(1, static_cast<char>(value)); }

// An LDAPMessage with this id around this operation.
std::string message(const std::string& operation, int id = 1, const std::string& controls = "") { return tlv(0x30, tlv(0x02, one(id)) + operation + controls); }

std::optional<Filter> filter_from(const std::string& encoded) {
  ber::Reader reader(view(encoded));
  const auto element = reader.next();
  if (!element) return std::nullopt;
  return parse_filter(*element);
}

std::string assertion(unsigned char tag, const std::string& attribute, const std::string& value) { return tlv(tag, octets(attribute) + octets(value)); }
std::string equal(const std::string& attribute, const std::string& value) { return assertion(0xA3, attribute, value); }

Entry alice() {
  Entry entry;
  entry.dn = "uid=alice,ou=people,dc=example,dc=com";
  entry.add("uid", "alice");
  entry.add("cn", "Alice Smith");
  entry.add("objectClass", "person");
  entry.add("objectClass", "inetOrgPerson");
  entry.add("uidNumber", "1000");
  entry.add("memberOf", "cn=Staff,ou=groups,dc=example,dc=com");
  return entry;
}

Match evaluate(const std::string& encoded) {
  const auto filter = filter_from(encoded);
  EXPECT_TRUE(filter);
  return filter ? filter->evaluate(alice()) : Match::undefined;
}

}  // namespace

// RFC 4511 section 5.1 and X.690: every length form it allows, none it does not.
TEST(Ber, EveryLengthForm) {
  // The contents, copied, since an element only points into what it was read from.
  const auto read = [](const Raw& raw) -> std::optional<std::string> {
    const auto element = ber::Reader(raw).next();
    if (!element) return std::nullopt;
    return std::string(element->text());
  };
  EXPECT_EQ(read({0x04, 0x02, 'h', 'i'}), "hi");
  EXPECT_EQ(read({0x04, 0x81, 0x02, 'h', 'i'}), "hi");
  // Not minimal, which BER allows.
  EXPECT_EQ(read({0x04, 0x84, 0x00, 0x00, 0x00, 0x02, 'h', 'i'}), "hi");
  EXPECT_EQ(read({0x04, 0x00}), "");

  Raw long_form{0x04, 0x82, 0x01, 0x00};
  long_form.resize(4 + 256, 'x');
  EXPECT_EQ(read(long_form)->size(), 256u);

  const Raw tagged{0x8A, 0x00};
  EXPECT_EQ(ber::Reader(tagged).next()->tag, 0x8A);
}

TEST(Ber, WhatIsRefused) {
  const auto read = [](const Raw& raw) { return ber::Reader(raw).next().has_value(); };
  EXPECT_FALSE(read({0x30, 0x80, 0x00, 0x00})) << "the indefinite form";
  EXPECT_FALSE(read({0x04, 0x85, 0, 0, 0, 0, 2, 'h', 'i'})) << "more length bytes than taken";
  EXPECT_FALSE(read({0x1F, 0x01, 0x01})) << "the high tag number form";
  EXPECT_FALSE(read({0x04, 0x03, 'h', 'i'})) << "shorter than it says";
  EXPECT_FALSE(read({0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 'h'})) << "a length past anything held";
  EXPECT_FALSE(read({})) << "nothing";
}

TEST(Ber, Numbers) {
  const auto number = [](const Raw& content) { return ber::integer({0x02, content}); };
  EXPECT_EQ(number({0x00}), 0);
  EXPECT_EQ(number({0x7F}), 127);
  EXPECT_EQ(number({0x00, 0x80}), 128);
  EXPECT_EQ(number({0xFF}), -1);
  EXPECT_EQ(number({0x80}), -128);
  EXPECT_EQ(number({0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}), INT64_MAX);
  EXPECT_FALSE(number({}));
  EXPECT_FALSE(number({1, 2, 3, 4, 5, 6, 7, 8, 9}));
  const Raw yes{0xFF};
  const Raw no{0x00};
  const Raw two{1, 2};
  EXPECT_EQ(ber::boolean({0x01, yes}), true);
  EXPECT_EQ(ber::boolean({0x01, no}), false);
  EXPECT_FALSE(ber::boolean({0x01, two}));
}

TEST(Ber, FramingAStream) {
  const auto state = [](const Raw& raw, std::size_t most = 100) { return ber::frame(raw, most); };
  EXPECT_EQ(state({}).state, ber::Frame::State::partial);
  EXPECT_EQ(state({0x30}).state, ber::Frame::State::partial);
  EXPECT_EQ(state({0x30, 0x82, 0x00}).state, ber::Frame::State::partial);
  EXPECT_EQ(state({0x30, 0x02, 0x01}).state, ber::Frame::State::partial);
  const auto whole = state({0x30, 0x01, 0x01, 0x99});
  EXPECT_EQ(whole.state, ber::Frame::State::complete);
  EXPECT_EQ(whole.size, 3u);
  EXPECT_EQ(state({0x30, 0x80}).state, ber::Frame::State::invalid);
  EXPECT_EQ(state({0x1F}).state, ber::Frame::State::invalid);
  // Past the cap, known from the header alone, whatever has arrived of the rest.
  EXPECT_EQ(state({0x30, 0x7F}, 100).state, ber::Frame::State::invalid);
  EXPECT_EQ(state({0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}).state, ber::Frame::State::invalid);
  // Exactly the cap is good.
  Raw at_cap{0x30, 0x62};
  at_cap.resize(100, 0);
  EXPECT_EQ(state(at_cap).state, ber::Frame::State::complete);
}

TEST(Ber, TheWriterIsMinimalAndNests) {
  ber::Writer writer;
  writer.begin(0x30);
  writer.integer(0x02, 127);
  writer.integer(0x02, 128);
  writer.integer(0x02, -1);
  writer.integer(0x02, -129);
  writer.boolean(0x01, true);
  writer.octets(0x04, "hi");
  writer.end();
  EXPECT_EQ(writer.bytes(), text_of({0x30, 21, 0x02, 1, 0x7F, 0x02, 2, 0x00, 0x80, 0x02, 1, 0xFF, 0x02, 2, 0xFF, 0x7F, 0x01, 1, 0xFF, 0x04, 2, 'h', 'i'}));

  ber::Writer large;
  large.octets(0x04, std::string(200, 'x'));
  EXPECT_EQ(large.bytes().substr(0, 3), text_of({0x04, 0x81, 200}));
  ber::Writer larger;
  larger.begin(0x30);
  larger.octets(0x04, std::string(300, 'x'));
  larger.end();
  EXPECT_EQ(larger.bytes().substr(0, 4), text_of({0x30, 0x82, 0x01, 0x30}));
}

// RFC 4514 section 4's examples, and the forms in the tree.
TEST(Dn, TheFormsInTheTree) {
  const auto dn = parse_dn("uid=alice,ou=people,dc=example,dc=com");
  ASSERT_TRUE(dn);
  ASSERT_EQ(dn->rdns.size(), 4u);
  EXPECT_EQ(dn->rdns[0], (Rdn{"uid", "alice"}));
  EXPECT_EQ(dn->rdns[3], (Rdn{"dc", "com"}));
  EXPECT_EQ(to_string(*dn), "uid=alice,ou=people,dc=example,dc=com");

  EXPECT_TRUE(parse_dn("")->empty()) << "the rootDSE";
  EXPECT_TRUE(parse_dn("   ")->empty());
}

TEST(Dn, Escaping) {
  EXPECT_EQ(parse_dn("cn=Smith\\, John,dc=x")->rdns[0].value, "Smith, John");
  EXPECT_EQ(parse_dn("cn=James \\\"Jim\\\" Smith\\, III,dc=x")->rdns[0].value, "James \"Jim\" Smith, III");
  EXPECT_EQ(parse_dn("cn=Lu\\C4\\8Di\\C4\\87,dc=x")->rdns[0].value,
            "Lu\xC4\x8D"
            "i\xC4\x87");
  EXPECT_EQ(parse_dn("cn=\\ leading,dc=x")->rdns[0].value, " leading");
  EXPECT_EQ(parse_dn("cn=trailing\\ ,dc=x")->rdns[0].value, "trailing ");
  EXPECT_EQ(parse_dn("cn=\\#one,dc=x")->rdns[0].value, "#one");
  EXPECT_EQ(parse_dn("cn=a=b,dc=x")->rdns[0].value, "a=b");

  for (const std::string value : {"Smith, John", "a+b", " both ", "#one", "q\"uote", "back\\slash", "a;b", "<a>"}) {
    const auto back = parse_dn("cn=" + escape_dn_value(value) + ",dc=x");
    ASSERT_TRUE(back) << value;
    EXPECT_EQ(back->rdns[0].value, value);
  }
}

TEST(Dn, FoldingForComparison) {
  const auto a = parse_dn("UID=Alice,OU=People,DC=Example,DC=COM");
  const auto b = parse_dn("uid=alice, ou=people,  dc=example, dc=com");
  ASSERT_TRUE(a);
  ASSERT_TRUE(b);
  EXPECT_EQ(a->rdns[0].type, "uid");
  EXPECT_EQ(a->rdns[0].value, "Alice") << "kept as written";
  EXPECT_NE(*a, *b);
  EXPECT_EQ(normalised(*a), normalised(*b));
}

TEST(Dn, Within) {
  const auto under = normalised(*parse_dn("uid=alice,ou=people,dc=example,dc=com"));
  const auto people = normalised(*parse_dn("ou=people,dc=example,dc=com"));
  const auto groups = normalised(*parse_dn("ou=groups,dc=example,dc=com"));
  EXPECT_TRUE(within(under, people));
  EXPECT_TRUE(within(people, people));
  EXPECT_FALSE(within(people, under));
  EXPECT_FALSE(within(under, groups));
}

TEST(Dn, EverythingElseIsRefused) {
  for (const std::string bad : {"alice", "=alice", "uid=", "uid=,dc=x", "uid=a,", "uid=a,,dc=x", "uid=a+cn=b,dc=x", "1.2.3=a,dc=x", "uid=#04024869", "uid=a\\",
                                "uid=a\\4", "uid=a\\zz", "uid=a\\00", "uid=a;dc=x", "uid=a<b", "uid=a>b", "uid=a\"b", "9a=b", "u_d=a"}) {
    EXPECT_FALSE(parse_dn(bad)) << bad;
  }
  EXPECT_FALSE(parse_dn(std::string("uid=a\0b", 7))) << "a NUL";

  std::string deep;
  for (std::size_t i = 0; i < kMostDnComponents; ++i) deep += (deep.empty() ? "" : ",") + std::string("ou=a");
  EXPECT_TRUE(parse_dn(deep));
  EXPECT_FALSE(parse_dn(deep + ",ou=a")) << "one past the cap";
}

TEST(Filter, EachKindAgainstAnEntry) {
  EXPECT_EQ(evaluate(equal("uid", "alice")), Match::yes);
  EXPECT_EQ(evaluate(equal("UID", "ALICE")), Match::yes) << "folded";
  EXPECT_EQ(evaluate(equal("uid", "bob")), Match::no);
  EXPECT_EQ(evaluate(equal("objectClass", "person")), Match::yes) << "any of its values";
  EXPECT_EQ(evaluate(assertion(0xA8, "uid", "alice")), Match::yes) << "approxMatch is equality";
  EXPECT_EQ(evaluate(tlv(0x87, "uid")), Match::yes);
  EXPECT_EQ(evaluate(tlv(0x87, "MAIL")), Match::no);
  // DNs compare by name, not by bytes.
  EXPECT_EQ(evaluate(equal("memberOf", "CN=staff, OU=Groups, DC=example, DC=com")), Match::yes);
  EXPECT_EQ(evaluate(equal("uidNumber", "01000")), Match::yes);
}

TEST(Filter, Substrings) {
  const auto substring = [](const std::string& pieces) { return evaluate(tlv(0xA4, octets("cn") + tlv(0x30, pieces))); };
  EXPECT_EQ(substring(tlv(0x80, "ali")), Match::yes);
  EXPECT_EQ(substring(tlv(0x80, "smith")), Match::no);
  EXPECT_EQ(substring(tlv(0x82, "SMITH")), Match::yes);
  EXPECT_EQ(substring(tlv(0x81, "ce s")), Match::yes);
  EXPECT_EQ(substring(tlv(0x80, "al") + tlv(0x81, "ce") + tlv(0x81, "mi") + tlv(0x82, "th")), Match::yes);
  EXPECT_EQ(substring(tlv(0x81, "mi") + tlv(0x81, "ce")), Match::no) << "in order";
  // The final may not overlap what has been matched.
  EXPECT_EQ(substring(tlv(0x80, "alice smi") + tlv(0x82, "smith")), Match::no);

  EXPECT_FALSE(filter_from(tlv(0xA4, octets("cn") + tlv(0x30, "")))) << "no pieces";
  EXPECT_FALSE(filter_from(tlv(0xA4, octets("cn") + tlv(0x30, tlv(0x81, "a") + tlv(0x80, "b"))))) << "an initial not first";
  EXPECT_FALSE(filter_from(tlv(0xA4, octets("cn") + tlv(0x30, tlv(0x82, "a") + tlv(0x81, "b"))))) << "something after the final";
  EXPECT_FALSE(filter_from(tlv(0xA4, octets("cn") + tlv(0x30, tlv(0x82, "a") + tlv(0x82, "b"))))) << "two finals";
}

// TODO/2026-11-04-ldap.md: ordering on the POSIX numbers only, Undefined anywhere else.
TEST(Filter, Ordering) {
  EXPECT_EQ(evaluate(assertion(0xA5, "uidNumber", "1000")), Match::yes);
  EXPECT_EQ(evaluate(assertion(0xA5, "uidNumber", "1001")), Match::no);
  EXPECT_EQ(evaluate(assertion(0xA6, "uidNumber", "1000")), Match::yes);
  EXPECT_EQ(evaluate(assertion(0xA6, "uidNumber", "999")), Match::no);
  EXPECT_EQ(evaluate(assertion(0xA5, "uid", "a")), Match::undefined);
  EXPECT_EQ(evaluate(assertion(0xA5, "uidNumber", "many")), Match::undefined);
}

// RFC 4511 section 4.5.1.7: three values, through every combination.
TEST(Filter, Undefined) {
  const auto undefined = equal("mail", "a@example.com");
  const auto yes = equal("uid", "alice");
  const auto no = equal("uid", "bob");
  EXPECT_EQ(evaluate(undefined), Match::undefined) << "an attribute the entry does not have";
  EXPECT_EQ(evaluate(tlv(0xA9, "")), Match::undefined) << "extensibleMatch";

  EXPECT_EQ(evaluate(tlv(0xA2, undefined)), Match::undefined);
  EXPECT_EQ(evaluate(tlv(0xA2, yes)), Match::no);
  EXPECT_EQ(evaluate(tlv(0xA2, no)), Match::yes);
  EXPECT_EQ(evaluate(tlv(0xA0, yes + undefined)), Match::undefined);
  EXPECT_EQ(evaluate(tlv(0xA0, no + undefined)), Match::no);
  EXPECT_EQ(evaluate(tlv(0xA0, yes + yes)), Match::yes);
  EXPECT_EQ(evaluate(tlv(0xA1, no + undefined)), Match::undefined);
  EXPECT_EQ(evaluate(tlv(0xA1, yes + undefined)), Match::yes);
  EXPECT_EQ(evaluate(tlv(0xA1, no + no)), Match::no);
  // RFC 4526's absolute filters.
  EXPECT_EQ(evaluate(tlv(0xA0, "")), Match::yes);
  EXPECT_EQ(evaluate(tlv(0xA1, "")), Match::no);
  // Absent is false for presence, so this finds those without one.
  EXPECT_EQ(evaluate(tlv(0xA2, tlv(0x87, "mail"))), Match::yes);
}

TEST(Filter, NestingToTheCapAndOnePast) {
  std::string encoded = tlv(0x87, "uid");
  for (int depth = 1; depth < kMostFilterDepth; ++depth) encoded = tlv(0xA2, encoded);
  EXPECT_TRUE(filter_from(encoded));
  EXPECT_FALSE(filter_from(tlv(0xA2, encoded)));
}

TEST(Filter, TooManyItems) {
  std::string many;
  for (std::size_t i = 0; i < kMostFilterItems - 1; ++i) many += std::string("\x87\x01u", 3);
  ber::Writer fits;
  fits.octets(0xA0, many);
  EXPECT_TRUE(filter_from(fits.bytes()));
  ber::Writer past;
  past.octets(0xA0, many + std::string("\x87\x01u", 3));
  EXPECT_FALSE(filter_from(past.bytes()));
}

TEST(Filter, Malformed) {
  EXPECT_FALSE(filter_from(tlv(0xA2, ""))) << "not of nothing";
  EXPECT_FALSE(filter_from(tlv(0xA2, tlv(0x87, "a") + tlv(0x87, "b")))) << "not of two";
  EXPECT_FALSE(filter_from(tlv(0x87, ""))) << "present of no attribute";
  EXPECT_FALSE(filter_from(tlv(0xA3, octets("uid")))) << "equality with no value";
  EXPECT_FALSE(filter_from(tlv(0xA3, octets("") + octets("x")))) << "equality with no attribute";
  EXPECT_FALSE(filter_from(tlv(0xA3, octets("uid") + octets("x") + octets("y")))) << "something more";
  EXPECT_FALSE(filter_from(tlv(0xAF, ""))) << "no such kind";
}

TEST(Filter, PinnedValues) {
  EXPECT_EQ(pinned_value(*filter_from(equal("UID", "alice")), "uid"), "alice");
  EXPECT_EQ(pinned_value(*filter_from(tlv(0xA0, tlv(0x87, "cn") + equal("uid", "alice"))), "uid"), "alice");
  EXPECT_FALSE(pinned_value(*filter_from(tlv(0xA1, equal("uid", "alice"))), "uid")) << "an or pins nothing";
  EXPECT_FALSE(pinned_value(*filter_from(tlv(0xA2, equal("uid", "alice"))), "uid")) << "nor a not";
  EXPECT_FALSE(pinned_value(*filter_from(equal("cn", "alice")), "uid"));
}

// RFC 4511 section 4.2.
TEST(Message, ABind) {
  const auto bytes = message(tlv(0x60, tlv(0x02, one(3)) + octets("uid=alice,dc=x") + tlv(0x80, "secret")), 7);
  const auto parsed = parse_message(view(bytes));
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->id, 7);
  const auto& bind = std::get<BindRequest>(parsed->request);
  EXPECT_EQ(bind.version, 3);
  EXPECT_EQ(bind.name, "uid=alice,dc=x");
  ASSERT_TRUE(bind.password);
  EXPECT_EQ(lugh::secret_text(*bind.password), "secret");

  const auto sasl = parse_message(view(message(tlv(0x60, tlv(0x02, one(3)) + octets("") + tlv(0xA3, octets("PLAIN"))))));
  ASSERT_TRUE(sasl);
  EXPECT_FALSE(std::get<BindRequest>(sasl->request).password);
}

TEST(Message, ASearch) {
  const auto bytes = message(tlv(0x63, octets("dc=x") + tlv(0x0A, one(2)) + tlv(0x0A, one(0)) + tlv(0x02, one(10)) + tlv(0x02, one(30)) + tlv(0x01, one(0)) +
                                           equal("uid", "alice") + tlv(0x30, octets("cn") + octets("mail"))));
  const auto parsed = parse_message(view(bytes));
  ASSERT_TRUE(parsed);
  const auto& search = std::get<SearchRequest>(parsed->request);
  EXPECT_EQ(search.base, "dc=x");
  EXPECT_EQ(search.scope, Scope::subtree);
  EXPECT_EQ(search.size_limit, 10);
  EXPECT_EQ(search.time_limit, 30);
  EXPECT_FALSE(search.types_only);
  EXPECT_EQ(search.filter.attribute, "uid");
  EXPECT_EQ(search.attributes, (std::vector<std::string>{"cn", "mail"}));

  const auto with_scope = [](int scope) {
    return message(tlv(0x63, octets("dc=x") + tlv(0x0A, one(scope)) + tlv(0x0A, one(0)) + tlv(0x02, one(0)) + tlv(0x02, one(0)) + tlv(0x01, one(0)) +
                                 tlv(0x87, "uid") + tlv(0x30, "")));
  };
  EXPECT_TRUE(parse_message(view(with_scope(0))));
  EXPECT_FALSE(parse_message(view(with_scope(3)))) << "no such scope";
}

TEST(Message, TheWrites) {
  const auto attribute = tlv(0x30, octets("mail") + tlv(0x31, octets("a@x") + octets("b@x")));
  const auto modify = parse_message(view(message(tlv(0x66, octets("uid=a,dc=x") + tlv(0x30, tlv(0x30, tlv(0x0A, one(2)) + attribute))))));
  ASSERT_TRUE(modify);
  const auto& changed = std::get<ModifyRequest>(modify->request);
  EXPECT_EQ(changed.object, "uid=a,dc=x");
  ASSERT_EQ(changed.changes.size(), 1u);
  EXPECT_EQ(changed.changes[0].operation, ModifyOperation::replace);
  EXPECT_EQ(changed.changes[0].attribute.type, "mail");
  EXPECT_EQ(changed.changes[0].attribute.values, (std::vector<std::string>{"a@x", "b@x"}));
  EXPECT_FALSE(parse_message(view(message(tlv(0x66, octets("x") + tlv(0x30, tlv(0x30, tlv(0x0A, one(3)) + attribute))))))) << "no such operation";

  const auto add = parse_message(view(message(tlv(0x68, octets("uid=a,dc=x") + tlv(0x30, attribute)))));
  ASSERT_TRUE(add);
  EXPECT_EQ(std::get<AddRequest>(add->request).attributes.size(), 1u);

  const auto remove = parse_message(view(message(tlv(0x4A, "uid=a,dc=x"))));
  ASSERT_TRUE(remove);
  EXPECT_EQ(std::get<DeleteRequest>(remove->request).entry, "uid=a,dc=x");

  const auto rename = parse_message(view(message(tlv(0x6C, octets("uid=a,dc=x") + octets("uid=b") + tlv(0x01, one(0xFF))))));
  ASSERT_TRUE(rename);
  EXPECT_TRUE(std::get<ModifyDnRequest>(rename->request).delete_old);
  EXPECT_FALSE(std::get<ModifyDnRequest>(rename->request).new_superior);
  const auto moved = parse_message(view(message(tlv(0x6C, octets("uid=a,dc=x") + octets("uid=b") + tlv(0x01, one(0)) + tlv(0x80, "dc=y")))));
  ASSERT_TRUE(moved);
  EXPECT_EQ(std::get<ModifyDnRequest>(moved->request).new_superior, "dc=y");
}

TEST(Message, TheRest) {
  EXPECT_TRUE(std::holds_alternative<UnbindRequest>(parse_message(view(message(tlv(0x42, ""))))->request));
  EXPECT_EQ(std::get<AbandonRequest>(parse_message(view(message(tlv(0x50, one(9)))))->request).id, 9);

  const auto compare = parse_message(view(message(tlv(0x6E, octets("uid=a,dc=x") + tlv(0x30, octets("mail") + octets("a@x"))))));
  ASSERT_TRUE(compare);
  EXPECT_EQ(std::get<CompareRequest>(compare->request).attribute, "mail");

  const auto start_tls = parse_message(view(message(tlv(0x77, tlv(0x80, kStartTlsOid)))));
  ASSERT_TRUE(start_tls);
  EXPECT_EQ(std::get<ExtendedRequest>(start_tls->request).oid, kStartTlsOid);
  EXPECT_FALSE(std::get<ExtendedRequest>(start_tls->request).value);
  const auto with_value = parse_message(view(message(tlv(0x77, tlv(0x80, "1.2.3") + tlv(0x81, "data")))));
  EXPECT_EQ(std::get<ExtendedRequest>(with_value->request).value, "data");
}

TEST(Message, Controls) {
  const auto paged = encode_paged_results({100, "cookie"});
  const auto controls = tlv(0xA0, tlv(0x30, octets(kPagedResultsOid) + tlv(0x01, one(0xFF)) + octets(paged)) + tlv(0x30, octets("1.2.3")));
  const auto parsed = parse_message(view(message(tlv(0x42, ""), 1, controls)));
  ASSERT_TRUE(parsed);
  ASSERT_EQ(parsed->controls.size(), 2u);
  EXPECT_EQ(parsed->controls[0].oid, kPagedResultsOid);
  EXPECT_TRUE(parsed->controls[0].critical);
  const auto read = parse_paged_results(*parsed->controls[0].value);
  ASSERT_TRUE(read);
  EXPECT_EQ(read->size, 100);
  EXPECT_EQ(read->cookie, "cookie");
  EXPECT_FALSE(parsed->controls[1].critical) << "DEFAULT FALSE";
  EXPECT_FALSE(parsed->controls[1].value);

  EXPECT_FALSE(parse_paged_results("not ber"));
  EXPECT_FALSE(parse_message(view(message(tlv(0x42, ""), 1, tlv(0xA0, tlv(0x30, octets(""))))))) << "a control with no OID";
}

// RFC 3062 section 2.
TEST(Message, PasswordModify) {
  const auto value = tlv(0x30, tlv(0x80, "uid=a,dc=x") + tlv(0x81, "old") + tlv(0x82, "new"));
  const auto parsed = parse_password_modify(value);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->user, "uid=a,dc=x");
  EXPECT_EQ(lugh::secret_text(*parsed->old_password), "old");
  EXPECT_EQ(lugh::secret_text(*parsed->new_password), "new");

  const auto partial = parse_password_modify(tlv(0x30, tlv(0x82, "new")));
  ASSERT_TRUE(partial);
  EXPECT_FALSE(partial->user);
  EXPECT_FALSE(partial->old_password);

  EXPECT_TRUE(parse_password_modify(tlv(0x30, "")));
  EXPECT_FALSE(parse_password_modify(tlv(0x30, tlv(0x82, "a") + tlv(0x81, "b")))) << "out of order";
  EXPECT_FALSE(parse_password_modify(tlv(0x30, tlv(0x81, "a") + tlv(0x81, "b")))) << "twice";
  EXPECT_FALSE(parse_password_modify(tlv(0x30, tlv(0x83, "a")))) << "no such part";
}

TEST(Message, WhatIsNotOne) {
  EXPECT_FALSE(parse_message(view(message(tlv(0x42, ""), 0)))) << "id zero";
  EXPECT_FALSE(parse_message(view(message(tlv(0x42, ""), 0x80)))) << "a negative id";
  EXPECT_FALSE(parse_message(view(message(tlv(0x42, "x"))))) << "an unbind with something in it";
  EXPECT_FALSE(parse_message(view(message(tlv(0x71, ""))))) << "no such operation";
  EXPECT_FALSE(parse_message(view(message(tlv(0x61, ""))))) << "a response, sent to a server";
  EXPECT_FALSE(parse_message(view(tlv(0x31, tlv(0x02, one(1)) + tlv(0x42, ""))))) << "not a sequence";
  EXPECT_FALSE(parse_message(view(message(tlv(0x42, "")) + "x"))) << "bytes after it";
  EXPECT_FALSE(parse_message(view(tlv(0x30, tlv(0x02, one(1)))))) << "no operation";
  EXPECT_FALSE(parse_message(view(tlv(0x30, tlv(0x02, one(1)) + tlv(0x42, "") + octets("x"))))) << "something not controls after it";
}

// However it is cut short, a whole message is never read from part of one.
TEST(Message, TruncationAtEveryByte) {
  const auto paged = encode_paged_results({5, ""});
  const std::vector<std::string> messages{
      message(tlv(0x60, tlv(0x02, one(3)) + octets("uid=a,dc=x") + tlv(0x80, "secret"))),
      message(tlv(0x63, octets("dc=x") + tlv(0x0A, one(2)) + tlv(0x0A, one(0)) + tlv(0x02, one(0)) + tlv(0x02, one(0)) + tlv(0x01, one(0)) +
                            tlv(0xA0, equal("uid", "a") + tlv(0x87, "cn")) + tlv(0x30, octets("cn"))),
              1, tlv(0xA0, tlv(0x30, octets(kPagedResultsOid) + octets(paged)))),
      message(tlv(0x66, octets("x") + tlv(0x30, tlv(0x30, tlv(0x0A, one(0)) + tlv(0x30, octets("a") + tlv(0x31, octets("b"))))))),
  };
  for (const auto& whole : messages) {
    ASSERT_TRUE(parse_message(view(whole)));
    for (std::size_t length = 0; length < whole.size(); ++length) {
      EXPECT_FALSE(parse_message(view(whole.substr(0, length)))) << length;
      EXPECT_NE(ber::frame(view(whole.substr(0, length)), kMostMessageBytes).state, ber::Frame::State::complete) << length;
    }
    EXPECT_EQ(ber::frame(view(whole), kMostMessageBytes).size, whole.size());
  }
}

// The answers, by the bytes RFC 4511 gives them.
TEST(Message, Responses) {
  EXPECT_EQ(encode_result(1, ResponseOp::bind, {ResultCode::invalid_credentials, "", "no"}),
            tlv(0x30, tlv(0x02, one(1)) + tlv(0x61, tlv(0x0A, one(49)) + octets("") + octets("no"))));
  EXPECT_EQ(
      encode_result(2, ResponseOp::search_done, {}, {{kPagedResultsOid, false, "v"}}),
      tlv(0x30, tlv(0x02, one(2)) + tlv(0x65, tlv(0x0A, one(0)) + octets("") + octets("")) + tlv(0xA0, tlv(0x30, octets(kPagedResultsOid) + octets("v")))));
  EXPECT_EQ(encode_search_entry(3, "uid=a,dc=x", {{"cn", {"A", "B"}}}),
            tlv(0x30, tlv(0x02, one(3)) + tlv(0x64, octets("uid=a,dc=x") + tlv(0x30, tlv(0x30, octets("cn") + tlv(0x31, octets("A") + octets("B")))))));
  EXPECT_EQ(encode_extended(4, {}, kStartTlsOid, "v"),
            tlv(0x30, tlv(0x02, one(4)) + tlv(0x78, tlv(0x0A, one(0)) + octets("") + octets("") + tlv(0x8A, kStartTlsOid) + tlv(0x8B, "v"))));
}

// This machine's compiler has no libFuzzer, so the same properties as the fuzz targets, over a fixed
// sequence of damaged messages: the sanitizer builds are what make this one count.
TEST(Message, DamagedMessagesAreOnlyEverRefused) {
  const auto paged = encode_paged_results({5, "c"});
  const std::vector<std::string> seeds{
      message(tlv(0x60, tlv(0x02, one(3)) + octets("uid=a,dc=x") + tlv(0x80, "secret"))),
      message(tlv(0x63, octets("dc=x") + tlv(0x0A, one(2)) + tlv(0x0A, one(0)) + tlv(0x02, one(0)) + tlv(0x02, one(0)) + tlv(0x01, one(0)) +
                            tlv(0xA0, equal("uid", "a") + tlv(0xA2, tlv(0x87, "cn")) + tlv(0xA4, octets("cn") + tlv(0x30, tlv(0x80, "a") + tlv(0x82, "z")))) +
                            tlv(0x30, octets("cn"))),
              1, tlv(0xA0, tlv(0x30, octets(kPagedResultsOid) + octets(paged)))),
      message(tlv(0x66, octets("x") + tlv(0x30, tlv(0x30, tlv(0x0A, one(0)) + tlv(0x30, octets("a") + tlv(0x31, octets("b"))))))),
      message(tlv(0x77, tlv(0x80, kPasswordModifyOid) + tlv(0x81, tlv(0x30, tlv(0x81, "old") + tlv(0x82, "new"))))),
  };
  std::uint32_t state = 1;
  const auto random = [&](std::uint32_t below) {
    state = state * 1664525u + 1013904223u;
    return (state >> 8) % below;
  };
  int parsed = 0;
  for (int round = 0; round < 20000; ++round) {
    auto bytes = seeds[random(static_cast<std::uint32_t>(seeds.size()))];
    for (std::uint32_t edits = 1 + random(4); edits > 0; --edits) {
      const auto at = random(static_cast<std::uint32_t>(bytes.size()));
      switch (random(3)) {
        case 0:
          bytes[at] = static_cast<char>(random(256));
          break;
        case 1:
          bytes.erase(at, 1 + random(3));
          break;
        default:
          bytes.insert(at, 1, static_cast<char>(random(256)));
          break;
      }
      if (bytes.empty()) bytes.push_back(0);
    }
    (void)ber::frame(view(bytes), kMostMessageBytes);
    if (const auto read = parse_message(view(bytes))) {
      ++parsed;
      if (const auto* search = std::get_if<SearchRequest>(&read->request)) (void)search->filter.evaluate(alice());
      if (const auto* extended = std::get_if<ExtendedRequest>(&read->request); extended && extended->value) (void)parse_password_modify(*extended->value);
      for (const auto& control : read->controls) {
        if (control.value) (void)parse_paged_results(*control.value);
      }
    }
    // The same damage as a DN: what parses survives being written and read again.
    if (const auto dn = parse_dn(bytes)) {
      const auto again = parse_dn(to_string(*dn));
      ASSERT_TRUE(again) << to_string(*dn);
      EXPECT_EQ(*again, *dn);
    }
  }
  EXPECT_GT(parsed, 0) << "some damage leaves a message that still reads, or this tests only the first check";
}
