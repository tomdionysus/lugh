//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The API's one status and error code per fault (docs/api.md, "Errors"), the stack's Fault
// included: unavailable and timed out answer 503, each with its own code, and what failed
// inside is in the log, never the response.

#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <memory>
#include <string>

#include "lugh/api/api_support.h"

namespace {

struct Written {
  unsigned status;
  std::string code;
  std::string message;
};

Written write(lugh::Fault fault, const std::string& message) {
  auto response = std::make_shared<lugh::http::HttpResponse>();
  lugh::api::write_fault(response, fault, message);
  const auto error = boost::json::parse(response->body()).at("error").as_object();
  return {response->result_int(), std::string(error.at("code").as_string()), std::string(error.at("message").as_string())};
}

}  // namespace

TEST(ApiFaults, EachFaultHasItsStatusAndCode) {
  using lugh::Fault;
  const struct {
    Fault fault;
    unsigned status;
    const char* code;
  } expected[] = {
      {Fault::not_found, 404, "not_found"}, {Fault::conflict, 412, "changed"}, {Fault::duplicate, 409, "duplicate"},
      {Fault::invalid, 400, "invalid"},     {Fault::refused, 409, "refused"},  {Fault::unavailable, 503, "unavailable"},
      {Fault::timed_out, 503, "timed_out"}, {Fault::failed, 500, "failed"},    {Fault::cancelled, 503, "cancelled"},
  };
  for (const auto& each : expected) {
    const auto written = write(each.fault, "the caller's message");
    EXPECT_EQ(written.status, each.status) << lugh::fault_name(each.fault);
    EXPECT_EQ(written.code, each.code) << lugh::fault_name(each.fault);
  }
}

// The caller's refusal is said as the operation said it; a failure inside is not.
TEST(ApiFaults, WhatFailedInsideIsNotSaid) {
  using lugh::Fault;
  EXPECT_EQ(write(Fault::refused, "the last factor").message, "the last factor");
  for (const auto fault : {Fault::failed, Fault::unavailable, Fault::timed_out, Fault::cancelled})
    EXPECT_EQ(write(fault, "the store: /var/lib/lugh/store").message.find("/var/lib"), std::string::npos) << lugh::fault_name(fault);
  EXPECT_NE(write(Fault::timed_out, "x").message.find("may yet land"), std::string::npos) << "a write past its deadline may still be made";
  EXPECT_NE(write(Fault::cancelled, "x").message.find("may yet land"), std::string::npos) << "a cancelled write may still be made";
}
