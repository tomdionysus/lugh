#include "loggers/logger_stdio.h"

#include <gtest/gtest.h>

#include <boost/json.hpp>
#include <regex>
#include <sstream>

#include "loggers/logger_scoped.h"

using lugh::loggers::LogFormat;
using lugh::loggers::LoggerScoped;
using lugh::loggers::LoggerStdIO;
namespace loggers = lugh::loggers;

TEST(LoggerStdIO, TextLineIsTimeLevelAndMessage) {
  std::ostringstream out;
  LoggerStdIO logger(loggers::DEBUG, out);

  logger.info("hello");

  EXPECT_TRUE(std::regex_match(out.str(), std::regex(R"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \[INFO \] hello\n)"))) << out.str();
}

TEST(LoggerStdIO, LevelFiltersBelowIt) {
  std::ostringstream out;
  LoggerStdIO logger(loggers::WARN, out);

  logger.debug("d");
  logger.info("i");
  logger.warn("w");

  EXPECT_EQ(out.str().find("[DEBUG]"), std::string::npos);
  EXPECT_EQ(out.str().find("[INFO ]"), std::string::npos);
  EXPECT_NE(out.str().find("[WARN ] w"), std::string::npos);
}

TEST(LoggerStdIO, ErrorAndRawIgnoreTheLevel) {
  std::ostringstream out;
  LoggerStdIO logger(loggers::ERROR, out);

  logger.error("e");
  logger.raw("r");

  EXPECT_NE(out.str().find("[ERROR] e"), std::string::npos);
  EXPECT_NE(out.str().find("[-----] r"), std::string::npos);
}

TEST(LoggerStdIO, SetLevelTakesEffect) {
  std::ostringstream out;
  LoggerStdIO logger(loggers::ERROR, out);

  logger.info("before");
  logger.set_level(loggers::INFO);
  logger.info("after");

  EXPECT_EQ(out.str().find("before"), std::string::npos);
  EXPECT_NE(out.str().find("after"), std::string::npos);
}

TEST(LoggerStdIO, JsonLiftsNestedScopesIntoAField) {
  std::ostringstream out;
  auto base = std::make_shared<LoggerStdIO>(loggers::DEBUG, out);
  base->set_format(LogFormat::Json);
  LoggerScoped inner("router", std::make_shared<LoggerScoped>("http", base));

  inner.warn("slow");

  const auto line = boost::json::parse(out.str()).as_object();
  EXPECT_EQ(line.at("level").as_string(), "warn");
  EXPECT_EQ(line.at("scope").as_string(), "http/router");
  EXPECT_EQ(line.at("message").as_string(), "slow");
  EXPECT_TRUE(line.contains("at"));
}

TEST(LoggerStdIO, JsonWithoutScopeHasNoScopeField) {
  std::ostringstream out;
  LoggerStdIO logger(loggers::DEBUG, out);
  logger.set_format(LogFormat::Json);

  logger.info("plain");

  const auto line = boost::json::parse(out.str()).as_object();
  EXPECT_FALSE(line.contains("scope"));
  EXPECT_EQ(line.at("message").as_string(), "plain");
}
