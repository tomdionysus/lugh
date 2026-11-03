//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "loggers/logger_scoped.h"

#include <gtest/gtest.h>

#include "mocks/logger_mock.h"

using lugh::loggers::LoggerScoped;

TEST(LoggerScoped, PrefixesEveryLevelWithItsScope) {
  auto mock = std::make_shared<MockLogger>();
  LoggerScoped logger("oauth", mock);

  logger.debug("a");
  logger.info("b");
  logger.warn("c");
  logger.error("d");

  EXPECT_EQ(mock->lines(), (std::vector<std::string>{"(oauth) a", "(oauth) b", "(oauth) c", "(oauth) d"}));
}

TEST(LoggerScoped, NestsOutermostFirst) {
  auto mock = std::make_shared<MockLogger>();
  LoggerScoped logger("inner", std::make_shared<LoggerScoped>("outer", mock));

  logger.info("x");

  EXPECT_EQ(mock->lines().front(), "(outer) (inner) x");
}

TEST(LoggerScoped, BaseLoggerIsTheWrappedOne) {
  auto mock = std::make_shared<MockLogger>();
  LoggerScoped logger("s", mock);

  EXPECT_EQ(logger.base_logger(), mock);
}
