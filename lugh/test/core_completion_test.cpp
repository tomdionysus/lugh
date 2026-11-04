//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <thread>
#include <vector>

#include "lugh/core/completion.h"

using lugh::Completion;
using namespace std::chrono_literals;

TEST(Completion, TheAnswerIsPostedNeverInline) {
  boost::asio::io_context io;
  int answer = 0;
  auto completion = Completion<int>::start(10s, io.get_executor(), [&](int value) { answer = value; }, [] { return -1; });
  completion->finish(7);
  EXPECT_EQ(answer, 0) << "not until the caller's executor runs it";
  EXPECT_TRUE(completion->answered());
  io.run();
  EXPECT_EQ(answer, 7);
}

TEST(Completion, TheDeadlineAnswersWhenNothingElseDoes) {
  boost::asio::io_context io;
  std::vector<int> answers;
  auto completion = Completion<int>::start(20ms, io.get_executor(), [&](int value) { answers.push_back(value); }, [] { return -1; });
  io.run();
  ASSERT_EQ(answers, std::vector<int>{-1});
  EXPECT_TRUE(completion->answered());

  // An answer after the deadline is dropped: the caller has had its one.
  completion->finish(7);
  io.restart();
  io.run();
  EXPECT_EQ(answers, std::vector<int>{-1});
}

TEST(Completion, AnAnswerBeforeTheDeadlineIsTheOnlyOne) {
  boost::asio::io_context io;
  std::vector<int> answers;
  auto completion = Completion<int>::start(20ms, io.get_executor(), [&](int value) { answers.push_back(value); }, [] { return -1; });
  completion->finish(7);
  io.run();
  EXPECT_EQ(answers, std::vector<int>{7}) << "the deadline does not answer again";
}

TEST(Completion, ManyThreadsOneAnswer) {
  for (int round = 0; round < 50; ++round) {
    boost::asio::io_context io;
    std::atomic<int> calls{0};
    auto completion = Completion<int>::start(1ms, io.get_executor(), [&](int) { ++calls; }, [] { return -1; });
    boost::asio::thread_pool racers(4);
    for (int i = 0; i < 4; ++i) boost::asio::post(racers, [completion, i] { completion->finish(i); });
    racers.join();
    io.run();
    EXPECT_EQ(calls.load(), 1);
  }
}

TEST(Completion, AnAnswerKnownAtOnceIsStillPosted) {
  boost::asio::io_context io;
  int answer = 0;
  lugh::answer_now<int>(io.get_executor(), [&](int value) { answer = value; }, 3);
  EXPECT_EQ(answer, 0);
  io.run();
  EXPECT_EQ(answer, 3);
}
