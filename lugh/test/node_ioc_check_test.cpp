//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifndef LUGH_SOURCE_DIR
#error "LUGH_SOURCE_DIR must name the source tree"
#endif

// Inversion of control, enforced. Outside the composition root and the adapters, nothing
// names a clock, the environment, a thread, a process or a file write, a concrete adapter
// or sink, or a lock that is not Dannan's. Adapted from blackraven-admin's ioc-check,
// itself from T.O.M.S's ioc-acceptance; a rule from the first commit, so any hit fails.
// The library and the node are checked; the tests and fuzz targets are not the service.
// Comments are not searched: a comment naming getenv is not a call.

namespace {

struct Pattern {
  std::string name;
  // Plain text every match contains: only a line holding one goes to the regex, which is
  // slow, and which stays the judge.
  std::vector<std::string> needles;
  std::regex regex;
  // A line the pattern must catch, so a pattern that has stopped matching anything, or whose
  // needles miss what its regex catches, fails here rather than passing everything.
  std::string example;

  bool matches(const std::string& line) const {
    const auto holds = [&](const std::string& needle) { return line.find(needle) != std::string::npos; };
    return std::any_of(needles.begin(), needles.end(), holds) && std::regex_search(line, regex);
  }
};

const std::vector<Pattern>& patterns() {
  static const std::vector<Pattern> all = {
      // A clock's now(), not a member of ours that happens to be called now.
      {"::now()", {"::now()"}, std::regex(R"(\b(?:\w+_clock|Clock)::now\(\))"), "auto t = std::chrono::system_clock::now();"},
      {"std::time(", {"std::time("}, std::regex(R"(std::time\()"), "const auto t = std::time(nullptr);"},
      {"getenv", {"getenv"}, std::regex(R"(\bgetenv\b)"), "const char* home = std::getenv(\"HOME\");"},
      {"gethostname", {"gethostname"}, std::regex(R"(\bgethostname\b)"), "gethostname(name, sizeof name);"},
      {"thread", {"thread"}, std::regex(R"(std::j?thread\b|\bthread_pool\b)"), "std::thread worker([] {});"},
      {"fork/exec/popen",
       {"fork", "exec", "popen", "posix_spawn", "system"},
       std::regex(R"(\b(?:fork|vfork|execv\w*|execl\w*|popen|posix_spawn\w*|system)\s*\()"),
       "if (fork() == 0) {"},
      {"file write",
       {"ofstream", "fopen", "filesystem::"},
       std::regex(
           R"(std::ofstream\b|\bfopen\s*\(|std::filesystem::(?:rename|remove|remove_all|create_directories|create_directory|copy|copy_file|permissions)\b)"),
       "std::filesystem::remove_all(path);"},
      {"randomness", {"RAND_bytes", "random_device"}, std::regex(R"(\bRAND_bytes\b|std::random_device\b)"), "RAND_bytes(out, 32);"},
      // A POSIX call on a file, at global scope: ::open, ::write, ::rename and the rest.
      {"POSIX file call",
       {"::open", "::creat", "::write", "::unlink", "::rename", "::link", "::mkdir", "::fsync", "::ftruncate"},
       std::regex(R"((?:^|[^\w.>:])::(?:open|creat|write|unlink|rename|link|mkdir|fsync|ftruncate)\s*\()"),
       "const auto put = ::write(fd, data, size);"},
      {"terminal", {"isatty", "tcgetattr", "tcsetattr"}, std::regex(R"(\b(?:isatty|tcgetattr|tcsetattr)\b)"), "if (::isatty(1) == 1) {"},
      // The process's own memory: locking, mapping and limits.
      {"process memory",
       {"CRYPTO_secure_malloc_init", "mlock", "mmap", "setrlimit"},
       std::regex(R"(\bCRYPTO_secure_malloc_init\b|\bmlock(?:all)?\b|\bmmap\b|\bsetrlimit\b)"),
       "setrlimit(RLIMIT_CORE, &none);"},
      // The concrete adapters and sinks, by name: everything else takes the port.
      {"concrete adapter",
       {"System", "ConsoleSink", "JsonSink", "console_sink"},
       std::regex(R"(\bSystem(?:Environment|Files|Console)\b|\b(?:ConsoleSink|JsonSink|console_sink)\b)"),
       "auto files = std::make_shared<SystemFiles>(pool);"},
      // Dannan's clocks are the process's: only the composition root reaches for them.
      {"Dannan clock",
       {"SteadyTimeSource", "SystemWallClock", "steady_time_source", "system_wall_clock"},
       std::regex(R"(\b(?:SteadyTimeSource|SystemWallClock|steady_time_source|system_wall_clock)\b)"),
       "const auto& wall = dannan::contract::system_wall_clock();"},
      // Every lock is one of Dannan's (dannan/contract/thread_safety.h), so the thread-safety
      // analysis sees every one.
      {"unchecked lock",
       {"std::mutex", "std::shared_mutex", "std::recursive_mutex", "std::lock_guard", "std::unique_lock", "std::scoped_lock", "std::shared_lock"},
       std::regex(R"(std::(?:mutex|shared_mutex|recursive_mutex|lock_guard|unique_lock|scoped_lock|shared_lock)\b)"),
       "std::lock_guard<std::mutex> lock(_mutex);"},
  };
  return all;
}

// Exempt from every pattern: the composition root, and the adapters, whose job is to be the
// one place that names the real thing. Add each adapter here as it is written.
const std::set<std::string> kAdapters = {
    "tools/lugh_node.cpp",
    "lugh/system/system_environment.h",
    "lugh/system/system_environment.cpp",
    "lugh/system/system_files.h",  // SystemFiles: the keyring on disk
    "lugh/system/system_files.cpp",
    "lugh/system/system_console.h",  // SystemConsole: a passphrase typed without echo
    "lugh/system/system_console.cpp",
};

// The text with // and /* */ comments blanked, line breaks kept, string literals kept.
std::string strip_comments(const std::string& text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t i = 0; i < text.size();) {
    if (text[i] == '"') {
      std::size_t j = i + 1;
      while (j < text.size() && text[j] != '"') j += text[j] == '\\' ? 2 : 1;
      out.append(text, i, std::min(j + 1, text.size()) - i);
      i = j + 1;
    } else if (text.compare(i, 2, "//") == 0) {
      const auto end = text.find('\n', i);
      i = end == std::string::npos ? text.size() : end;
    } else if (text.compare(i, 2, "/*") == 0) {
      const auto close = text.find("*/", i + 2);
      const auto end = close == std::string::npos ? text.size() : close + 2;
      out.append(static_cast<std::size_t>(std::count(text.begin() + static_cast<std::ptrdiff_t>(i), text.begin() + static_cast<std::ptrdiff_t>(end), '\n')),
                 '\n');
      i = end;
    } else {
      out.push_back(text[i++]);
    }
  }
  return out;
}

// Every .cpp and .h of the library and the node, by repository-relative path.
std::vector<std::string> service_sources(const std::filesystem::path& root) {
  std::vector<std::string> out;
  for (const auto* top : {"lugh", "tools"}) {
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root / top)) {
      if (!entry.is_regular_file()) continue;
      const auto extension = entry.path().extension();
      if (extension != ".cpp" && extension != ".h") continue;
      const auto relative = entry.path().lexically_relative(root).generic_string();
      if (relative.rfind("lugh/test/", 0) == 0 || relative.rfind("lugh/fuzz/", 0) == 0) continue;
      out.push_back(relative);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

}  // namespace

TEST(IocCheck, EveryPatternCatchesWhatItForbids) {
  for (const auto& pattern : patterns()) EXPECT_TRUE(pattern.matches(pattern.example)) << pattern.name;
}

TEST(IocCheck, OursAreNotTheirs) {
  // A member called now(), a namespace-qualified call, and a word that only contains one.
  const auto& all = patterns();
  const auto find = [&](const std::string& name) { return *std::find_if(all.begin(), all.end(), [&](const Pattern& p) { return p.name == name; }); };
  EXPECT_FALSE(find("::now()").matches("const auto t = _time.now();"));
  EXPECT_FALSE(find("POSIX file call").matches("socket.write(buffer);"));
  EXPECT_FALSE(find("POSIX file call").matches("boost::asio::write(stream, buffer);"));
  EXPECT_FALSE(find("unchecked lock").matches("dannan::contract::Lock lock(_mutex);"));
  EXPECT_FALSE(find("fork/exec/popen").matches("const auto ecosystem = 1;"));
}

TEST(IocCheck, CommentsAreNotSearched) {
  EXPECT_EQ(strip_comments("a; // getenv\nb;"), "a; \nb;");
  EXPECT_EQ(strip_comments("a; /* getenv\n fork() */ b;"), "a; \n b;");
  EXPECT_EQ(strip_comments("auto s = \"// not a comment\";"), "auto s = \"// not a comment\";");
  EXPECT_EQ(strip_comments("auto s = \"a \\\" // b\"; // c"), "auto s = \"a \\\" // b\"; ");
}

TEST(IocCheck, NothingOutsideTheCompositionRootAndTheAdapters) {
  const std::filesystem::path root(LUGH_SOURCE_DIR);
  const auto sources = service_sources(root);
  ASSERT_GT(sources.size(), 50u) << "the source tree was not found at " << root;
  for (const auto& adapter : kAdapters) EXPECT_TRUE(std::filesystem::exists(root / adapter)) << adapter << " is listed as an adapter and does not exist";

  std::vector<std::string> hits;
  for (const auto& relative : sources) {
    if (kAdapters.count(relative) != 0) continue;
    std::ifstream in(root / relative, std::ios::binary);
    std::stringstream text;
    text << in.rdbuf();
    std::istringstream lines(strip_comments(text.str()));
    std::string line;
    for (int number = 1; std::getline(lines, line); ++number) {
      for (const auto& pattern : patterns()) {
        if (pattern.matches(line)) hits.push_back(relative + ":" + std::to_string(number) + ": " + pattern.name + ": " + line);
      }
    }
  }
  std::string report;
  for (const auto& hit : hits) report += hit + "\n";
  EXPECT_TRUE(hits.empty()) << "outside the composition root (tools/lugh_node.cpp) and the adapters, nothing may name these:\n" << report;
}
