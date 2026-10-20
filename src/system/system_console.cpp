#include "system/system_console.h"

#include <termios.h>
#include <unistd.h>

#include <cerrno>

namespace lugh::system {

namespace {

constexpr std::size_t kMostCharacters = 1024;

void say(const std::string& text) {
  std::size_t done = 0;
  while (done < text.size()) {
    const auto put = ::write(STDERR_FILENO, text.data() + done, text.size() - done);
    if (put < 0 && errno == EINTR) continue;
    if (put <= 0) return;
    done += static_cast<std::size_t>(put);
  }
}

// Echo off for as long as it lives, and back as it was after.
class NoEcho {
 public:
  NoEcho() {
    if (::isatty(STDIN_FILENO) != 1 || ::tcgetattr(STDIN_FILENO, &_saved) != 0) return;
    termios quiet = _saved;
    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    quiet.c_lflag |= ECHONL;
    _active = ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0;
  }

  ~NoEcho() {
    if (_active) ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &_saved);
  }

  NoEcho(const NoEcho&) = delete;
  NoEcho& operator=(const NoEcho&) = delete;

 private:
  termios _saved{};
  bool _active = false;
};

// A character at a time, straight from the descriptor, so no stdio buffer holds a copy.
std::optional<Secret> read_line(const std::string& prompt) {
  say(prompt);
  NoEcho quiet;

  Secret line;
  while (true) {
    char c = 0;
    const auto got = ::read(STDIN_FILENO, &c, 1);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) return line.empty() ? std::nullopt : std::optional<Secret>(std::move(line));
    if (c == '\n') break;
    if (line.size() >= kMostCharacters) return std::nullopt;
    line.push_back(c);
  }

  // A line typed on Windows, or pasted from one.
  if (!line.empty() && line.reveal().back() == '\r') {
    Secret trimmed;
    for (const char c : line.reveal().substr(0, line.size() - 1)) trimmed.push_back(c);
    return trimmed;
  }
  return line;
}

}  // namespace

Task<std::optional<Secret>> SystemConsole::read_secret(std::string prompt) {
  co_return co_await offload(_blocking, [prompt = std::move(prompt)] { return read_line(prompt); });
}

void SystemConsole::show_secret(const std::string& label, const Secret& secret) {
  say("\n" + label + "\n\n    ");
  // Straight from locked memory to the descriptor, with no copy on the way.
  const auto text = secret.reveal();
  std::size_t done = 0;
  while (done < text.size()) {
    const auto put = ::write(STDERR_FILENO, text.data() + done, text.size() - done);
    if (put < 0 && errno == EINTR) continue;
    if (put <= 0) break;
    done += static_cast<std::size_t>(put);
  }
  say("\n\n");
}

}  // namespace lugh::system
