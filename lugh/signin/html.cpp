//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/signin/html.h"

namespace lugh::signin {

std::string escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char c : text) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&#39;";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

std::string page(std::string_view title, std::string_view body, std::string_view head) {
  std::string out =
      "<!doctype html>\n"
      "<html lang=\"en\">\n"
      "<head>\n"
      "<meta charset=\"utf-8\">\n"
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
      "<meta name=\"referrer\" content=\"no-referrer\">\n"
      "<title>";
  out += escape(title);
  out +=
      " - Lugh</title>\n"
      "<link rel=\"stylesheet\" href=\"/signin/style.css\">\n";
  out += head;
  out +=
      "</head>\n"
      "<body>\n"
      "<main class=\"card\">\n"
      "<p class=\"wordmark\">Lugh</p>\n"
      "<h1>";
  out += escape(title);
  out += "</h1>\n";
  out += body;
  out +=
      "</main>\n"
      "</body>\n"
      "</html>\n";
  return out;
}

std::string_view stylesheet() {
  return R"(:root {
  --bg: #0c0e10;
  --surface: #15181c;
  --surface-raised: #1c2026;
  --border: #272c33;
  --text: #e8ebee;
  --text-muted: #939da7;
  --good: #00cc44;
  --warn: #ffb020;
  --bad: #ff4d4d;
  --radius: 14px;
  --gap: 16px;
  color-scheme: dark;
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); }
body {
  font-family: "Roboto", system-ui, sans-serif;
  font-size: 16px;
  line-height: 1.5;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--gap);
}
.card {
  width: 100%;
  max-width: 26rem;
  background: color-mix(in srgb, var(--surface) 92%, transparent);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: calc(var(--gap) * 2);
}
.wordmark {
  margin: 0 0 var(--gap);
  text-transform: uppercase;
  letter-spacing: 0.2em;
  font-size: 0.8rem;
  color: var(--text-muted);
}
h1 { margin: 0 0 var(--gap); font-size: 1.4rem; font-weight: 500; }
p { margin: 0 0 var(--gap); }
.muted { color: var(--text-muted); }
label {
  display: block;
  margin: 0 0 calc(var(--gap) / 4);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.75rem;
  color: var(--text-muted);
}
input[type=text], input[type=password] {
  width: 100%;
  margin: 0 0 var(--gap);
  padding: 0.7rem 0.8rem;
  border-radius: calc(var(--radius) / 2);
  border: 1px solid var(--border);
  background: var(--surface-raised);
  color: var(--text);
  font: inherit;
}
input:focus { outline: 2px solid color-mix(in srgb, var(--good) 60%, transparent); outline-offset: 1px; }
button {
  width: 100%;
  padding: 0.75rem;
  border: 0;
  border-radius: 999px;
  background: var(--good);
  color: var(--bg);
  font: inherit;
  font-weight: 600;
  cursor: pointer;
}
a { color: var(--good); }
.notice {
  padding: 0.7rem 0.9rem;
  border-radius: calc(var(--radius) / 2);
  margin: 0 0 var(--gap);
  background: color-mix(in srgb, var(--bad) 14%, transparent);
  border: 1px solid color-mix(in srgb, var(--bad) 40%, transparent);
}
.notice.warn {
  background: color-mix(in srgb, var(--warn) 14%, transparent);
  border-color: color-mix(in srgb, var(--warn) 40%, transparent);
}
.secret {
  font-family: ui-monospace, "SFMono-Regular", monospace;
  font-size: 1.05rem;
  letter-spacing: 0.08em;
  word-break: break-all;
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: calc(var(--radius) / 2);
  padding: 0.7rem 0.9rem;
  margin: 0 0 var(--gap);
}
ul.codes { list-style: none; padding: 0; columns: 2; }
.alternative { margin-top: var(--gap); font-size: 0.9rem; }
)";
}

void write_page(const std::shared_ptr<http::HttpResponse>& response, http::status status, const std::string& html) {
  response->result(status);
  response->set(http::field::content_type, "text/html; charset=utf-8");
  response->set(http::field::cache_control, "no-store");
  response->set("Content-Security-Policy", kPagePolicy);
  response->body() = html;
}

void write_redirect(const std::shared_ptr<http::HttpResponse>& response, std::string_view location) {
  response->result(http::status::see_other);
  response->set(http::field::location, location);
  response->set(http::field::cache_control, "no-store");
  response->set("Content-Security-Policy", kPagePolicy);
  response->body().clear();
}

void write_leaving(const std::shared_ptr<http::HttpResponse>& response, std::string_view location) {
  const auto safe = escape(location);
  write_page(response, http::status::ok,
             page("Continuing", "<p><a class=\"leaving\" href=\"" + safe + "\">Continue to the application</a></p>\n",
                  "<meta http-equiv=\"refresh\" content=\"0; url=" + safe + "\">\n"));
}

}  // namespace lugh::signin
