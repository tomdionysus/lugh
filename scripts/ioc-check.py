#!/usr/bin/env python3
"""Inversion of control, enforced.

Outside the composition root and the adapters, nothing names a clock, the
environment, a thread, a process or a file write, and nothing names a
concrete adapter. Adapted from blackraven-admin's scripts/ioc-check.py,
itself from T.O.M.S's ioc-acceptance.py; a rule from the first commit, so
any hit fails.

Comments are not searched: a comment naming getenv is not a call.

Usage: ioc-check.py [ROOT]
"""

import pathlib
import re
import sys

PATTERNS = {
    # A clock's now(), not a member of ours that happens to be called now.
    "::now()": r"\b(?:\w+_clock|Clock)::now\(\)",
    "std::time(": r"std::time\(",
    "getenv": r"\bgetenv\b",
    "gethostname": r"\bgethostname\b",
    "thread": r"std::j?thread\b|\bthread_pool\b",
    "fork/exec/popen": r"\b(?:fork|vfork|execv\w*|execl\w*|popen|posix_spawn\w*|system)\s*\(",
    "file write": r"std::ofstream\b|\bfopen\s*\(|std::filesystem::(?:rename|remove|remove_all|create_directories|create_directory|copy|copy_file|permissions)\b",
    "randomness": r"\bRAND_bytes\b|std::random_device\b",
    # The concrete adapters, by name: everything else takes the port.
    "concrete adapter": r"\bSystem(?:Clock|Environment|Random)\b|\bLoggerStdIO\b",
}

# Exempt from every pattern: the composition root, and the adapters, whose job
# is to be the one place that names the real thing. Add each adapter here as
# it is written.
ADAPTERS = {
    "src/main.cpp",
    "src/system/system_clock.h",
    "src/system/system_clock.cpp",
    "src/system/system_environment.h",
    "src/system/system_environment.cpp",
    "src/loggers/logger_stdio.h",  # LoggerStdIO: stamps each line with the time
    "src/loggers/logger_stdio.cpp",
    "src/system/system_random.h",  # SystemRandom: OpenSSL's CSPRNG
    "src/system/system_random.cpp",
}

# Exempt from one pattern only.
EXEMPT = {}


def strip_comments(text):
    """The text with // and /* */ comments blanked, string literals kept."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)
    files = sorted(path for path in (root / "src").rglob("*") if path.suffix in (".cpp", ".h"))

    hits = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if relative in ADAPTERS:
            continue
        lines = strip_comments(path.read_text(errors="replace")).splitlines()
        for name, pattern in PATTERNS.items():
            if relative in EXEMPT.get(name, ()):
                continue
            for number, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    hits.append(f"{relative}:{number}: {name}: {line.strip()}")

    for hit in hits:
        print(hit)
    if hits:
        print(f"FAIL: {len(hits)} hits; outside main.cpp and the adapters, nothing may name these")
        return 1
    print(f"ok: {len(files)} files, nothing outside main.cpp and the adapters names a clock, the environment, a thread, a process or a file write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
