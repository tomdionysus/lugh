#!/usr/bin/env python3
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

"""Inversion of control, enforced.

Outside the composition root and the adapters, nothing names a clock, the
environment, a thread, a process or a file write, and nothing names a
concrete adapter. Adapted from blackraven-admin's scripts/ioc-check.py,
itself from T.O.M.S's ioc-acceptance.py; a rule from the first commit, so
any hit fails.

Comments are not searched: a comment naming getenv is not a call.

Usage: lugh_ioc_check.py [ROOT]
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
    # A POSIX call on a file, at global scope: ::open, ::write, ::rename and the rest.
    "POSIX file call": r"(?<![\w.>:])::(?:open|creat|write|unlink|rename|link|mkdir|fsync|ftruncate)\s*\(",
    "terminal": r"\b(?:isatty|tcgetattr|tcsetattr)\b",
    # The process's own memory: locking, mapping and limits.
    "process memory": r"\bCRYPTO_secure_malloc_init\b|\bmlock(?:all)?\b|\bmmap\b|\bsetrlimit\b",
    # The concrete adapters, by name: everything else takes the port.
    "concrete adapter": r"\bSystem(?:Environment|Files|Console)\b|\b(?:ConsoleSink|JsonSink|console_sink)\b",
    # Dannan's clocks are the process's: only the composition root reaches for them.
    "Dannan clock": r"\b(?:SteadyTimeSource|SystemWallClock|steady_time_source|system_wall_clock)\b",
    # Every lock is one of Dannan's (dannan/contract/thread_safety.h), so the thread-safety
    # analysis sees every one.
    "unchecked lock": r"std::(?:mutex|shared_mutex|recursive_mutex|lock_guard|unique_lock|scoped_lock|shared_lock)\b",
}

# Exempt from every pattern: the composition root, and the adapters, whose job
# is to be the one place that names the real thing. Add each adapter here as
# it is written.
ADAPTERS = {
    "tools/lugh_node.cpp",
    "lugh/system/system_environment.h",
    "lugh/system/system_environment.cpp",
    "lugh/system/system_files.h",  # SystemFiles: the keyring on disk
    "lugh/system/system_files.cpp",
    "lugh/system/system_console.h",  # SystemConsole: a passphrase typed without echo
    "lugh/system/system_console.cpp",
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
    # The library and the service; the tests and fuzz targets are not the service.
    files = sorted(
        path
        for path in [*(root / "lugh").rglob("*"), *(root / "tools").rglob("*")]
        if path.suffix in (".cpp", ".h") and not path.relative_to(root).as_posix().startswith(("lugh/test/", "lugh/fuzz/"))
    )

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
        print(f"FAIL: {len(hits)} hits; outside the composition root (tools/lugh_node.cpp) and the adapters, nothing may name these")
        return 1
    print(f"ok: {len(files)} files, nothing outside the composition root (tools/lugh_node.cpp) and the adapters names a clock, the environment, a thread, a process, a file write or an unchecked lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
