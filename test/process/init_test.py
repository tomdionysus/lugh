#!/usr/bin/env python3
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

"""`lugh-node init`, and the start that needs what it made.

With a credential: init writes 32 raw bytes to standard output and the
keyring to the state directory, then performs genesis, showing root's password
once on standard error and keeping it nowhere, refuses a terminal for that output, and never
replaces a keyring. A start without the credential, or with the wrong one, or
with no keyring, fails saying why; with it, the service comes up. With a
passphrase: init asks twice on standard input, and every start asks again.

Usage: init_test.py PATH_TO_LUGH
"""

import json
import os
import pty
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

failures = 0
BASE64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
        print(f"FAIL {name}{': ' + detail if detail else ''}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def environment(credentials=None):
    out = {k: v for k, v in os.environ.items() if not k.startswith("LUGH_") and k != "CREDENTIALS_DIRECTORY"}
    if credentials:
        out["CREDENTIALS_DIRECTORY"] = credentials
    return out


def make_certificate(directory):
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def root_password(stderr):
    """The password genesis showed: the indented line after its label."""
    lines = stderr.decode(errors="replace").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("The root password") and i + 2 < len(lines):
            return lines[i + 2].strip()
    return ""


def on_disk(directory, needle):
    """Whether any file under the directory holds the bytes."""
    for root, _, files in os.walk(directory):
        for name in files:
            with open(os.path.join(root, name), "rb") as f:
                if needle in f.read():
                    return True
    return False


def init(binary, state, *extra, stdin=None):
    return subprocess.run([binary, "init", "--state-directory", state, *extra], input=stdin,
                          capture_output=True, env=environment())


def serve(binary, cert, key, state, credentials=None, stdin=b""):
    """Starts the service; answers (came up, log text). Stopped either way."""
    port = free_port()
    log = tempfile.TemporaryFile()
    process = subprocess.Popen(
        [binary, "--tls-certificate", cert, "--tls-key", key, "--state-directory", state,
         "--address", "127.0.0.1", "--port", str(port)],
        stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, env=environment(credentials),
    )
    process.stdin.write(stdin)
    process.stdin.close()

    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE

    up = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=1, context=insecure) as response:
                up = json.load(response) == {"status": "ok"}
            break
        except Exception:
            time.sleep(0.1)

    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    log.seek(0)
    return up, log.read().decode(errors="replace")


def credential_mode(binary, directory, cert, key):
    state = os.path.join(directory, "credential-state")
    credentials = os.path.join(directory, "credentials")
    os.makedirs(credentials, mode=0o700)
    master = os.path.join(credentials, "lugh-master-key")

    up, text = serve(binary, cert, key, state, credentials)
    check("no keyring: the service does not start", not up)
    check("no keyring: it says to run init", "lugh-node init" in text, text)

    made = init(binary, state)
    check("init succeeds", made.returncode == 0, made.stderr.decode(errors="replace"))
    check("init writes 32 bytes to standard output", len(made.stdout) == 32, f"{len(made.stdout)} bytes")
    check("init makes the keyring", os.path.isfile(os.path.join(state, "keyring")))
    check("the keyring is private", oct(os.stat(os.path.join(state, "keyring")).st_mode & 0o777) == "0o600")
    check("the state directory is private", oct(os.stat(state).st_mode & 0o777) == "0o700")
    check("init does not echo the key", made.stdout.hex() not in made.stderr.decode(errors="replace"))
    password = root_password(made.stderr)
    check("genesis shows root's password", len(password) == 24 and set(password) <= BASE64URL, made.stderr.decode(errors="replace"))
    check("genesis does not put it on standard output", password.encode() not in made.stdout)
    check("nor anywhere on disk", password and not on_disk(state, password.encode()))
    check("genesis makes the store", os.path.isfile(os.path.join(state, "store", "users.log")))
    with open(master, "wb") as out:
        out.write(made.stdout)
    keyring = open(os.path.join(state, "keyring"), "rb").read()
    check("the master key is not in the keyring", made.stdout not in keyring)

    again = init(binary, state)
    check("a second init fails", again.returncode != 0)
    check("a second init writes no key", again.stdout == b"")
    check("a second init makes no second root", root_password(again.stderr) == "")
    check("a second init leaves the keyring", open(os.path.join(state, "keyring"), "rb").read() == keyring)

    up, text = serve(binary, cert, key, state)
    check("no credential: the service does not start", not up)
    check("no credential: it names the credential", "lugh-master-key" in text, text)

    up, text = serve(binary, cert, key, state, credentials)
    check("with the credential: the service comes up", up, text)
    check("with the credential: it says the keyring opened", "Opened keyring" in text, text)

    with open(master, "wb") as out:
        out.write(os.urandom(32))
    up, text = serve(binary, cert, key, state, credentials)
    check("the wrong credential: the service does not start", not up)
    check("the wrong credential: it says so", "does not open" in text, text)

    # A terminal on standard output would show the key: refused, and nothing made.
    tty_state = os.path.join(directory, "tty-state")
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(binary, [binary, "init", "--state-directory", tty_state], environment())
    output = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    _, status = os.waitpid(pid, 0)
    check("init to a terminal fails", os.waitstatus_to_exitcode(status) != 0)
    check("init to a terminal says why", b"terminal" in output, output.decode(errors="replace"))
    check("init to a terminal makes nothing", not os.path.exists(os.path.join(tty_state, "keyring")))


def passphrase_mode(binary, directory, cert, key):
    state = os.path.join(directory, "passphrase-state")
    passphrase = b"correct horse battery staple"

    short = init(binary, state, "--passphrase", stdin=b"too short\ntoo short\n")
    check("a short passphrase is refused", short.returncode != 0 and b"16 characters" in short.stderr, short.stderr.decode())

    differ = init(binary, state, "--passphrase", stdin=passphrase + b"\n" + passphrase + b"!\n")
    check("passphrases that differ are refused", differ.returncode != 0 and b"differ" in differ.stderr, differ.stderr.decode())
    check("and nothing is made", not os.path.exists(os.path.join(state, "keyring")))

    made = init(binary, state, "--passphrase", stdin=passphrase + b"\n" + passphrase + b"\n")
    check("init with a passphrase succeeds", made.returncode == 0, made.stderr.decode(errors="replace"))
    check("init with a passphrase writes nothing to standard output", made.stdout == b"")
    check("init with a passphrase makes the keyring", os.path.isfile(os.path.join(state, "keyring")))
    password = root_password(made.stderr)
    check("init with a passphrase: genesis shows root's password", len(password) == 24, made.stderr.decode(errors="replace"))

    up, text = serve(binary, cert, key, state, stdin=passphrase + b"\n")
    check("with the passphrase: the service comes up", up, text)

    up, text = serve(binary, cert, key, state, stdin=b"not the passphrase at all\n")
    check("the wrong passphrase: the service does not start", not up)
    check("the wrong passphrase: it says so", "does not open" in text, text)

    up, text = serve(binary, cert, key, state, stdin=b"")
    check("no passphrase: the service does not start", not up)
    check("no passphrase: it says so", "none was given" in text, text)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as directory:
        cert, key = make_certificate(directory)
        credential_mode(binary, directory, cert, key)
        passphrase_mode(binary, directory, cert, key)
    print("all checks passed" if failures == 0 else f"{failures} checks failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
