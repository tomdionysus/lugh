#!/usr/bin/env python3
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

"""/api/v1 through the real binary, over TLS, before P6.

A node made with `lugh-node init` has root and nothing else: no token, key or
setting opens the API. Until sessions and OAuth tokens resolve a caller (P6),
every route refuses everyone with 401, whatever is presented, and an unknown
path is still a JSON 404.

Usage: api_test.py PATH_TO_LUGH
"""

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

failures = 0

INSECURE = ssl.create_default_context()
INSECURE.check_hostname = False
INSECURE.verify_mode = ssl.CERT_NONE


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
        print(f"FAIL {name}{': ' + detail if detail else ''}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def environment(credentials):
    out = {k: v for k, v in os.environ.items() if not k.startswith("LUGH_") and k != "CREDENTIALS_DIRECTORY"}
    out["CREDENTIALS_DIRECTORY"] = credentials
    return out


def request(port, method, path, authorization=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=data, method=method)
    if authorization:
        req.add_header("Authorization", authorization)
    try:
        with urllib.request.urlopen(req, timeout=5, context=INSECURE) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, response.headers
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else None, error.headers


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as directory:
        cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = os.path.join(directory, "state")
        credentials = os.path.join(directory, "credentials")
        os.makedirs(credentials, mode=0o700)
        made = subprocess.run([binary, "init", "--state-directory", state], capture_output=True, env=environment(credentials))
        check("init", made.returncode == 0, made.stderr.decode(errors="replace"))
        with open(os.path.join(credentials, "lugh-master-key"), "wb") as out:
            out.write(made.stdout)
        password = [line.strip() for line in made.stderr.decode(errors="replace").splitlines() if line.startswith("    ")]
        password = password[0] if password else "none"

        port = free_port()
        log = tempfile.TemporaryFile()
        process = subprocess.Popen([binary, "--tls-certificate", cert, "--tls-key", key, "--state-directory", state,
                                    "--address", "127.0.0.1", "--port", str(port)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=environment(credentials))
        deadline = time.monotonic() + 15
        up = False
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=1, context=INSECURE):
                    up = True
                break
            except Exception:
                time.sleep(0.1)
        check("comes up after genesis", up)

        for authorization in (None, "Bearer anything", "Bearer " + password, "Basic " + password):
            for method, path in (("GET", "/api/v1/users"), ("POST", "/api/v1/users"), ("GET", "/api/v1/audit")):
                status, body, headers = request(port, method, path, authorization, {} if method == "POST" else None)
                check(f"{method} {path} with {authorization and authorization.split()[0]}: 401",
                      status == 401 and body["error"]["code"] == "unauthorized", f"{status} {body}")
        check("401 says how", headers.get("WWW-Authenticate") == 'Bearer realm="lugh"', str(headers))
        status, body, _ = request(port, "GET", "/api/v1/nothing")
        check("an unknown path: a JSON 404", status == 404 and body["error"]["code"] == "not_found", f"{status} {body}")

        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
        log.seek(0)
        text = log.read().decode(errors="replace")
        check("the service says who it holds", "1 users, 1 groups" in text, text)
        check("root's password is never logged", password not in text)

    print("all checks passed" if failures == 0 else f"{failures} checks failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
