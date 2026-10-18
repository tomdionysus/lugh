#!/usr/bin/env python3
"""The service stops on SIGTERM and SIGINT, promptly and cleanly.

A shutdown that hangs would stall every deploy for systemd's stop timeout.
This makes a certificate, starts the real binary on a config of its own on
a free port, waits until /health answers over TLS, sends the signal, and
requires it to exit with status 0 within 5 seconds, saying so in its log.
Adapted from blackraven-admin.

Usage: shutdown_test.py PATH_TO_LUGH
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
import urllib.request

CONFIG = """
log: {{ level: info }}
tls: {{ certificate: "{cert}", key: "{key}" }}
"""

STOP_WITHIN_S = 5.0

failures = 0


def check(name, ok, detail=""):
    global failures
    if not ok:
        failures += 1
        print(f"FAIL {name}{': ' + detail if detail else ''}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_certificate(directory):
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def run_once(binary, config_path, sig):
    port = free_port()
    log = tempfile.TemporaryFile()
    environment = {k: v for k, v in os.environ.items() if not k.startswith("LUGH_")}
    process = subprocess.Popen(
        [binary, "--config", config_path, "--address", "127.0.0.1", "--port", str(port)],
        stdout=log, stderr=subprocess.STDOUT, env=environment,
    )

    # The server's certificate is self-signed and this is about the service, not the chain.
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE

    health = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/health", timeout=1, context=insecure) as response:
                health = json.load(response)
            break
        except Exception:
            time.sleep(0.1)
    name = signal.Signals(sig).name
    check(f"{name}: the service came up", health is not None)
    check(f"{name}: /health is the service's own JSON", health == {"status": "ok"}, str(health))

    sent = time.monotonic()
    process.send_signal(sig)
    try:
        status = process.wait(timeout=STOP_WITHIN_S)
        took = time.monotonic() - sent
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        status = None
        took = None

    log.seek(0)
    text = log.read().decode(errors="replace")
    check(f"{name}: exited within {STOP_WITHIN_S:.0f} s", took is not None, "still running; killed")
    check(f"{name}: with status 0", status == 0, f"status {status}")
    check(f"{name}: saying why", f"Stopping on {name}" in text)
    check(f"{name}: and that it stopped", "Stopped" in text)
    if took is not None:
        print(f"{name}: stopped in {took * 1000:.0f} ms")
    if failures:
        print(text)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory() as directory:
        cert, key = make_certificate(directory)
        config_path = os.path.join(directory, "config.yaml")
        with open(config_path, "w") as out:
            out.write(CONFIG.format(cert=cert, key=key))
        run_once(binary, config_path, signal.SIGTERM)
        run_once(binary, config_path, signal.SIGINT)
    print("all checks passed" if failures == 0 else f"{failures} checks failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
