#!/usr/bin/env python3
"""(Re)generate message.enc with the real binary.

    python3 solution/make_message.py

Writes solution/plaintext.txt (= fixed HEADER + BODY), encrypts it with
bin/veil-x86_64 under a fresh random passphrase and writes message.enc.
Checks: `veil -d` with that passphrase round-trips, and solve() recovers the
file without it. The passphrase is printed once; the attack doesn't need it.
"""
import os
import secrets
import string
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solve import BINARY, HEADER, HERE, REPO, SolveError, solve

BODY = (
    b"\n"
    b"Advanced Practical IT-Security - Reverse Engineering Challenge\n"
    b"\n"
    b"The passphrase only shapes a tiny 16-slot table. Seed and feedback\n"
    b"are public, so whoever knows how a message starts can read the rest.\n"
    b"\n"
    b"DHBW{p4ssw0rd_k3y3d_str3am_2026}\n"
)


def main() -> int:
    plaintext = HEADER + BODY
    pt_path = os.path.join(HERE, "plaintext.txt")
    enc_path = os.path.join(REPO, "message.enc")
    with open(pt_path, "wb") as f:
        f.write(plaintext)

    pw = "".join(secrets.choice(string.ascii_lowercase) for _ in range(12))
    with tempfile.TemporaryDirectory() as tmp:
        ct_path = os.path.join(tmp, "ct")
        rt_path = os.path.join(tmp, "rt")
        for attempt in range(1, 11):
            subprocess.run([BINARY, "-p", pw, pt_path, ct_path],
                           check=True, capture_output=True)
            with open(ct_path, "rb") as f:
                blob = f.read()
            try:
                assert solve(blob) == plaintext, "solver mismatch"
                break
            except SolveError as e:
                print(f"attempt {attempt}: {e} - new nonce", file=sys.stderr)
        else:
            print("[FAIL] could not produce a solvable message.enc", file=sys.stderr)
            return 1

        subprocess.run([BINARY, "-d", "-p", pw, ct_path, rt_path],
                       check=True, capture_output=True)
        with open(rt_path, "rb") as f:
            assert f.read() == plaintext, "veil -d round trip failed"

    with open(enc_path, "wb") as f:
        f.write(blob)
    print(f"wrote {enc_path} ({len(blob)} B), nonce {blob[:8].hex()}")
    print(f"passphrase used (not needed for the attack): {pw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
