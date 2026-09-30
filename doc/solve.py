#!/usr/bin/env python3
"""Recover the plaintext of message.enc WITHOUT the passphrase.

Usage:
    python3 doc/solve.py [message.enc]      # decrypt + built-in self-test
    python3 doc/solve.py --no-selftest [f]  # decrypt only
    python3 doc/solve.py --selftest-only    # self-test only

The attack ("16 drawers"):
  1. Seed and feedback do not depend on the passphrase (only on the nonce, a
     constant inside the binary and the ciphertext). So for every byte we can
     compute which of the 16 table slots ("drawers") was used: idx_i.
  2. Every byte that used the same drawer was XORed with the SAME key byte.
     => 16 independent "one key byte" ciphers.
  3. For each drawer, try all 256 key bytes and keep the one that makes the
     text look most like German (space, e, n, i, ... are frequent).
No known plaintext, no passphrase, no brute force. Standard library only.
"""
import math
import os
import secrets
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))     # doc/
REPO = os.path.dirname(HERE)                          # Projektwurzel
BINARY = os.path.join(REPO, "src", "veil-x86_64")

NONCE_LEN = 8
MASK32 = 0xFFFFFFFF

# LCG constants, from the imul/add in the keystream loop.
A = 0x71FED3C5
C = 0x2A9F1B8D

# Key embedded in the binary: ENC_KEYS[3] XOR KPAD (built by update_stats).
KEY = bytes([
    0x3A, 0x91, 0x7C, 0x02, 0xE5, 0x4D, 0xB8, 0x66,
    0x1F, 0xCA, 0x09, 0x9D, 0x74, 0x20, 0xF3, 0x58,
])

# Rough German letter frequencies (percent) for the "looks like text" score.
LETTERS = "enisratdhulcgmobwfkzpvjyxq"
FREQ = [17.4, 9.8, 7.6, 7.3, 7.0, 6.5, 6.2, 5.1, 4.8, 4.4, 3.4, 3.1, 3.0,
        2.5, 2.5, 1.9, 1.9, 1.7, 1.2, 1.1, 0.7, 0.7, 0.3, 0.04, 0.03, 0.02]


class SolveError(Exception):
    pass


def _le32(b: bytes) -> int:
    return int.from_bytes(b[:4], "little")


def _build_score_table() -> list[float]:
    """log-probability of every byte value appearing in German text."""
    p: dict[int, float] = {}
    for ch, f in zip(LETTERS, FREQ):
        p[ord(ch)] = 0.80 * f / 100            # lowercase
        p[ord(ch.upper())] = 0.02 * f / 100    # uppercase
    p[ord(" ")] = 0.14
    p[ord("\n")] = 0.02
    for ch in ",.-!()':":
        p[ord(ch)] = 0.004
    return [math.log(p.get(b, 1e-6)) for b in range(256)]


SCORE = _build_score_table()


def key_fold(key: bytes = KEY) -> int:
    """The constant part of the seed: fold of the embedded key (0xC8480C4A)."""
    s = 0
    for b in key:
        s = ((s << 5) ^ (s >> 27) ^ b) & MASK32
    return s


def derive_seed(nonce: bytes) -> int:
    """Start state: nonce + binary constant only, no passphrase."""
    s = key_fold() ^ _le32(nonce[0:4])
    return (A * s + _le32(nonce[4:8])) & MASK32


def index_stream(nonce: bytes, ciphertext: bytes) -> list[int]:
    """Drawer number (state >> 28) & 0xF for every ciphertext byte."""
    state = derive_seed(nonce)
    fb = _le32(nonce[0:4])
    idx = []
    for c in ciphertext:
        state = (A * state + C) & MASK32
        state ^= fb
        idx.append((state >> 28) & 0xF)
        fb = ((fb << 8) | c) & MASK32
    return idx


def recover_table(idx: list[int], ciphertext: bytes) -> list[int]:
    """Per drawer: pick the key byte that makes its bytes look most like text."""
    S = []
    for slot in range(16):
        group = [c for c, k in zip(ciphertext, idx) if k == slot]
        S.append(max(range(256), key=lambda k: sum(SCORE[c ^ k] for c in group)))
    return S


def solve(blob: bytes) -> bytes:
    if len(blob) < NONCE_LEN:
        raise SolveError("file too short for a nonce header")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    idx = index_stream(nonce, ct)
    S = recover_table(idx, ct)
    return bytes(c ^ S[k] for c, k in zip(ct, idx))


def _read_reference(path: str) -> bytes:
    """plaintext.txt with LF line endings (git may check it out as CRLF on Windows)."""
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def _veil(*args: str) -> None:
    r = subprocess.run([BINARY, *args], capture_output=True)
    if r.returncode != 0:
        raise SolveError(f"veil {' '.join(args)} failed (rc={r.returncode}): "
                         f"{r.stderr.decode(errors='replace')}")


def selftest(rounds: int = 20) -> bool:
    """Encrypt plaintext.txt with RANDOM passphrases via the real binary and
    recover it with solve(), which never sees the passphrase."""
    ref_path = os.path.join(HERE, "plaintext.txt")
    if not os.access(BINARY, os.X_OK) or not os.path.exists(ref_path):
        print("[FAIL] self-test: binary or plaintext.txt missing", file=sys.stderr)
        return False
    plaintext = _read_reference(ref_path)
    alphabet = string.ascii_letters + string.digits
    good = 0
    with tempfile.TemporaryDirectory() as tmp:
        pt_path = os.path.join(tmp, "pt")
        ct_path = os.path.join(tmp, "ct")
        with open(pt_path, "wb") as f:
            f.write(plaintext)
        for _ in range(rounds):
            pw = "".join(secrets.choice(alphabet)
                         for _ in range(1 + secrets.randbelow(16)))
            _veil("-p", pw, pt_path, ct_path)
            with open(ct_path, "rb") as f:
                blob = f.read()
            del pw  # recovery below works on the file alone
            good += solve(blob) == plaintext
    ok = good >= rounds * 0.9
    print(f"[{'OK' if ok else 'FAIL'}] self-test: {good}/{rounds} fresh files with "
          "random passphrases recovered byte-exact without the passphrase")
    return ok


def main() -> int:
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ok = True

    if "--selftest-only" not in flags:
        enc_path = args[0] if args else os.path.join(REPO, "src", "message.enc")
        with open(enc_path, "rb") as f:
            blob = f.read()
        try:
            recovered = solve(blob)
        except SolveError as e:
            print(f"[FAIL] {e}", file=sys.stderr)
            return 1

        with open(os.path.join(HERE, "decrypted_message.txt"), "wb") as f:
            f.write(recovered)
        print("nonce (hex):", blob[:NONCE_LEN].hex())
        print("--- recovered plaintext ---")
        sys.stdout.write(recovered.decode("utf-8", errors="replace"))
        print("--- end ---")

        ref_path = os.path.join(HERE, "plaintext.txt")
        if os.path.exists(ref_path):
            expected = _read_reference(ref_path)
            if recovered == expected:
                print("[OK] recovered plaintext is byte-identical to plaintext.txt")
            else:
                print("[FAIL] recovered plaintext does NOT match plaintext.txt",
                      file=sys.stderr)
                ok = False

    if "--no-selftest" not in flags:
        ok = selftest() and ok

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
