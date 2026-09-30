#!/usr/bin/env python3
"""Recover the plaintext of message.enc WITHOUT the passphrase.

Usage:
    python3 solution/solve.py [message.enc]      # decrypt + built-in self-test
    python3 solution/solve.py --no-selftest [f]  # decrypt only
    python3 solution/solve.py --selftest-only    # self-test only

The attack ("S-box leak"):
  * The start state only depends on the nonce (first 8 bytes of the file) and
    a constant folded from the key embedded in the binary.
  * The feedback only consumes ciphertext bytes, which we have.
  => the whole index sequence (state >> 28) & 0xF is computable for the
     entire file, no passphrase involved.
  * The passphrase only keys a 16-slot table S. Every veil message starts with
    the same fixed, public HEADER, so S[idx_i] = P_i ^ C_i over the header.
    Once all 16 slots appeared in the header, S is fully known and the rest of
    the file decrypts. No passphrase, no brute force.

Only the Python standard library is used. The passphrase appears nowhere.
"""
import os
import secrets
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BINARY = os.path.join(REPO, "bin", "veil-x86_64")

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

# Fixed, publicly documented header every veil message starts with (README).
HEADER = (
    b"-----BEGIN VEIL MESSAGE-----\n"
    b"Format: veil/1 stream transform, 8-byte nonce as prefix\n"
    b"Origin: DHBW Mannheim - Advanced Practical IT-Security\n"
    b"Notice: this header is fixed and identical in every\n"
    b"veil message. The body follows the marker.\n"
    b"-----BEGIN BODY-----\n"
)
assert len(HEADER) == 256, len(HEADER)


class SolveError(Exception):
    pass


def _le32(b: bytes) -> int:
    return int.from_bytes(b[:4], "little")


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
    """Table index (state >> 28) & 0xF for every ciphertext byte."""
    state = derive_seed(nonce)
    fb = _le32(nonce[0:4])
    idx = []
    for c in ciphertext:
        state = (A * state + C) & MASK32
        state ^= fb
        idx.append((state >> 28) & 0xF)
        fb = ((fb << 8) | c) & MASK32
    return idx


def recover_table(idx: list[int], ciphertext: bytes, header: bytes) -> list[int]:
    """Read S[idx] = P ^ C off the known header; all 16 slots must show up."""
    if len(ciphertext) < len(header):
        raise SolveError(f"ciphertext ({len(ciphertext)} B) shorter than the "
                         f"known header ({len(header)} B)")
    S = [None] * 16
    for i, (p, c) in enumerate(zip(header, ciphertext)):
        k = idx[i]
        if S[k] is None:
            S[k] = p ^ c
        elif S[k] != p ^ c:
            raise SolveError(f"inconsistent table slot {k} at offset {i}: "
                             "file does not start with the known header or "
                             "the cipher model is wrong")
    missing = [k for k in range(16) if S[k] is None]
    if missing:
        raise SolveError(f"header covers only {16 - len(missing)}/16 table "
                         f"indices (missing {missing}) - lengthen the header")
    return S


def solve(blob: bytes, header: bytes = HEADER) -> bytes:
    if len(blob) < NONCE_LEN:
        raise SolveError("file too short for a nonce header")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    idx = index_stream(nonce, ct)
    S = recover_table(idx, ct, header)
    return bytes(c ^ S[k] for c, k in zip(ct, idx))


def _veil(*args: str) -> None:
    r = subprocess.run([BINARY, *args], capture_output=True)
    if r.returncode != 0:
        raise SolveError(f"veil {' '.join(args)} failed (rc={r.returncode}): "
                         f"{r.stderr.decode(errors='replace')}")


def selftest(rounds: int = 20) -> bool:
    """Encrypt HEADER + random body with a RANDOM passphrase via the real
    binary, then recover it with solve() - which never sees the passphrase."""
    if not os.access(BINARY, os.X_OK):
        print(f"[FAIL] self-test: {BINARY} is not executable here", file=sys.stderr)
        return False
    alphabet = string.ascii_letters + string.digits
    with tempfile.TemporaryDirectory() as tmp:
        pt_path = os.path.join(tmp, "pt")
        ct_path = os.path.join(tmp, "ct")
        for r in range(rounds):
            pw = "".join(secrets.choice(alphabet)
                         for _ in range(1 + secrets.randbelow(16)))
            plaintext = HEADER + secrets.token_bytes(secrets.randbelow(512))
            with open(pt_path, "wb") as f:
                f.write(plaintext)
            _veil("-p", pw, pt_path, ct_path)
            with open(ct_path, "rb") as f:
                blob = f.read()
            del pw  # recovery below works on the file alone
            try:
                got = solve(blob)
            except SolveError as e:
                print(f"[FAIL] self-test round {r + 1}: {e}", file=sys.stderr)
                return False
            if got != plaintext:
                print(f"[FAIL] self-test round {r + 1}: recovered plaintext differs",
                      file=sys.stderr)
                return False
    print(f"[OK] self-test: {rounds}/{rounds} fresh files with random passphrases "
          "recovered byte-exact without the passphrase")
    return True


def main() -> int:
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ok = True

    if "--selftest-only" not in flags:
        enc_path = args[0] if args else os.path.join(REPO, "message.enc")
        with open(enc_path, "rb") as f:
            blob = f.read()
        try:
            recovered = solve(blob)
        except SolveError as e:
            print(f"[FAIL] {e}", file=sys.stderr)
            return 1

        with open(os.path.join(HERE, "recovered.txt"), "wb") as f:
            f.write(recovered)
        print("nonce (hex):", blob[:NONCE_LEN].hex())
        print("--- recovered plaintext ---")
        sys.stdout.write(recovered.decode("utf-8", errors="replace"))
        print("--- end ---")

        ref_path = os.path.join(HERE, "plaintext.txt")
        if os.path.exists(ref_path):
            with open(ref_path, "rb") as f:
                expected = f.read()
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
