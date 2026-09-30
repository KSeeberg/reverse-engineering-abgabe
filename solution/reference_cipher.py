#!/usr/bin/env python3
"""Clean reference implementation of the `veil` stream cipher ("S-box leak" variant).

This mirrors src/veil.c byte-for-byte. It is documentation only: the solver
(solve.py) does NOT use it and never needs the passphrase.

  1. passphrase -> FNV-1a-64 digest (tally_bytes)
       * profile : 16 bytes that key a 16-slot RC4-style table (init_table)
       * pk32    : still computed, but only dumped into a noise sink
  2. seed = fold(embedded_key) ^ nonce, LCG-mixed        (derive_seed)
       -> depends on nonce + binary constant only, NOT on the passphrase
  3. per byte:
       state = A*state + C
       state ^= fb                      # fb = rolling ciphertext feedback
       ks    = S[(state >> 28) & 0xF]   # 16-slot table, top nibble picks
       out   = in ^ ks
       fb    = ((fb << 8) | ciphertext_byte) & 0xFFFFFFFF

The table: KSA over a 16-entry permutation P (mod 16), then
S[i] = (P[i] << 4) | P[i ^ 0xA], so every keystream byte is a full byte.
"""

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

# LCG constants (the imul/add in format_output).
A = 0x71FED3C5
C = 0x2A9F1B8D

# The embedded 16-byte key (ENC_KEYS[3] XOR KPAD, reconstructed in update_stats).
KEY = bytes([
    0x3A, 0x91, 0x7C, 0x02, 0xE5, 0x4D, 0xB8, 0x66,
    0x1F, 0xCA, 0x09, 0x9D, 0x74, 0x20, 0xF3, 0x58,
])

FNV_OFFSET = 1469598103934665603
FNV_PRIME  = 1099511628211


def _le32(b: bytes) -> int:
    return int.from_bytes(b[:4], "little")


def tally_bytes(pw: bytes):
    """FNV-1a-64 of the passphrase -> (16-byte profile, 32-bit pk32)."""
    h = FNV_OFFSET
    for b in pw:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    h2 = ((h * FNV_PRIME) & MASK64) ^ (h >> 29)
    profile = bytes([(h >> (8 * i)) & 0xFF for i in range(8)] +
                    [(h2 >> (8 * i)) & 0xFF for i in range(8)])
    pk32 = (h ^ (h >> 32)) & MASK32
    return profile, pk32


def init_table(profile: bytes):
    """RC4-style key schedule over 16 slots -> 16-byte table."""
    P = list(range(16))
    j = 0
    for i in range(16):
        j = (j + P[i] + profile[i]) & 0xF
        P[i], P[j] = P[j], P[i]
    return [(P[i] << 4) | P[i ^ 0xA] for i in range(16)]


def derive_seed(key: bytes, nonce: bytes) -> int:
    s = 0
    for b in key:
        s = ((s << 5) ^ (s >> 27) ^ b) & MASK32
    s ^= _le32(nonce[0:4])
    s = (A * s + _le32(nonce[4:8])) & MASK32
    return s


def transform(data: bytes, key: bytes, nonce: bytes, pw: bytes, decrypt: bool) -> bytes:
    profile, _pk32 = tally_bytes(pw)
    S = init_table(profile)
    state = derive_seed(key, nonce)
    fb = _le32(nonce[0:4])
    out = bytearray(len(data))
    for i, b in enumerate(data):
        state = (A * state + C) & MASK32
        state ^= fb
        ks = S[(state >> 28) & 0xF]
        out[i] = b ^ ks
        cbyte = data[i] if decrypt else out[i]   # the ciphertext byte
        fb = ((fb << 8) | cbyte) & MASK32
    return bytes(out)


def encrypt(plaintext: bytes, key: bytes, nonce: bytes, pw: bytes) -> bytes:
    return transform(plaintext, key, nonce, pw, decrypt=False)


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, pw: bytes) -> bytes:
    return transform(ciphertext, key, nonce, pw, decrypt=True)
