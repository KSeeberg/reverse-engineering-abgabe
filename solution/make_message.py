#!/usr/bin/env python3
"""(Re)generate message.enc with the real binary.

    python3 solution/make_message.py

Writes solution/plaintext.txt (= BODY, a silly poem with the flag, no fixed
header), encrypts it with bin/veil-x86_64 under a fresh random passphrase and
writes message.enc. Checks: `veil -d` with that passphrase round-trips and
solve() recovers the file without the passphrase (new nonce if it doesn't).
The passphrase is printed once.
"""
import os
import secrets
import string
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from solve import BINARY, HERE, REPO, solve

BODY = (
    b'Das Lied von der kleinen Tabelle\n'
    b'(ein dummes Gedicht ueber schwache Kryptografie)\n'
    b'\n'
    b'Es war einmal ein Passwort, ganz lang und ganz geheim,\n'
    b'es glaubte sich im Tresor und sang dazu im Reim.\n'
    b'Doch tief im Bauch der Maschine, da sitzt ein kleines Ding:\n'
    b"sechzehn winzige Faecher, mehr Platz gibt's nicht, ping-ping!\n"
    b'\n'
    b'Der Startwert ist kein Geheimnis, die Nonce liegt offen da,\n'
    b'die Rueckkopplung frisst Chiffretext, den hat ja jeder, ja!\n'
    b'So laeuft die ganze Zahlenfolge ohne Passwort ab,\n'
    b'und keiner muss was raten, nur ein bisschen Mathe-Knack.\n'
    b'\n'
    b'Wer zaehlt, wie oft ein Zeichen in seinem Fach erscheint,\n'
    b'der sieht: das Leerzeichen gewinnt, egal, wie sehr man weint.\n'
    b'Ein Fach nach dem anderen fliegt auf, ganz ohne Brute Force,\n'
    b'das Passwort bleibt ein Phantom, nur Schmuck und Mode, ein Gruss.\n'
    b'\n'
    b"Drum merke dir, mein lieber Freund, und schreib's dir hinters Ohr:\n"
    b'Ein Schloss mit sechzehn Schluesseln ist kein Schloss, es ist ein Tor.\n'
    b'Wer wirklich Geheimnisse hueten will, nimmt mehr als Fach und Kniff,\n'
    b"und liest er dies, dann hat er's raus - der Rest ist nur noch Griff.\n"
    b'\n'
    b'Und weil du so fleissig gesucht hast und nicht aufgegeben hast,\n'
    b'bekommst du jetzt als Lohn die Flagge, ohne Hast:\n'
    b'\n'
    b'DHBW{p4ssw0rd_k3y3d_str3am_2026}\n'
)


def main() -> int:
    plaintext = BODY
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
            if solve(blob) == plaintext:
                break
            print(f"attempt {attempt}: solver mismatch - new nonce", file=sys.stderr)
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
