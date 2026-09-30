# Lösungsweg (privat) — veil challenge ("S-Box-Leak"-Variante)

Diese Datei liegt in `solution/` und ist per `.gitignore` vom Repo ausgeschlossen.
Flag: `DHBW{p4ssw0rd_k3y3d_str3am_2026}`.

**Schwachstelle in einem Satz:** Das Passwort keyt nur eine 16-Einträge-S-Box, während
Seed (Nonce + Binary-Konstante) und Rückkopplung (Ciphertext) öffentlich sind — also ist
die komplette S-Box-Index-Folge ohne Passwort berechenbar, und der feste, dokumentierte
256-Byte-Header verrät alle 16 S-Box-Werte.

Das beim Erzeugen von `message.enc` benutzte Passwort (`vhofmuepybss`, zufällig) wird für den
Angriff **nicht** gebraucht und steht nur der Vollständigkeit halber hier.

---

## Das Verfahren (aus dem Binary)
Viel Ablenkung wie gehabt: AES-S-Box + `decrypt_payload`, Fake-Key-Tabelle, `verify_password`
(strcmp gegen Decoy-String, steuert nur die Meldung „invalid license key“), Bogus-Funktionen über
eine Funktionszeiger-Tabelle, Opaque Predicates aus `volatile`/`getpid`, ptrace-Anti-Debug.
Der echte Weg (unauffällig benannt):
- `tally_bytes` — FNV-1a-64 über `-p` (Offset `1469598103934665603`, Prime `0x100000001b3`).
  Liefert ein 16-Byte-Profil; der 32-bit-Wert `pk32` landet nur noch im Noise-Sink.
- `init_table` — RC4-KSA über 16 Slots (`& 0xF`) → Permutation `P`,
  dann `S[i] = (P[i]<<4) | P[i^0xA]` (16 Einträge, volle Byte-Werte).
- `derive_seed` — Fold des eingebetteten Keys (`ENC_KEYS[3]^KPAD`) = Konstante **0xC8480C4A**,
  dann `s ^= le32(nonce[0:4]); s = A*s + le32(nonce[4:8])`. **Kein Passwort.**
- `format_output` — pro Byte: `state = A*state + C; state ^= fb; ks = S[(state>>28)&0xF];
  out = in^ks; fb = (fb<<8)|ciphertext_byte`. **A=0x71FED3C5**, **C=0x2A9F1B8D**.

## Angriff Schritt für Schritt (ohne Passwort)
1. **Triage:** `file` → x86-64, stripped; `--help` zeigt `-p`/`-d`; Header von `message.enc`
   = 8-Byte-Nonce; README dokumentiert den festen 256-Byte-Klartext-Header.
2. **Ghidra:** Keystream-Schleife finden (LCG-Konstanten `imul 0x71FED3C5`, `add 0x2A9F1B8D`,
   `shr 28`), von dort rückwärts `derive_seed`, `init_table`, `tally_bytes`. Erkennen:
   `state` hängt nur an Nonce + Key-Fold, das Passwort wirkt nur über `S`.
3. **Konstante holen:** Key-Fold `0xC8480C4A` (bzw. `ENC_KEYS[3]^KPAD` falten) — statisch oder
   per gdb (Achtung ptrace: unter Debugger wird Key-Index 0 genommen).
4. **Index-Folge berechnen:** `state` aus Nonce + Konstante seeden und über den ganzen Ciphertext
   laufen lassen; `fb` wird nur mit Ciphertext-Bytes gefüttert → `idx_i = (state_i>>28)&0xF`
   für jede Position, ohne Passwort.
5. **S-Box aus dem Header lesen:** für `i < 256`: `S[idx_i] = header_i ^ ct_i`
   (gleiche Indizes müssen gleiche Werte liefern = Konsistenzcheck).
   Bei `message.enc` kommen alle 16 Indizes im Header vor.
6. **Entschlüsseln:** `pt_i = ct_i ^ S[idx_i]` für die ganze Datei → Flag.

```bash
python3 solution/solve.py              # entschlüsselt message.enc + Selbsttest (20 Runden)
python3 solution/solve.py --no-selftest
python3 solution/make_message.py       # message.enc + plaintext.txt neu erzeugen
```

## Warum kein Brute-Force nötig ist
Der einzige passwortabhängige Teil ist die Tabelle `S` — und die hat nur 16 Einträge, die man
direkt aus Known-Plaintext abliest, statt sie über das Passwort zu erraten. Alles andere
(Seed, Rückkopplung, Index-Folge) ist aus Datei + Binary öffentlich. Das Passwort (hier 12
zufällige Buchstaben, beliebig lang/stark) spielt deshalb keine Rolle.
Wahrscheinlichkeit, dass 256 Byte Header nicht alle 16 Indizes treffen: ≈ 16·(15/16)^256 ≈ 10⁻⁶;
bei nur 64 Byte wären es ~23 %. Der Solver bricht in dem Fall mit
„header covers only k/16 table indices … lengthen the header“ ab.

---

## Optional / Bonus
- **Anti-Debug:** `ptrace(PTRACE_TRACEME)` → bei Debugger falscher Key-Index (0 statt 3).
  Für die statische Lösung irrelevant.
- **String-Deobfuskation:** Pad `SPAD = 5B 1F A7 3C D2 66 89 E4`, `enc[i]^SPAD[i&7]`.
- `bin/veil-aarch64` ist noch **nicht** neu gebaut (alte Chiffre) — braucht `gcc-aarch64-linux-gnu`.
