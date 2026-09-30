# Lösungsweg (privat) — veil challenge

> **Flag:** `DHBW{p4ssw0rd_k3y3d_str3am_2026}`

## Kern in einem Satz
Das Passwort steuert nur **16 Schlüsselbytes**. Welches Byte an welcher Stelle benutzt wird,
hängt allein von **Nonce + Chiffretext** ab (beides öffentlich) — nie vom Passwort. Also liest
man die 16 Bytes per Häufigkeitsanalyse direkt aus dem Text ab. Kein Passwort, kein Brute-Force.

## Einfach ausführen
```bash
python3 doc/solve.py                 # entschlüsselt src/message.enc + Selbsttest
python3 doc/solve.py --no-selftest
python3 doc/make_message.py          # src/message.enc + doc/plaintext.txt neu erzeugen
```

## Die Schritte
1. **Datei angucken** — `file src/veil-x86_64` → x86-64, stripped. `--help` zeigt `-p` und `-d`. Die ersten 8 Bytes von `src/message.enc` sind die Nonce.
2. **Echte Krypto in Ghidra finden** — such nach `imul 0x71FED3C5`, `add 0x2A9F1B8D`, `shr 28`. Das ist der Generator, der pro Byte ein „Fach" 0–15 aussucht. Merksatz: Fach hängt nur von Nonce + Chiffretext ab, nicht vom Passwort.
3. **Startwert holen** — eingebaute Konstante = `0xC8480C4A` (in `solve.py` als `key_fold`). Nicht unter gdb laufen lassen — `ptrace`-Falle verbiegt den Wert.
4. **Fach-Folge ausrechnen** — mit Nonce + Konstante den `state` durchlaufen lassen, Chiffretext als Rückkopplung füttern → für jede Position die Fach-Nummer 0–15.
5. **Nach Fächern sortieren** — alle Bytes mit demselben Fach wurden mit demselben Schlüsselbyte ge-XOR-t → 16 winzige „ein Byte raten".
6. **Jedes Fach knacken** — pro Fach alle 256 Werte testen, der richtige ergibt lesbaren deutschen Text. `solve.py` macht das per Häufigkeitsanalyse automatisch.
7. **Entschlüsseln** — `klartext = chiffre ^ S[fach]` über die ganze Datei → Gedicht mit Flag.

## Wie `veil` verschlüsselt (aus dem Binary)
Viel Ablenkung drin (AES-S-Box, Fake-Schlüssel, Dummy-Funktionen, `ptrace`). Der echte Teil:

1. **Passwort → Tabelle.** `tally_bytes` hasht das Passwort (FNV-1a), `init_table` mischt daraus 16 Bytes `S[0..15]`. Einzige Stelle, an der das Passwort wirkt.
2. **Startwert.** `derive_seed` = eingebauter Schlüssel + Nonce (erste 8 Bytes). Kein Passwort.
3. **Pro Byte** (`format_output`):
   ```
   state = A*state + C        (A=0x71FED3C5, C=0x2A9F1B8D)
   state ^= fb
   fach  = (state >> 28) & 0xF
   out   = in ^ S[fach]
   fb    = (fb << 8) | chiffretext_byte
   ```
   `fb` (Rückkopplung) bekommt nur Chiffretext-Bytes — die hat der Angreifer.

## Warum es klappt
- Tabelle hat nur 16 Einträge → aus dem Text ablesbar statt über das Passwort raten.
- Kein bekannter Klartext mehr (fester Header entfernt), aber normaler Text reicht: bei ~1200 Bytes landen ~75 Bytes pro Fach → sichere Häufigkeitsanalyse. Test: 60/60 fehlerfrei geknackt.
- Bei sehr kurzen Nachrichten wird das Raten unsicher → bekannter Anfang (z. B. Flag-Format `DHBW{`) hilft.

## Optional / Bonus
- **Anti-Debug:** `ptrace(PTRACE_TRACEME)` → unter Debugger falscher Schlüssel-Index (0 statt 3). Für die statische Lösung egal.
- **Strings entschlüsseln:** Pad `SPAD = 5B 1F A7 3C D2 66 89 E4`, `enc[i] ^ SPAD[i & 7]`.
- **Gelöschter Diagnose-Print:** früher zwei Hex-Bytes auf Stderr (z. B. `282b`) — nur Köder, entfernt.
- `src/veil-aarch64` ist die ARM-Variante (per `src/build.sh` mitgebaut) — für die Aufgabe (x86-64) nicht nötig.