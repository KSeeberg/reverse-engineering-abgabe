# Lösungsweg (privat) — veil challenge

Diese Datei ist die ausführliche Lösungsdokumentation (Abgabe, 5P).
Flag: `DHBW{p4ssw0rd_k3y3d_str3am_2026}`

## Die Idee in drei Sätzen
Das Passwort steuert nur eine winzige Tabelle mit **16 Fächern**. Alles andere, nämlich
Startwert, Nonce und Rückkopplung, ist öffentlich. Deshalb kann man für jedes Byte der Datei
ausrechnen, **welches Fach** benutzt wurde, und ohne das Passwort zu kennen, die 16 Fächer per
Häufigkeitsanalyse erraten.

Das Passwort (`veil`-Aufruf mit `-p`) wird für den Angriff nicht gebraucht.
Es wurde nur beim ursprünglichen Verschlüsseln von `message.enc` verwendet.

## Wie `veil` verschlüsselt (aus dem Binary gelesen)
Im Binary steckt viel Ablenkung (AES-S-Box, Fake-Schlüssel, Dummy-Funktionen, `ptrace`).
Der echte Teil ist klein:

1. **Passwort → Tabelle.** `tally_bytes` macht aus dem Passwort einen Hash (FNV-1a), `init_table`
   mischt daraus 16 Bytes `S[0..15]`. Das ist die einzige Stelle, an der das Passwort wirkt.
2. **Startwert.** `derive_seed` nimmt einen im Binary eingebauten Schlüssel plus die Nonce
   (die ersten 8 Bytes der Datei). **Kein Passwort.**
3. **Pro Byte** (`format_output`):
   ```
   state = A*state + C        (A=0x71FED3C5, C=0x2A9F1B8D)
   state ^= fb
   fach  = (state >> 28) & 0xF
   out   = in ^ S[fach]
   fb    = (fb << 8) | chiffretext_byte
   ```
   `fb` (Rückkopplung) bekommt nur Chiffretext-Bytes, und den hat der Angreifer.

## Der Angriff Schritt für Schritt
1. **Triage.** `file src/veil-x86_64` → x86-64, stripped. `--help` zeigt `-p` und `-d`.
   Die ersten 8 Bytes von `message.enc` sind die Nonce.
2. **Schleife im Decompiler finden** (Ghidra): Suche nach `imul 0x71FED3C5`, `add 0x2A9F1B8D`
   und `shr 28`. Von dort rückwärts zu `derive_seed` und `init_table`.
   Erkenntnis: Die Fach-Nummer hängt nicht vom Passwort ab.
3. **Konstante holen.** Der eingebaute Schlüssel gefaltet ergibt `0xC8480C4A`
   (`ENC_KEYS[3] ^ KPAD`, siehe `key_fold()` in `solve.py`).
   Achtung: Unter einem Debugger nimmt das Programm wegen `ptrace` einen anderen Schlüssel.
4. **Fach-Folge berechnen.** Mit Nonce und Konstante den `state` laufen lassen, `fb` mit den
   Chiffretext-Bytes füttern. Ergebnis: für jede Position die Fach-Nummer 0–15.
5. **Nach Fächern sortieren.** Alle Bytes, die dasselbe Fach benutzt haben, wurden mit **demselben**
   Schlüsselbyte XOR-verknüpft. Das sind 16 kleine Probleme à „ein Schlüsselbyte raten".
6. **Schlüsselbyte raten.** Pro Fach alle 256 Werte probieren. Der richtige liefert Text, der
   nach Deutsch aussieht (Leerzeichen, `e`, `n`, `i` … sind häufig, Steuerzeichen kommen nicht vor).
   `solve.py` vergibt dafür Punkte und nimmt den besten Wert.
7. **Entschlüsseln.** `klartext = chiffretext ^ S[fach]` für die ganze Datei → Gedicht mit Flag.

```bash
python3 doc/solve.py              # entschlüsselt src/message.enc + Selbsttest (20 Runden)
python3 doc/solve.py --no-selftest
```

## Warum das klappt (und kein Brute-Force nötig ist)
- Die Tabelle hat nur 16 Einträge. Man muss sie nicht über das Passwort erraten, sondern liest sie
  direkt aus dem Text ab.
- Es gibt **keinen bekannten Klartext** mehr (der feste Header wurde entfernt), aber die Nachricht
  ist normaler Text. Das reicht: bei ca. 1200 Bytes landen rund 75 Bytes in jedem Fach, genug für
  eine sichere Häufigkeitsanalyse. Im Test wurden 60 von 60 frischen Verschlüsselungen fehlerfrei geknackt.
- Bei sehr kurzen Nachrichten (wenige Bytes pro Fach) wird das Raten unsicher. Dann hilft ein
  bekannter Nachrichtenanfang, zum Beispiel das Flag-Format `DHBW{`.

---

## Optional / Bonus
- **Anti-Debug:** `ptrace(PTRACE_TRACEME)` → unter Debugger falscher Schlüssel-Index (0 statt 3).
  Für die statische Lösung irrelevant.
- **Strings entschlüsseln:** Pad `SPAD = 5B 1F A7 3C D2 66 89 E4`, `enc[i] ^ SPAD[i & 7]`.
- **Gelöschter Diagnose-Print:** Früher gab `veil` auf Stderr zwei Hex-Bytes aus (z. B. `282b`).
  Das war nur ein Köder und ist entfernt.
- `src/veil-aarch64` ist die ARM-Variante derselben Chiffre (per `src/build.sh` mitgebaut).
  Für die Aufgabe (x86-64) nicht nötig, liegt aber als Zusatz bei.