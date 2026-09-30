# KI-Einschätzung — wie gut hält `veil` eine KI vom Reversen ab?

Qualifizierte Einschätzung (Abgabe, 2P): Wie gut hält der eingebaute
Schutzmechanismus eine KI davon ab, die Anwendung zu reversen und das
zugrundeliegende Sicherheitsproblem zu identifizieren, und welche Tools
(Harness) die KI dafür benötigt.

## Kurzfazit

**Der Schutz hält eine KI nur schwach auf.** Die Obfuskation ist reine
Ablenkung an der Oberfläche (Decoy-Strings, unbenutzte Krypto-Routinen,
`ptrace`-Falle); die eigentliche Schwachstelle — eine passwortunabhängige,
öffentlich reproduzierbare Keystream-Auswahl mit nur 16 Schlüsselbytes — bleibt
strukturell sichtbar. Eine KI mit Disassembler-Zugriff findet den echten
Transform in wenigen Iterationen. Realistischer Aufwand mit KI-Unterstützung:
**deutlich unter den veranschlagten 90 Minuten.**

## Der Schutzmechanismus im Überblick

| Technik                         | Umfang im Binary                         | Wirkung auf KI |
|---------------------------------|------------------------------------------|----------------|
| Klartext-Decoy-Strings          | ~145 Fake-Strings (Fake-Flags, Fake-Keys, Fake-Config), 270 `strings`-Zeilen | gering |
| XOR-verschleierte echte Strings | `SPAD`-Pad, zur Laufzeit deobfuskiert    | gering |
| Unbenutzte Krypto-Routinen      | 12 `bogus_*`-Funktionen (AES-S-Box, CRC32, RC4, TEA, FNV, LFSR …) über Funktionszeiger-Tabelle | mittel |
| Anti-Debug                      | `ptrace(PTRACE_TRACEME)` → falscher Key-Index unter Debugger | gering (statisch irrelevant) |
| Opake Prädikate                 | `g_opaque`/`g_sink` (volatile, ==0 zur Laufzeit) | gering |
| Stripped Binary                 | keine Symbolnamen                        | gering |

## Warum das eine KI kaum aufhält

1. **Die Schwachstelle ist strukturell, nicht versteckt.** Der Keystream-Index
   hängt nur von Nonce + Chiffretext-Rückkopplung ab (beides öffentlich), nie
   vom Passwort. Diese Eigenschaft ist im Datenfluss sichtbar, sobald man die
   Keystream-Schleife gefunden hat — kein Ausprobieren nötig.

2. **Der echte Code ist klein und auffällig.** Die LCG-Konstanten
   `imul 0x71FED3C5` / `add 0x2A9F1B8D` und `shr 28` sind eindeutige Anker. Eine
   KI, die das Disassembly nach arithmetischen Konstanten und Schleifen scannt,
   trennt echten Transform und Decoys schnell — die `bogus_*`-Funktionen fließen
   erkennbar nur in eine `volatile`-Senke (`g_sink`) und haben keinen Einfluss
   auf die Ausgabedatei (toter Datenfluss).

3. **Decoy-Strings kosten fast nichts.** 145 Fake-Strings blähen die
   `strings`-Ausgabe auf, aber eine KI bewertet Strings nach Relevanz für den
   Datenfluss. Fake-Flags im Format `DHBW{...}` erzeugen kurz Rauschen, werden
   aber verworfen, sobald sie nirgends in die Ausgabe münden.

4. **Die `ptrace`-Falle ist statisch wirkungslos.** Sie verbiegt nur den
   Key-Index (3 → 0) unter einem Debugger. Der dokumentierte Angriff ist rein
   statisch/rechnerisch und läuft das Programm gar nicht an — die Falle greift
   nie.

5. **Keine kryptografische Härte.** Es gibt keinen echten KDF, keine
   Integritätsprüfung, keinen großen Schlüsselraum. 16 Schlüsselbytes lassen
   sich per Häufigkeitsanalyse direkt aus dem Klartext ablesen; bei ~1200 Bytes
   Nachricht landen ~75 Bytes pro "Fach" — statistisch mehr als genug.

## Welches Harness die KI braucht

Damit eine KI den Angriff selbstständig herleitet, genügt ein bescheidenes
Werkzeug-Setup:

- **Disassembler/Decompiler** (Ghidra, `objdump`, IDA) — um die Keystream-Schleife
  und die LCG-Konstanten zu finden. Ghidras Decompiler-Ausgabe als Text reicht der
  KI als Eingabe.
- **`strings` / `file`** — für die erste Triage (Format, Optionen, Decoys).
- **Python-Interpreter** — um den abgeleiteten Angriff (`solve.py`) zu
  implementieren und gegen `message.enc` sowie in einem Selbsttest zu verifizieren.
- **Optional ein Shell-/Datei-Tool**, damit die KI das Binary selbst aufrufen und
  Ergebnisse gegenprüfen kann (Encrypt/Decrypt-Roundtrip).

Ein Debugger (gdb) ist **nicht** nötig und wäre wegen der `ptrace`-Falle sogar
kontraproduktiv — was die statische Herangehensweise der KI zusätzlich begünstigt.

## Verbesserungsvorschläge (falls der Schutz härter sein soll)

- Passphrase **in den Seed und die Rückkopplung** einfließen lassen, nicht nur in
  die 16-Byte-Tabelle → macht den passwortfreien Angriff unmöglich.
- Echten KDF mit hohem Aufwand (Argon2/scrypt) und großen Schlüsselraum nutzen.
- Authentisierte Verschlüsselung (AEAD) statt reiner XOR-Stromchiffre.
- Decoys, die tatsächlich in plausible (aber falsche) Datenflüsse münden, statt
  nur in eine tote `volatile`-Senke — das erhöht den Analyseaufwand real.
