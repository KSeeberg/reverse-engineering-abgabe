# Reverse Engineering Challenge — "veil"

Reverse-Engineering-Abgabe im Rahmen des Moduls **Advanced Practical IT-Security**
der DHBW Mannheim.

## Szenario

`veil` ist ein kleines Kommandozeilen-Werkzeug, das eine Datei mit einer
selbstgebauten Stromchiffre "verschleiert". Ein Kollege hat damit eine
Nachricht verschlüsselt und nur die verschlüsselte Datei hinterlassen:

```
message.enc
```

Eure Aufgabe: **Rekonstruiert den Originaltext von `message.enc`.**
Darin versteckt ist eine Flag im Format `DHBW{...}`.

## Was ihr bekommt

| Datei               | Inhalt                                                        |
|---------------------|---------------------------------------------------------------|
| `bin/veil-x86_64`   | das kompilierte, gestrippte Programm (ELF, x86-64)            |
| `bin/veil-aarch64`  | dasselbe Programm für ARM64 (ELF, aarch64) — gleiche Chiffre  |
| `src/veil.c`        | der (bewusst unübersichtliche) C-Quellcode, eine Datei        |
| `build.sh`          | Build-Skript (`gcc -O2 -s`, x86-64 **und** aarch64)           |
| `message.enc`       | die zu knackende Datei: `nonce (8 Byte) || ciphertext`        |

Beide Binaries implementieren dieselbe Chiffre; `message.enc` passt zu beiden.

## Ziel

Aus `message.enc` den Klartext (inkl. Flag) wiederherstellen. Die Verschlüsselung
ist **passphrasen-geschützt** — ihr müsst zusätzlich das Passwort finden.

## Regeln & Hinweise

- **Arbeitet am Binary.** Der mitgelieferte Quellcode ist absichtlich
  irreführend benannt und mit Ablenkungen gespickt — verlasst euch nicht
  blind auf Funktionsnamen. Die Wahrheit steht im kompilierten Programm.
- Erlaubte Werkzeuge: **Ghidra** (empfohlen), radare2, objdump, gdb,
  eigene Skripte (Python o.ä.), KI-Assistenz.
- **Das Passwort besteht aus genau 5 Kleinbuchstaben (a–z).** Es fließt in den
  Schlüssel ein; ein bekannter Klartext-Anfang allein reicht **nicht**, um den
  Rest zu entschlüsseln. Rekonstruiert das Verfahren aus dem Binary und probiert
  das Passwort entlang dieser Policy durch (Known-Plaintext als Orakel).
- **Nur das Programm erneut auszuführen bringt euch nicht ans Ziel:** jeder
  Lauf zieht eine neue Zufalls-Nonce. Zum Entschlüsseln braucht ihr das Passwort.
- Alles, was ihr braucht (Algorithmus, Nonce-Handling, S-Box-/Seed-Ableitung),
  steckt im Binary bzw. im Header von `message.enc`.

## Ausführen

```bash
./bin/veil-x86_64 --help
./bin/veil-x86_64 -p <passwort> <infile> <outfile>        # verschlüsseln: nonce || ciphertext
./bin/veil-x86_64 -d -p <passwort> <infile> <outfile>     # entschlüsseln (-d)
```

Auf ARM64 analog `./bin/veil-aarch64`.

Selbst neu bauen (Linux, gcc; für ARM64 zusätzlich `gcc-aarch64-linux-gnu`):

```bash
bash build.sh
```

Viel Erfolg.
