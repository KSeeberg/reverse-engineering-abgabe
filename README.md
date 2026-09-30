# Reverse-Engineering-Abgabe — "veil"

Reverse-Engineering-Challenge im Rahmen des Moduls **Advanced Practical
IT-Security** der DHBW Mannheim. Im Klartext von `message.enc` steckt eine Flag
im Format `DHBW{...}`.

## Ordnerstruktur

```
src/                        Quellen und gebaute Artefakte
  veil.c                    Quellcode des Programms
  veil-x86_64               kompilierte Binary (ELF, x86-64, stripped)
  veil-aarch64              ARM-Variante derselben Chiffre (Zusatz)
  message.enc              die verschlüsselte Nachricht
  build.sh                  Build-Script (baut beide Binaries nach src/, kopiert veil-x86_64 nach aufgabenordner/)

doc/                        Dokumentation und Lösung
  aufgabenstellung.md       Aufgabenstellung (wie sie der Studi bekommt)
  anleitung.md              Nutzerdokumentation (--help)
  loesung.md                ausführlicher Lösungsweg
  einfache_loesung.md       kompakter Lösungsweg
  decrypted_message.txt     der wiederhergestellte Klartext (mit Flag)
  ki_einschaetzung.md       Einschätzung: wie gut hält der Schutz eine KI auf
  solve.py                  Solver (Angriff ohne Passphrase) + Selbsttest
  reference_cipher.py       Referenz-Implementierung der Chiffre
  make_message.py           erzeugt message.enc + plaintext.txt neu
  plaintext.txt             Original-Klartext (Referenz)

aufgabenordner/             das, was der Studi zum Bearbeiten erhält
  veil-x86_64
  message.enc
  aufgabenstellung.md
```

## Schnellstart

```bash
# Bauen (aus src/)
cd src && ./build.sh

# Angriff / Verifikation (aus der Projektwurzel)
python3 doc/solve.py                 # entschlüsselt src/message.enc + Selbsttest
python3 doc/solve.py --no-selftest   # nur entschlüsseln
```

Flag: siehe `doc/decrypted_message.txt`.
