# Nutzerdokumentation — `veil`

`veil` ist ein kleines Kommandozeilen-Werkzeug, das eine Datei mit einer eigenen
Strom-Chiffre ("veil stream transform") umwandelt. Beim Verschlüsseln wird eine
zufällige 8-Byte-Nonce vorangestellt, sodass jeder Lauf eine andere Ausgabedatei
erzeugt.

## Aufruf

```
veil [optionen] <eingabedatei> <ausgabedatei>
```

## Optionen

| Option        | Bedeutung                                              |
|---------------|--------------------------------------------------------|
| `-p <key>`    | Passphrase (optional; zum Entschlüsseln erforderlich)  |
| `-d`          | Transformation umkehren (entschlüsseln)                |
| `-h, --help`  | Hilfe anzeigen und beenden                             |

## Hilfetext (`./veil-x86_64 --help`)

```
Usage: veil [options] <infile> <outfile>

Apply the veil stream transform to <infile>, writing the result
to <outfile>. A random 8-byte nonce is prepended to the output,
so each run produces a distinct file.

Options:
  -p <key>    passphrase (optional; required to decrypt)
  -d          reverse the transform (decrypt)
  -h, --help  show this help and exit
```

## Beispiele

```bash
# Verschlüsseln (mit Passphrase, frische Nonce wird vorangestellt)
./veil-x86_64 -p geheim  klartext.txt  chiffre.enc

# Entschlüsseln (Nonce steckt in den ersten 8 Bytes der Datei)
./veil-x86_64 -d -p geheim  chiffre.enc  klartext.txt
```

## Ausgabeformat

- **Verschlüsseln:** `ausgabe = nonce(8 Byte) || chiffretext`
- **Entschlüsseln:** die Nonce wird aus den ersten 8 Bytes der Eingabe gelesen,
  Ausgabe ist nur der Klartext.

## Plattform

Lauffähig unter Ubuntu Linux (x86-64) als Kommandozeilenprogramm. Die ELF-Binary
`veil-x86_64` ist statisch gelinkt gegen die glibc und benötigt keine weiteren
Bibliotheken.

## Für das Reverse Engineering benötigte Tools (Kurzüberblick)

Für die Analyse werden ein Decompiler (Ghidra), die Standard-Triage-Tools
`file` / `strings` / Hexdump (`xxd`), Python 3 (für das Lösungsskript) sowie eine
Linux-Umgebung (getestet unter Kali Linux) benötigt. Die ausführliche Begründung
und das genaue Vorgehen stehen in `loesung.md`.
