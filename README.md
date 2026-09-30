Ihnen liegt die verschlüsselte Datei `message.enc` vor, die mit dem Programm `veil`
verschlüsselt wurde. Ziel ist die Entschlüsselung der Datei — analysieren Sie die
Anwendung, um einen Ansatzpunkt zum Wiederherstellen des Klartexts zu finden.

---

# Reverse Engineering Challenge — "veil"

Reverse-Engineering-Abgabe im Rahmen des Moduls **Advanced Practical IT-Security**
der DHBW Mannheim. Im Klartext steckt eine Flag im Format `DHBW{...}`.

## Was Sie bekommen

| Datei             | Inhalt                                                  |
|-------------------|---------------------------------------------------------|
| `bin/veil-x86_64` | das kompilierte, gestrippte Programm (ELF, x86-64)      |
| `message.enc`     | die verschlüsselte Datei                                |

## Kurz-Doku (`./bin/veil-x86_64 --help`)

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
