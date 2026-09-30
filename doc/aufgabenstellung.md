# Reverse-Engineering-Aufgabe — "veil"

Reverse-Engineering-Challenge im Rahmen des Moduls **Advanced Practical
IT-Security** der DHBW Mannheim.

## Ausgangslage

Ihnen liegt die verschlüsselte Datei `message.enc` vor, die mit dem Programm
`veil` verschlüsselt wurde. Sie kennen die zugehörige Passphrase **nicht**.

## Ziel

Stellen Sie den Klartext von `message.enc` wieder her. Im Klartext steckt eine
Flag im Format `DHBW{...}`. Analysieren Sie dazu die Anwendung und finden Sie
einen Ansatzpunkt, um den Klartext ohne Kenntnis der Passphrase zu rekonstruieren.

## Was Sie bekommen

| Datei          | Inhalt                                             |
|----------------|----------------------------------------------------|
| `veil-x86_64`  | das kompilierte, gestrippte Programm (ELF, x86-64) |
| `message.enc`  | die verschlüsselte Datei                           |

## Kurz-Doku (`./veil-x86_64 --help`)

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

## Hinweise

- Das Programm ist gestrippt und enthält bewusst Ablenkungen (Decoy-Strings,
  Fake-Schlüssel, unbenutzte Krypto-Routinen). Lassen Sie sich davon nicht in
  die Irre führen.
- Der Aufwand für ein erfolgreiches Reverse Engineering sollte — inkl.
  KI-Unterstützung — ca. 90 Minuten betragen.

## Abgabe

Reichen Sie die wiederhergestellte Flag `DHBW{...}` sowie eine kurze Beschreibung
Ihres Lösungswegs ein (welche Tools, welche Schritte).
