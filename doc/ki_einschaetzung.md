# KI-Einschätzung — wie gut hält `veil` eine KI vom Reversen ab?

## Kurzfazit

Der Schutz zielt nicht auf kryptografische Härte, sondern darauf, KI-gestütztes Reversing teuer und fehleranfällig zu machen. Das funktioniert an folgenden Stellen:

- **Fake-Secrets im `strings`-Dump:** `master_key=`, `AES_KEY_HEX=`, `backup_passphrase=`, RSA-Key, JWT, API-Keys: alles eine Fassade, um die KI zu verwirren
- **Falsche Krypto-Fährten:** AES-256-GCM, argon2, pbkdf2, mehrere „cipher suites": wird alles nicht benutzt.
- **Fake-Hinweise:** „key half in second binary", „argon2-derived", `do_not_grep_for_the_obvious_marker_here`
- **Fake-Optionen in `--help`:** `--kdf`, `--rounds`, `--hsm`, `--fips`, `--verify`: sind nicht existent.
- **Anti-Debug:** `ptrace(TRACEME)` + „safe key under debugger": gdb-Tool liefert nichts sinnvolles
- **Decoy-Struktur:** Fake-`entry`, tote Fake-Funktionen, sinnlose „noise"-Aufrufe verstecken die eine echte Loop
- **Fake-Container-Kram:** `VEILCONTAINERv3`, `MAGIC=`, `secret_marker_begin`: suggeriert Format, das es nicht gibt
- **Kein Ein-Klick-Angriff:** Lädt man das Binary mit direktem Auftrag („entschlüssle das / knack das Passwort") bei einer KI hoch, greifen deren Sicherheitsfilter und die Anfrage wird als Cracking geflaggt/abgelehnt. Nutzbar ist die KI nur, wenn man die Analyse als legitime, schrittweise RE-Übung rahmt und sie Stück für Stück durch Decompile-Ausgaben führt, wie bei den bisherigen Aufgaben. Einfaches Hochladen frisst nur Tokens und bringt keine sinnvolle Lösung.

## Tools/Harness, die eine KI benötigt

- KI benötigt den Kontext des Reverse Engineering, also wie die vorherigen Übungsaufgaben gelöst wurden
- KI kann besser reverse engineeren mit einem RE-Lotsen-Skill, der direkt weiß, wie man mit den Aufgaben umgeht
- Der Nutzer muss gezielte Prompts setzen können und wissen, mit welchen Informtionen die KI etwas anfangen kann
- Filter-Umgehung durch Framing: direkter Auftrag („knack das") wird geflaggt, deswegen muss der Nutzer es als schrittweise, legitime RE-Übung rahmen und die KI Stück für Stück durch die Aufgabe führen

## Tools, die der Nutzer braucht:

- Decompiler, in diesem Fall wurde *Ghidra* genutzt, sonst gibt es nur rohen Maschinencode
- Mensch muss file, strings, Decompile-Ausgaben und Hexdumps reinkopieren
- ggfs. Kali-Linux-Umgebung, wurde nur auf dieser getestet
- Python zum Schreiben und Laufenlassen des Lösungskripts