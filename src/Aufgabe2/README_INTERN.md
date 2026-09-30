# aufgabe2 – INTERNE Hinweise (NICHT an lösende Teams!)

VIER Lösungswege - nur EINER liefert DHBW{...}. Die 3 Fallen geben Text OHNE
DHBW-Praefix aus (erkennbar!).

  Weg 1 (FALSCH) check_decoy: invertierbarer rol/xor/acc-Transform gegen TGA.
        Serial 0v3rr1d3-r00t!!! -> root-override: kein Flag ... (KEIN DHBW)
  Weg 2 (FALSCH) check_affine (eigene rekursive Kette aff_step): affiner Per-Byte-
        Check (p*MA+MB)&0xFF==TT -> mit Python (Modulo-Inverse) loesbar. FALLE fuer
        "schnelle Inverter". Serial S3rv1c3-M0d3-K3y -> TOKEN=service-mode ... (KEIN DHBW)
  Weg 3 (FALSCH) backdoor: getenv("LABY_KEY")=="DHBW-DEV-ACCESS-2024"
        -> debug backdoor offen ... (KEIN DHBW)
  ECHT           f0->f1->...->f7 (tiefe Kette, verschluesselte Targets, f4 flattened,
        Produkte+ANDs -> NICHT invertierbar, nur mit z3). Kettenzustand koppelt alles.
        Serial L4byr1nth-D3p#42 -> DHBW{n3st3d_c4lls_z3_4nd_much_p4t13nc3}

Reihenfolge in main: Backdoor -> Weg1 -> Weg2 -> ECHT. Das echte Serial faellt durch
alle Decoys (verifiziert). Anti-Debug (ptrace) vergiftet den echten Flag-Key.
Rausch-Flags: OBF_N0..2, OBF_M0..3. Tote Krypto: fake_md5/fake_rc4.

Loesung: solution/solve_aufgabe2.py (z3, nur echter Pfad).
An die Teams: NUR aufgabe2 + AUFGABE.md. Vor Abgabe: Serials/Flags in genlaby.py
aendern, ./build2.sh.
