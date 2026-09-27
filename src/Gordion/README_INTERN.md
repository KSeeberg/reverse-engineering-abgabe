# gordian — INTERN (NICHT an lösende Teams!)

MEHRERE Wege, nur EINER liefert DHBW{...}. Erkennungsmerkmal: DHBW-Praefix.

  Weg 1 (FALSCH) check_decoy (rol/xor/acc-Transform), 0v3rr1d3-r00t!!!
                 -> "svc-mode: ok ..."            (KEIN DHBW)
  Weg 2 (FALSCH) check_affine (rekursiv, (p*MA+MB)&0xFF==TT, per Byte invertierbar),
                 S3rv1c3-M0d3-K3y -> "TOKEN=..."  (KEIN DHBW)
  Weg 3 (FALSCH) backdoor env GORDIAN_KEY=GORDIAN-DEV-ACCESS-2026
                 -> "debug console ..."           (KEIN DHBW)
  ECHT           f0->..->f7 (tiefe Kette, verschluesselte Targets, f4 flattened,
                 Produkte+ANDs -> nur mit z3), Kn0t-Cutt3r#2026
                 -> DHBW{0nly_th1s_p4th_c4rr13s_th3_s1gn4tur3}

emit() gibt einfach den entschluesselten Text aus -> falsche Keys ergeben die
Nicht-DHBW-Strings. Anti-Debug (ptrace) vergiftet den echten Key.
Loesung: solution/solve_gordian.py (z3). An die Teams: NUR gordian + AUFGABE.md.
Vor Abgabe: Serial/Flag in gengordian.py aendern, ./build.sh.
