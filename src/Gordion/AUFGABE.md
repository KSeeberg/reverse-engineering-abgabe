# Aufgabe: gordian

Gegeben ist das native Programm `gordian`, das bei einer korrekten 16-stelligen
Eingabe einen Flag ausgibt. Analysieren Sie das Programm per Reverse Engineering
und ermitteln Sie den Flag im Format `DHBW{…}`.

Aufruf: `./gordian <serial(16)>`







# oder so
# gordian — Den Knoten durchschlagen

Das Programm `gordian` kennt mehrere Eingaben, die es akzeptiert – doch nur
**eine** davon fördert den echten Flag zutage. Ein gültiger Flag hat immer die
Form `DHBW{…}`; Ausgaben ohne dieses Präfix stammen von Irrwegen.

Ihre Aufgabe: Schlagen Sie den richtigen Knoten durch. Analysieren Sie `gordian`
per Reverse Engineering und gewinnen Sie den Flag im Format `DHBW{…}`.

Aufruf: `./gordian <eingabe(16)>`
