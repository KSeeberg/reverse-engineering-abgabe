#!/usr/bin/env bash
set -e
python3 genlaby.py                       # erzeugt data.h (real + alle Decoys)
gcc -O2 -fno-stack-protector -o aufgabe2 aufgabe2.c
strip --strip-all aufgabe2
echo "[+] gebaut: ./aufgabe2"; file aufgabe2
