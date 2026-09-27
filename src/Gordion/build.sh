#!/usr/bin/env bash
set -e
python3 gengordian.py
gcc -O2 -fno-stack-protector -o gordian gordian.c
strip --strip-all gordian
echo "[+] gebaut: ./gordian"; file gordian
