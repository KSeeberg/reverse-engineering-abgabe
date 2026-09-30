#!/usr/bin/env bash
# Build der `veil`-Challenge fuer x86-64 und aarch64 aus einer einzigen Quelldatei.
# Beide Ziele sind optimiert (-O2) und gestrippt (-s). Diese Datei liegt in src/
# neben veil.c; die Binaries werden ebenfalls nach src/ geschrieben.
set -euo pipefail
cd "$(dirname "$0")"

SRC="veil.c"

# ---- x86_64 (nativ) --------------------------------------------------------
CC_X86="${CC_X86:-gcc}"
echo ">> baue veil-x86_64 mit $CC_X86"
"$CC_X86" -O2 -w -s -o veil-x86_64 "$SRC"

# ---- aarch64 (cross) -------------------------------------------------------
# Braucht den Standard-Cross-Compiler. Auf Debian/Ubuntu/Kali einmalig:
#   sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu
CC_ARM="${CC_ARM:-aarch64-linux-gnu-gcc}"
if ! command -v "$CC_ARM" >/dev/null 2>&1; then
    echo "" >&2
    echo "HINWEIS: aarch64-Cross-Compiler '$CC_ARM' nicht gefunden." >&2
    echo "veil-aarch64 wird uebersprungen. Zum Bauen installieren mit:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu" >&2
else
    echo ">> baue veil-aarch64 mit $CC_ARM"
    "$CC_ARM" -O2 -w -s -o veil-aarch64 "$SRC"
fi

echo ""
echo ">> fertig"
file veil-x86_64 veil-aarch64 2>/dev/null || file veil-x86_64
