#!/usr/bin/env bash
# Build the `veil` challenge for x86-64 and aarch64 from a single source file.
# Both targets are optimised (-O2) and stripped (-s).
set -euo pipefail
cd "$(dirname "$0")"

SRC="src/veil.c"
mkdir -p bin
rm -f bin/veil            # drop the old single-arch artefact if present

# ---- x86_64 (native) -------------------------------------------------------
CC_X86="${CC_X86:-gcc}"
echo ">> building bin/veil-x86_64 with $CC_X86"
"$CC_X86" -O2 -w -s -o bin/veil-x86_64 "$SRC"

# ---- aarch64 (cross) -------------------------------------------------------
# Needs the standard cross-compiler. On Debian/Ubuntu/Kali install it once with:
#   sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu
CC_ARM="${CC_ARM:-aarch64-linux-gnu-gcc}"
if ! command -v "$CC_ARM" >/dev/null 2>&1; then
    echo "" >&2
    echo "ERROR: aarch64 cross-compiler '$CC_ARM' not found." >&2
    echo "Install it and re-run build.sh:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu" >&2
    exit 1
fi
echo ">> building bin/veil-aarch64 with $CC_ARM"
"$CC_ARM" -O2 -w -s -o bin/veil-aarch64 "$SRC"

echo ""
echo ">> done"
file bin/veil-x86_64 bin/veil-aarch64
