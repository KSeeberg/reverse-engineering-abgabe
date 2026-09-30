#!/usr/bin/env bash
# Build der `veil`-Challenge fuer x86-64 und aarch64 aus einer einzigen Quelldatei.
# Beide Ziele sind Linux-ELF, optimiert (-O2) und gestrippt (-s). Diese Datei liegt
# in src/ neben veil.c; die Binaries werden ebenfalls nach src/ geschrieben,
# veil-x86_64 zusaetzlich nach ../aufgabenordner/.
#
# Laeuft auf:
#   - Kali/Debian/Ubuntu (x86_64 oder aarch64): gcc + Cross-Compiler fuer die
#     jeweils andere Architektur, z.B.
#       sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu
#     (auf einem ARM-Kali stattdessen gcc-x86-64-linux-gnu)
#   - macOS: veil.c ist Linux-Code (getrandom, PTRACE_TRACEME) und die Challenge
#     braucht ELF-Binaries, daher wird mit zig fuer Linux cross-kompiliert:
#       brew install zig
# Fehlt unter Linux der Cross-Compiler, wird ebenfalls zig genommen, falls vorhanden.
# Compiler lassen sich per CC_X86 / CC_ARM ueberschreiben.
set -euo pipefail
cd "$(dirname "$0")"

SRC="veil.c"
CFLAGS=(-O2 -w -s)

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
[ "$HOST_ARCH" = "arm64" ] && HOST_ARCH="aarch64"   # macOS nennt es arm64

# Setzt CC (Array) fuer Zielarchitektur $1 (x86_64|aarch64); 1 wenn keiner da ist.
pick_cc() {
    local arch="$1" override="$2"
    if [ -n "$override" ]; then
        CC=($override)
    elif [ "$HOST_OS" = "Linux" ] && [ "$HOST_ARCH" = "$arch" ]; then
        CC=(gcc)
    elif [ "$HOST_OS" = "Linux" ] && command -v "$arch-linux-gnu-gcc" >/dev/null 2>&1; then
        CC=("$arch-linux-gnu-gcc")
    elif command -v zig >/dev/null 2>&1; then
        CC=(zig cc -target "$arch-linux-gnu")
    else
        return 1
    fi
}

install_hint() {
    local arch="$1"
    if [ "$HOST_OS" = "Darwin" ]; then
        echo "  brew install zig" >&2
    else
        echo "  sudo apt-get update && sudo apt-get install -y gcc-${arch//_/-}-linux-gnu" >&2
    fi
}

build() {
    local arch="$1"
    echo ">> baue veil-$arch mit ${CC[*]}"
    "${CC[@]}" "${CFLAGS[@]}" -o "veil-$arch" "$SRC"
}

# ---- x86_64 (Pflicht, geht in den aufgabenordner) --------------------------
if ! pick_cc x86_64 "${CC_X86:-}"; then
    echo "FEHLER: kein Compiler fuer x86_64-Linux gefunden. Installieren mit:" >&2
    install_hint x86_64
    exit 1
fi
build x86_64

# Studi-Kopie im aufgabenordner/ synchron halten
if [ -d ../aufgabenordner ]; then
    echo ">> kopiere veil-x86_64 nach ../aufgabenordner/"
    cp veil-x86_64 ../aufgabenordner/veil-x86_64
fi

# ---- aarch64 (optional) ----------------------------------------------------
if pick_cc aarch64 "${CC_ARM:-}"; then
    build aarch64
else
    echo "" >&2
    echo "HINWEIS: kein Compiler fuer aarch64-Linux gefunden, veil-aarch64 wird" >&2
    echo "uebersprungen. Zum Bauen installieren mit:" >&2
    install_hint aarch64
fi

echo ""
echo ">> fertig"
file veil-x86_64 veil-aarch64 2>/dev/null || file veil-x86_64
