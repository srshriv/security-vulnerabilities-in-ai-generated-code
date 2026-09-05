#!/bin/bash
# AFL++ / ASAN / MSan Compilation Script
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[+] Compiling prog_000091 with AFL++ AddressSanitizer..."
if which afl-clang-fast > /dev/null 2>&1; then
    AFL_USE_ASAN=1 afl-clang-fast -g -O1 -o fuzz_asan harness.c
    echo "  -> Built fuzz_asan"
else
    gcc -fsanitize=address,undefined -g -O1 -o fuzz_asan harness.c
    echo "  -> Built fuzz_asan (gcc fallback)"
fi

echo "[+] Compiling prog_000091 with MemorySanitizer (MSan)..."
if which clang > /dev/null 2>&1; then
    clang -fsanitize=memory -g -O1 -o fuzz_msan harness.c || true
    echo "  -> Built fuzz_msan"
fi
