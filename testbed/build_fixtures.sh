#!/bin/sh
# Deterministic detection oracle for Callandor. Builds one synthetic Mach-O per
# vulnerability variant and asserts Callandor flags it. Version-proof, unlike the
# (stale) real-world target survey. Run on the host; needs no VM.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.build/release/Callandor"
[ -x "$BIN" ] || BIN="$ROOT/.build/debug/Callandor"
[ -x "$BIN" ] || { echo "build Callandor first (swift build -c release)"; exit 1; }

WORK="$ROOT/testbed/.fixtures"
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"
FAILED=0

assert_finds() {
  dir="$1"; type="$2"; label="$3"
  if "$BIN" "$dir" --json 2>/dev/null | grep -q "\"$type\""; then
    echo "  [PASS] $label  ->  $type"
  else
    echo "  [FAIL] $label  ->  $type NOT detected"; FAILED=1
  fi
}

# 1. relativePath — dependency loaded by a bare relative name
mkdir -p rel/lib; (cd rel
  printf 'int dep(void){return 1;}\n' > d.c
  clang -dynamiclib -install_name @rpath/libd.dylib -o lib/libd.dylib d.c
  printf 'int dep(void);int main(void){return dep();}\n' > m.c
  clang m.c -o app -Llib -ld -Wl,-rpath,@loader_path/lib
  install_name_tool -change @rpath/libd.dylib libd.dylib app)
assert_finds rel relativePath "relative LC_LOAD_DYLIB"

# 2. weakDylibHijack — weak-linked dylib missing, writable parent dir
mkdir -p weak/lib; (cd weak
  printf 'int w(void){return 2;}\n' > w.c
  clang -dynamiclib -install_name @rpath/libw.dylib -o lib/libw.dylib w.c
  printf 'int w(void);int main(void){return w();}\n' > m.c
  clang m.c -o app -Xlinker -weak_library -Xlinker lib/libw.dylib -Wl,-rpath,@loader_path/lib
  rm lib/libw.dylib)
assert_finds weak weakDylibHijack "missing weak dylib, writable parent"

# 3. rpathHijack — @rpath dependency present in a writable dir
mkdir -p rp/lib; (cd rp
  printf 'int r(void){return 3;}\n' > r.c
  clang -dynamiclib -install_name @rpath/libr.dylib -o lib/libr.dylib r.c
  printf 'int r(void);int main(void){return r();}\n' > m.c
  clang m.c -o app -Llib -lr -Wl,-rpath,@loader_path/lib)
assert_finds rp rpathHijack "writable @rpath dependency"

# 4. dlopenRelative — dlopen() of a relative/@-path; binary imports _dlopen
mkdir -p dl/plugins; (cd dl
  cat > m.c <<'EOF'
#include <dlfcn.h>
int main(void){ void *h = dlopen("@loader_path/plugins/libevil.dylib", RTLD_LAZY); return h ? 0 : 1; }
EOF
  clang m.c -o app)
assert_finds dl dlopenRelative "dlopen @loader_path relative"

# 5. envVarInjection — unsigned/non-hardened executable honors DYLD_INSERT_LIBRARIES
assert_finds dl envVarInjection "non-hardened executable (DYLD_INSERT)"

echo
[ "$FAILED" = 0 ] && echo "ALL VARIANTS DETECTED" || echo "SOME VARIANTS MISSED"
exit $FAILED
