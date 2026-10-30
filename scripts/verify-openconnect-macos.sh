#!/usr/bin/env bash
# Verifies a macOS OpenConnect bundle built by build-openconnect-macos.sh:
#   - every Mach-O targets macOS <= $MACOSX_DEPLOYMENT_TARGET (default 12.0)
#   - the binary has the expected architecture ($2: arm64 | x86_64)
#   - it links only system libraries (nothing from Homebrew, nothing bundled)
#   - it runs and reports GnuTLS
set -euo pipefail

bundle=${1:?usage: verify-openconnect-macos.sh <bundle-dir> <arch>}
arch=${2:?usage: verify-openconnect-macos.sh <bundle-dir> <arch>}
target=${MACOSX_DEPLOYMENT_TARGET:-12.0}
bin=$bundle/openconnect

ver_le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$1" ]; }

archs=$(lipo -archs "$bin")
[ "$archs" = "$arch" ] || { echo "FAIL: architecture '$archs', want '$arch'"; exit 1; }

fail=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q 'Mach-O' || continue
  minos=$(otool -l "$f" | awk '/LC_BUILD_VERSION/{b=1} b&&/minos/{print $2; exit} /LC_VERSION_MIN_MACOSX/{v=1} v&&/version/{print $2; exit}')
  echo "$f: minos $minos"
  if [ -z "$minos" ] || ! ver_le "$minos" "$target"; then
    echo "FAIL: $f requires macOS $minos, above $target"; fail=1
  fi
done < <(find "$bundle" -type f -print0)

echo "--- otool -L"
otool -L "$bin"
if otool -L "$bin" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)'; then
  echo "FAIL: links a non-system library"; fail=1
fi

echo "--- --version"
"$bin" --version 2>&1 | tee "$bundle.version.txt"
grep -q 'GnuTLS' "$bundle.version.txt" || { echo "FAIL: not built with GnuTLS"; fail=1; }
rm -f "$bundle.version.txt"

exit "$fail"
