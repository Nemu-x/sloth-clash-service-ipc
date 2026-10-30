#!/usr/bin/env bash
# Builds a self-contained OpenConnect for macOS into the bundle directory $1:
#   $1/openconnect   statically linked against GMP, Nettle and GnuTLS built here
#   $1/vpnc-script   pinned upstream script
#
# Why from source: Homebrew bottles target the runner's own macOS release, so a
# bundle assembled from them requires that release (the 9.21 bundles needed
# macOS 14 on arm64 and macOS 15 on Intel, while the app runs on macOS 12+).
# Every dependency here is built with MACOSX_DEPLOYMENT_TARGET (default 12.0,
# the minimum of the Go toolchain the app is built with) and linked statically;
# the binary only links system libraries (libxml2, zlib, iconv, Security,
# CoreFoundation). Every download is pinned by SHA-256.
#
# The caller verifies the result: scripts/verify-openconnect-macos.sh.
set -euo pipefail

out=${1:?usage: build-openconnect-macos.sh <bundle-dir>}
: "${MACOSX_DEPLOYMENT_TARGET:=12.0}"
export MACOSX_DEPLOYMENT_TARGET

work=$(mktemp -d)
prefix=$work/prefix
sdk=$(xcrun --show-sdk-path)
jobs=$(sysctl -n hw.ncpu)

export CFLAGS="-O2 -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
export CXXFLAGS=$CFLAGS
export LDFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
# Only our own .pc files: a Homebrew one on the runner must never be picked up.
export PKG_CONFIG_PATH=$prefix/lib/pkgconfig
export PKG_CONFIG_LIBDIR=$prefix/lib/pkgconfig

fetch() { # url sha256 -> extracted under $work
  local url=$1 sha=$2 file
  file=$work/$(basename "$url")
  curl -fsSL --retry 3 -o "$file" "$url"
  echo "$sha  $file" | shasum -a 256 -c -
  tar -xf "$file" -C "$work"
}

fetch https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz \
  a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
fetch https://ftp.gnu.org/gnu/nettle/nettle-3.10.2.tar.gz \
  fe9ff51cb1f2abb5e65a6b8c10a92da0ab5ab6eaf26e7fc2b675c45f1fb519b5
fetch https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.10.tar.xz \
  db7fab7cce791e7727ebbef2334301c821d79a550ec55c9ef096b610b03eb6b7
fetch https://www.infradead.org/openconnect/download/openconnect-9.12.tar.gz \
  a2bedce3aa4dfe75e36e407e48e8e8bc91d46def5335ac9564fbf91bd4b2413e

echo "::group::gmp"
(cd "$work/gmp-6.3.0" &&
  ./configure --prefix="$prefix" --disable-shared --enable-static --with-pic &&
  make -j"$jobs" && make install)
echo "::endgroup::"

echo "::group::nettle"
(cd "$work/nettle-3.10.2" &&
  ./configure --prefix="$prefix" --libdir="$prefix/lib" --disable-shared --enable-static \
    --disable-documentation --disable-openssl \
    --with-include-path="$prefix/include" --with-lib-path="$prefix/lib" &&
  make -j"$jobs" && make install)
echo "::endgroup::"

echo "::group::gnutls"
(cd "$work/gnutls-3.8.10" &&
  ./configure --prefix="$prefix" --disable-shared --enable-static \
    --with-included-libtasn1 --with-included-unistring \
    --without-p11-kit --without-idn --without-tpm --without-tpm2 \
    --without-zlib --without-zstd --without-brotli --without-leancrypto \
    --disable-doc --disable-manpages --disable-tests --disable-tools \
    --disable-cxx --disable-nls --disable-guile --disable-libdane &&
  make -j"$jobs" && make install)
echo "::endgroup::"

echo "::group::openconnect"
# libxml2 and zlib come from the SDK (no .pc files there, so the flags are
# given directly); --static makes pkg-config add GnuTLS' private deps (Nettle,
# GMP, Security and CoreFoundation for the system trust store).
(cd "$work/openconnect-9.12" &&
  ./configure --prefix="$prefix" --disable-shared --enable-static --disable-nls \
    --with-gnutls --without-openssl \
    --without-stoken --without-libpskc --without-gssapi --without-libpcsclite \
    --without-libproxy --without-lz4 --disable-docs \
    PKG_CONFIG="pkg-config --static" \
    LIBXML2_CFLAGS="-I$sdk/usr/include/libxml2" LIBXML2_LIBS="-lxml2" \
    ZLIB_CFLAGS="" ZLIB_LIBS="-lz" &&
  make -j"$jobs" && make install)
echo "::endgroup::"

mkdir -p "$out"
for d in sbin bin; do
  if [ -x "$prefix/$d/openconnect" ]; then
    cp "$prefix/$d/openconnect" "$out/openconnect"
    break
  fi
done
[ -x "$out/openconnect" ] || { echo "FAIL: openconnect binary not installed"; exit 1; }
strip -x "$out/openconnect"

curl -fsSL --retry 3 -o "$out/vpnc-script" \
  "https://gitlab.com/openconnect/vpnc-scripts/-/raw/ce9e961bd0f6b867e1c7c35f78f6fb973f6ff101/vpnc-script"
echo "f0c4d936a382f07711263242699b5e2d85d1ace37136bb78785d352997c17742  $out/vpnc-script" | shasum -a 256 -c -
chmod +x "$out/openconnect" "$out/vpnc-script"
