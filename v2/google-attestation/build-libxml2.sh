#!/usr/bin/env bash
# Build only the approved XML runtime, with no optional third-party libraries.
set -euo pipefail
if [[ $# -ne 1 || $1 != /* ]]; then
    echo "usage: $0 ABSOLUTE_INSTALL_PREFIX" >&2
    exit 2
fi
xml_prefix=$1
xml_version=2.15.4
xml_sha=98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821
xml_recipe="libxml2-$xml_version:$xml_sha:static-pic-no-iconv-icu-zlib-modules-python:v1"
if [[ -f "$xml_prefix/uq-build-recipe.txt" ]] &&
   [[ $(cat "$xml_prefix/uq-build-recipe.txt") == "$xml_recipe" ]] &&
   [[ -f "$xml_prefix/lib/libxml2.a" && -f "$xml_prefix/share/uq/libxml2-Copyright" ]]; then
    exit 0
fi
if [[ -e "$xml_prefix" ]]; then
    echo "Existing libxml2 prefix has no matching completed build: $xml_prefix" >&2
    exit 1
fi
xml_tmp=$(mktemp -d "${TMPDIR:-/tmp}/uq-libxml2.XXXXXXXX")
trap 'rm -rf -- "$xml_tmp"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --max-time 180 \
    "https://download.gnome.org/sources/libxml2/2.15/libxml2-$xml_version.tar.xz" \
    --output "$xml_tmp/source.tar.xz"
python3 - "$xml_tmp/source.tar.xz" "$xml_sha" <<'PY'
import hashlib
from pathlib import Path
import sys
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit("libxml2 source digest mismatch")
PY
tar -xJf "$xml_tmp/source.tar.xz" -C "$xml_tmp"
cd "$xml_tmp/libxml2-$xml_version"
./configure --prefix="$xml_prefix" --disable-shared --enable-static --with-pic \
    --without-python --without-iconv --without-icu --without-zlib \
    --without-modules --without-readline --without-history
make -j "${UQ_BUILD_JOBS:-4}"
make install
mkdir -p "$xml_prefix/share/uq"
cp Copyright "$xml_prefix/share/uq/libxml2-Copyright"
printf '%s\n' "$xml_recipe" > "$xml_prefix/uq-build-recipe.txt"
