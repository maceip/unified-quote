#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 OUTPUT_EXECUTABLE" >&2
    exit 2
fi
adapter_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
adapter_output=$1
if [[ $adapter_output != /* ]]; then
    adapter_output="$PWD/$adapter_output"
fi
cd "$adapter_dir"
export GOTOOLCHAIN=local
if [[ $(go env GOOS) != "$(go env GOHOSTOS)" || $(go env GOARCH) != "$(go env GOHOSTARCH)" ]]; then
    echo "Build the full Google adapter natively for its target; libxml2 requires a matching C toolchain." >&2
    exit 1
fi
case $(go env GOOS) in
    linux|darwin) ;;
    *) echo "The full Google adapter build currently supports Linux and macOS." >&2; exit 1 ;;
esac
adapter_native=${UQ_LIBXML2_PREFIX:-"$adapter_dir/../../target/google-native/$(go env GOOS)-$(go env GOARCH)/libxml2-2.15.4"}
mkdir -p "$(dirname -- "$adapter_native")"
adapter_native=$(cd "$(dirname -- "$adapter_native")" && pwd)/$(basename -- "$adapter_native")
bash "$adapter_dir/build-libxml2.sh" "$adapter_native"
export PKG_CONFIG_LIBDIR="$adapter_native/lib/pkgconfig"
export PKG_CONFIG_PATH="$adapter_native/lib/pkgconfig"
export CGO_ENABLED=1
[[ $(pkg-config --modversion libxml-2.0) == 2.15.4 ]]
go mod verify

# Enforce the currently authorized production dependency owners. Go's test-only
# modules are not linked into the executable. Expand this list only after the
# user explicitly approves a new non-Google library.
adapter_modules=$(go list -mod=readonly -deps -f '{{with .Module}}{{if .Replace}}{{.Replace.Path}}{{else}}{{.Path}}{{end}}{{end}}' ./cmd/uq-google-attestation | sort -u)
while IFS= read -r adapter_module; do
    case "$adapter_module" in
        ""|github.com/ZUNFTMAX/zmax-universal-attestations/v2/google-attestation|github.com/google/*|google.golang.org/*|golang.org/x/*) ;;
        github.com/beevik/etree|github.com/atulpatildbz/goxmldsig|github.com/atulpatildbz/libxml2|github.com/pkg/errors|github.com/jonboulle/clockwork|go.uber.org/multierr) ;;
        *) echo "Unapproved production dependency: $adapter_module" >&2; exit 1 ;;
    esac
done <<< "$adapter_modules"
go build -mod=readonly -trimpath -buildvcs=true -o "$adapter_output" ./cmd/uq-google-attestation
python3 "$adapter_dir/notices.py" "$adapter_output.NOTICES.txt"
cat "$adapter_native/uq-build-recipe.txt" "$adapter_native/share/uq/libxml2-Copyright" >> "$adapter_output.NOTICES.txt"
