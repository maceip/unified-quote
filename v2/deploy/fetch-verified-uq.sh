#!/usr/bin/env bash
# Build-host dependency acquisition. Never executed automatically by uq.
# Requires gh with artifact-attestation verification and sha256sum.
set -euo pipefail
if [[ $# != 5 ]]; then
  echo 'usage: fetch-verified-uq.sh <release-tag> <approved-source-sha> <approved-binary-sha256> <target> <new-destination>' >&2
  exit 2
fi
uq_tag=$1
uq_source=$2
uq_digest=$3
uq_target=$4
uq_destination=$5
[[ "$uq_tag" =~ ^v[0-9][0-9A-Za-z.-]*$ ]] || { echo 'invalid exact release tag' >&2; exit 2; }
[[ "$uq_source" =~ ^[0-9a-f]{40}$ ]] || { echo 'source commit must be 40 lower-case hex characters' >&2; exit 2; }
[[ "$uq_digest" =~ ^[0-9a-f]{64}$ ]] || { echo 'binary digest must be 64 lower-case hex characters' >&2; exit 2; }
[[ "$uq_source" != 0000000000000000000000000000000000000000 && "$uq_digest" != 0000000000000000000000000000000000000000000000000000000000000000 ]] || { echo 'approval pins must not be zero placeholders' >&2; exit 2; }
case "$uq_target" in
  x86_64-unknown-linux-gnu|aarch64-apple-darwin|x86_64-apple-darwin) uq_asset="uq-$uq_target" ;;
  x86_64-pc-windows-msvc) uq_asset="uq-$uq_target.exe" ;;
  *) echo 'unsupported release target' >&2; exit 2 ;;
esac
[[ "$uq_destination" = /* && ! -e "$uq_destination" && ! -L "$uq_destination" ]] || { echo 'destination must be a new absolute file path' >&2; exit 2; }
command -v gh >/dev/null
command -v sha256sum >/dev/null
uq_temp=$(mktemp -d)
trap 'rm -rf -- "$uq_temp"' EXIT
gh release download "$uq_tag" --repo ZUNFTMAX/zmax-universal-attestations --pattern "$uq_asset" --dir "$uq_temp"
uq_actual=$(sha256sum "$uq_temp/$uq_asset")
[[ "${uq_actual%% *}" == "$uq_digest" ]] || { echo 'binary does not match the independently approved SHA-256' >&2; exit 1; }
gh attestation verify "$uq_temp/$uq_asset" \
  --repo ZUNFTMAX/zmax-universal-attestations \
  --signer-workflow ZUNFTMAX/zmax-universal-attestations/.github/workflows/release.yml \
  --source-digest "$uq_source" \
  --predicate-type https://slsa.dev/provenance/v1 \
  --deny-self-hosted-runners
# noclobber prevents overwriting a destination created after the initial check.
(set -o noclobber; cat "$uq_temp/$uq_asset" > "$uq_destination")
chmod 0755 "$uq_destination"
echo "Verified release dependency written to $uq_destination"
