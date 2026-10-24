#!/bin/bash
# Trust the binary named in a pin file, then rebuild keyhole.
#   bash scripts/update-age-pin.sh          # age.pin
#   bash scripts/update-age-pin.sh gpg.pin  # gpg.pin
# Run this yourself after an upgrade. It is not a package hook:
# a hook would bless whatever file appeared at that path.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
name="${1:-age.pin}"
if [[ "$name" == */* ]]; then
  echo "pass a pin file name in the repo root, such as age.pin or gpg.pin" >&2
  exit 1
fi
pin="$root/$name"

if [[ ! -f "$pin" ]]; then
  echo "missing $pin" >&2
  exit 1
fi

mapfile -t lines < <(grep -v -e '^[[:space:]]*$' -e '^[[:space:]]*#' "$pin")
path="${lines[0]:-}"
old="${lines[1]:-}"

if [[ "$path" != /* ]]; then
  echo "$name path must be absolute" >&2
  exit 1
fi
if [[ ! "$old" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "$name sha256 must be 64 hex characters" >&2
  exit 1
fi
if [[ ! -f "$path" ]]; then
  echo "missing $path" >&2
  exit 1
fi

new=$(sha256sum -- "$path" | awk '{print $1}')
if [[ "$new" == "$old" ]]; then
  echo "$path already matches $name"
  exit 0
fi

echo "$name    $old"
echo "installed  $new"
echo "path       $path"

if [[ ! -t 0 ]]; then
  echo "refusing to update the pin without a terminal confirmation" >&2
  exit 1
fi

read -r -p "Type yes to trust this binary and rebuild: " answer
if [[ "$answer" != "yes" ]]; then
  echo "pin unchanged" >&2
  exit 1
fi

tmp=$(mktemp)
{
  grep -e '^[[:space:]]*#' "$pin" || true
  printf '%s\n%s\n' "$path" "$new"
} >"$tmp"
mv "$tmp" "$pin"

cd "$root"
cargo build --release
./target/release/keyhole version
