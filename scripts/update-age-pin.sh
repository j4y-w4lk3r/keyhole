#!/bin/bash
# Trust the age binary named in age.pin, then rebuild keyhole.
# Run this yourself after an age upgrade. It is not a package hook:
# a hook would bless whatever file appeared at that path.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
pin="$root/age.pin"

if [[ ! -f "$pin" ]]; then
  echo "missing $pin" >&2
  exit 1
fi

mapfile -t lines < <(grep -v -e '^[[:space:]]*$' -e '^[[:space:]]*#' "$pin")
path="${lines[0]:-}"
old="${lines[1]:-}"

if [[ "$path" != /* ]]; then
  echo "age.pin path must be absolute" >&2
  exit 1
fi
if [[ ! "$old" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "age.pin sha256 must be 64 hex characters" >&2
  exit 1
fi
if [[ ! -f "$path" ]]; then
  echo "missing $path" >&2
  exit 1
fi

new=$(sha256sum -- "$path" | awk '{print $1}')
if [[ "$new" == "$old" ]]; then
  echo "$path already matches age.pin"
  exit 0
fi

echo "age.pin    $old"
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
