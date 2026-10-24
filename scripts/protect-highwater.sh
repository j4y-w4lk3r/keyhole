#!/bin/bash
# Mark the remembered-version directory append-only.
# A normal user can still add a higher number. They cannot delete the
# directory, rename it, or truncate a file this script has already marked.
# Root clears the flag with: sudo chattr -a FILE
# Run this again after a new shelf creates a new file in the directory.

set -euo pipefail

if [[ -n "${KEYHOLE_STATE_DIR:-}" ]]; then
  root="$KEYHOLE_STATE_DIR"
elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
  root="$XDG_DATA_HOME/keyhole"
else
  root="${HOME:?}/.local/share/keyhole"
fi

dir="$root/highwater"
mkdir -p "$dir"
chmod 700 "$dir" 2>/dev/null || true
mode=$(stat -c %a "$dir")
if [[ "$mode" != "700" ]]; then
  echo "highwater is mode $mode, and chmod could not set 700" >&2
  exit 1
fi

sudo chattr +a "$dir"
shopt -s nullglob
for file in "$dir"/*; do
  if [[ -f "$file" ]]; then
    sudo chattr +a "$file"
  fi
done

echo "append-only: $dir"
lsattr -d "$dir"
lsattr "$dir" 2>/dev/null || true
