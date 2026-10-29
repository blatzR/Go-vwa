#!/usr/bin/env bash
# Prints the PR's changed files MINUS anything matched by the central ignore list.
# Usage:   changed_files.sh <base_sha> <head_sha>
# Writes:  $RUNNER_TEMP/scannable-files.txt and $RUNNER_TEMP/ignored-files.txt
set -euo pipefail

BASE="$1"
HEAD="$2"
CENTRAL=".github/security-review/ignore-patterns.txt"
OUT_DIR="${RUNNER_TEMP:-/tmp}"

# Remove comments, surrounding spaces and blank lines from the pattern file.
clean() { sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d'; }

# "." = start from every file; each pattern is then added as an exclusion.
pathspecs=(".")

add_patterns() {
  while IFS= read -r p; do
    case "$p" in
      '*'|'**'|'**/*')
        echo "ERROR: ignore pattern '$p' would skip every file. Refusing to run." >&2
        exit 1 ;;
    esac
    pathspecs+=(":(exclude,glob)$p")
  done
}

if [ -f "$CENTRAL" ]; then
  add_patterns < <(clean < "$CENTRAL")
fi

git diff --name-only "$BASE" "$HEAD"                      | sort > "$OUT_DIR/all-changed-files.txt"
git diff --name-only "$BASE" "$HEAD" -- "${pathspecs[@]}" | sort > "$OUT_DIR/scannable-files.txt"
comm -23 "$OUT_DIR/all-changed-files.txt" "$OUT_DIR/scannable-files.txt" > "$OUT_DIR/ignored-files.txt"

cat "$OUT_DIR/scannable-files.txt"
