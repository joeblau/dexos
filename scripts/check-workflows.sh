#!/usr/bin/env bash
set -euo pipefail

failed=0
while IFS= read -r match; do
  ref=${match#*@}
  ref=${ref%%[[:space:]#]*}
  if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    echo "mutable GitHub Action reference: $match" >&2
    failed=1
  fi
done < <(grep -RhoE 'uses:[[:space:]]+[^[:space:]#]+@[^[:space:]#]+' .github/workflows || true)

grep -qE '^permissions:[[:space:]]*$' .github/workflows/ci.yml || {
  echo "workflow must declare top-level permissions" >&2; failed=1;
}
grep -qE '^[[:space:]]+contents:[[:space:]]+read' .github/workflows/ci.yml || {
  echo "workflow may only grant contents: read" >&2; failed=1;
}

# contents: write is forbidden outside the tag-driven release workflow (which
# must upload signed assets). ci.yml and other PR gates stay read-only.
while IFS= read -r hit; do
  file=${hit%%:*}
  if [[ "$file" == ".github/workflows/release.yml" ]]; then
    continue
  fi
  echo "write permissions are forbidden outside release.yml: $hit" >&2
  failed=1
done < <(grep -REn '(^|[[:space:]])(write-all|contents:[[:space:]]+write|pull-requests:[[:space:]]+write)' .github/workflows || true)

exit "$failed"
