#!/usr/bin/env bash
# Tags HEAD with the next release and publishes a GitHub Release for it.
# Usage: .github/release.sh [patch|minor|major]   (default patch; needs GH_TOKEN)
# The first release is v0.1.0. Nothing happens when HEAD already has a release tag.
set -euo pipefail

bump=${1:-patch}
case "$bump" in patch | minor | major) ;; *) echo "release.sh: bump must be patch, minor or major, not $bump" >&2; exit 1 ;; esac

git fetch --tags --force --quiet origin
if git tag --points-at HEAD | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "HEAD is already released as $(git tag --points-at HEAD | head -1)"
  exit 0
fi

latest=$(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
if [ -z "$latest" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<<"${latest#v}"
  case "$bump" in
    major) next="v$((major + 1)).0.0" ;;
    minor) next="v$major.$((minor + 1)).0" ;;
    patch) next="v$major.$minor.$((patch + 1))" ;;
  esac
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --verify-tag --generate-notes
echo "released $next (previous: ${latest:-none})"
