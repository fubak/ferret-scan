#!/usr/bin/env bash
#
# Prepare a purge of patent-prosecution material from the ENTIRE git history.
#
# DESTRUCTIVE OPERATION (when finally pushed): this rewrites every commit hash
# from the first commit that touched these paths onward. It breaks all existing
# clones, forks, and open pull requests, and requires a coordinated force-push.
#
# This script does the rewrite on a FRESH MIRROR CLONE and a SEPARATE BACKUP,
# then STOPS before pushing. Review the result, then run the printed push
# command manually when you are ready. Nothing is force-pushed automatically.
#
# Prereq: git-filter-repo  (pipx install git-filter-repo  /  brew install git-filter-repo)
#
# Usage:
#   scripts/purge-patent-history.sh [repo-url]
#   (defaults to the GitHub remote of fubak/ferret-scan)
#
set -euo pipefail

REPO_URL="${1:-https://github.com/fubak/ferret-scan.git}"
WORKDIR="${WORKDIR:-./ferret-scan-purge.git}"
BACKUP="${WORKDIR%.git}-backup.git"

# Paths to remove from every commit. Keep in sync with the deletions already
# applied to HEAD (see CHANGELOG "Removed patent-prosecution material").
PATHS=(
  "docs/PATENT_ACTION_PLAN.md"
  "docs/PATENT_LANDSCAPE_ANALYSIS.md"
  "docs/ip-submissions"
)

if ! command -v git-filter-repo >/dev/null 2>&1; then
  echo "ERROR: git-filter-repo not found." >&2
  echo "       Install with: pipx install git-filter-repo  (or) brew install git-filter-repo" >&2
  exit 1
fi

if [ -e "$WORKDIR" ] || [ -e "$BACKUP" ]; then
  echo "ERROR: $WORKDIR or $BACKUP already exists; remove them first." >&2
  exit 1
fi

echo ">> [1/4] Mirror-cloning $REPO_URL -> $WORKDIR"
git clone --mirror "$REPO_URL" "$WORKDIR"

echo ">> [2/4] Keeping an untouched backup mirror at $BACKUP"
cp -a "$WORKDIR" "$BACKUP"

echo ">> [3/4] Rewriting history (removing patent paths) in $WORKDIR"
filter_args=()
for p in "${PATHS[@]}"; do filter_args+=(--path "$p"); done
git -C "$WORKDIR" filter-repo --force --invert-paths "${filter_args[@]}"

echo ">> [4/4] Verifying no patent paths remain in any ref"
remaining="$(git -C "$WORKDIR" log --all --oneline -- "${PATHS[@]}" || true)"
if [ -n "$remaining" ]; then
  echo "ERROR: patent paths still present after rewrite:" >&2
  echo "$remaining" >&2
  exit 1
fi
echo "   OK: no patent paths remain in history."

cat <<EOF

============================================================================
History rewritten locally. NOTHING has been pushed.

  Rewritten mirror : $WORKDIR
  Backup mirror    : $BACKUP   (force-push this back to restore if needed)

Before force-pushing, complete the coordination checklist in
docs/patent-history-purge.md (merge/close open PRs, warn collaborators, etc.).

When ready, this IRREVERSIBLY rewrites the remote and breaks all clones/PRs:

  git -C "$WORKDIR" push --force --mirror "$REPO_URL"

Then have everyone re-clone, and follow the post-purge steps in the runbook.
============================================================================
EOF
