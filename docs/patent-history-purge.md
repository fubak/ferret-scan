# Runbook — Purge patent material from git history

**Status:** prepared, **not executed**. This is a one-time maintainer operation.

PR #28 removed the patent-prosecution material from the current tree, but the
files remain reachable in older commits (they predate that branch and exist on
`main`). This runbook describes how to remove them from the **entire history**.

> ⚠️ **Destructive.** Rewriting history changes every commit hash from the first
> affected commit onward. It breaks all existing clones, forks, and open pull
> requests, and requires a coordinated force-push. Treat it as a scheduled
> maintenance event, not a casual cleanup.

## Scope — paths to remove

```
docs/PATENT_ACTION_PLAN.md
docs/PATENT_LANDSCAPE_ANALYSIS.md
docs/ip-submissions/        (all 5 patent-* packages)
```

These are documents, not credentials, so **no secret rotation is required**.
They were never part of the published npm package (the `files` allowlist in
`package.json` excludes `docs/`), so **no npm action is required** either.

## Pre-flight checklist

1. **Pick a quiet window** and announce it to all collaborators.
2. **Merge or close every open PR first** (including #28). After the rewrite,
   any PR built on the old history will show a broken/garbage diff and must be
   recreated. Confirm `gh pr list` (or the PR tab) is empty of in-flight work.
3. **Note current state** for verification: `git rev-parse main` and a count of
   affected commits: `git log --oneline --all -- docs/PATENT_ACTION_PLAN.md docs/PATENT_LANDSCAPE_ANALYSIS.md docs/ip-submissions | wc -l`.
4. **Ensure admins can temporarily lift branch protection** on `main` (force-push
   to a protected branch is blocked otherwise) and re-enable it afterward.
5. **Inventory forks.** Forks retain their own copy of the data; the rewrite does
   not touch them. Decide whether any need to be contacted/deleted.

## Execute (recommended: git-filter-repo)

A guarded helper is provided that rewrites a fresh mirror clone, keeps a backup,
verifies the result, and **stops before pushing**:

```bash
scripts/purge-patent-history.sh
# Review the output, then run the printed `git push --force --mirror …` command.
```

Manual equivalent:

```bash
# 1. Fresh mirror clone + backup
git clone --mirror https://github.com/fubak/ferret-scan.git ferret-scan-purge.git
cp -a ferret-scan-purge.git ferret-scan-backup.git      # restore point

# 2. Rewrite ALL refs (branches + tags), dropping the paths
cd ferret-scan-purge.git
git filter-repo --force --invert-paths \
  --path docs/PATENT_ACTION_PLAN.md \
  --path docs/PATENT_LANDSCAPE_ANALYSIS.md \
  --path docs/ip-submissions

# 3. Verify nothing remains (expect empty output)
git log --all --oneline -- \
  docs/PATENT_ACTION_PLAN.md docs/PATENT_LANDSCAPE_ANALYSIS.md docs/ip-submissions

# 4. Force-push the rewritten history (IRREVERSIBLE)
git push --force --mirror https://github.com/fubak/ferret-scan.git
```

### Alternative: BFG Repo-Cleaner

```bash
git clone --mirror https://github.com/fubak/ferret-scan.git ferret-scan-purge.git
bfg --delete-folders ip-submissions --delete-files 'PATENT_*.md' ferret-scan-purge.git
cd ferret-scan-purge.git
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force --mirror https://github.com/fubak/ferret-scan.git
```

## Post-purge

1. **Re-enable branch protection** on `main`.
2. **Everyone re-clones.** Old local clones still contain the data and can
   re-introduce it; existing checkouts should be discarded, not rebased.
3. **Recreate any needed PRs** from fresh branches off the rewritten `main`.
4. **GitHub cached blobs / old commit URLs.** Even after force-push, the old
   commits can remain accessible by direct SHA URL until GitHub garbage-collects
   them. To force removal (and to scrub them from any cached PR diffs), open a
   request with **GitHub Support** referencing the rewritten repo.
5. **Releases/tags.** `--mirror` rewrites tags too; if any GitHub Release points
   at a rewritten tag, confirm its assets and target are still correct.
6. **Forks** still contain the material — handle per the pre-flight decision.

## Rollback

Before the force-push, the original state is preserved in `ferret-scan-backup.git`.
To restore: `git -C ferret-scan-backup.git push --force --mirror <repo-url>`.
After collaborators have re-cloned the rewritten history, rollback is no longer
clean — do not roll back past that point without another coordinated rewrite.
