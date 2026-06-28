#!/bin/bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
git add --all
if git diff-index --quiet HEAD --; then
    git add -f *.c *.h *.md *.sh 2>/dev/null
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.sh" -o -name "Makefile" \) -exec git add -f {} +
fi
COMMIT_MSG="Auto-update exploit codes: $(date '+%Y-%m-%d %H:%M:%S')"
git commit -m "$COMMIT_MSG"
git push -u origin "$BRANCH"
