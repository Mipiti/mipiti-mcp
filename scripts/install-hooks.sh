#!/usr/bin/env bash
# Use the repository's hooks (.githooks): pre-commit fixes and stages the
# documented counts, pre-push refuses a push whose counts are stale.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
chmod +x .githooks/pre-commit .githooks/pre-push
git config core.hooksPath .githooks
echo "hooks installed: core.hooksPath=.githooks"
