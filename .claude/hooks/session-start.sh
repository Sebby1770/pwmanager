#!/bin/bash
# Installs test dependencies so a fresh Claude Code on the web session can run
# `python -m pytest` and `node tests/js/run.mjs` immediately.
set -euo pipefail

# Local sessions manage their own environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# Some base images ship a distro-packaged cryptography that pip cannot
# uninstall; install a new enough wheel alongside it instead of failing.
if ! python3 -c 'import cryptography, sys; sys.exit(int(cryptography.__version__.split(".")[0]) < 42)' 2>/dev/null; then
  python3 -m pip install -q --ignore-installed "cryptography>=42"
fi

python3 -m pip install -q -r requirements-dev.txt
