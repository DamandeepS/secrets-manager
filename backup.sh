#!/usr/bin/env bash
# Quick wrapper to run backup
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
python3 "$DIR/secrets_manager.py" backup "$@"
