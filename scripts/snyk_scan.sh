#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts
if [[ -z "${SNYK_TOKEN:-}" ]]; then
  printf '%s\n' '{"scanCompleted":false,"reason":"SNYK_TOKEN is not configured"}' > artifacts/snyk-status.json
  echo '::error::SNYK_TOKEN is not configured. Snyk Open Source scan was not performed.' >&2
  exit 1
fi
npm install --global snyk@1.1308.4
snyk test --file=requirements.txt --package-manager=pip --command=python3 --json-file-output=artifacts/snyk.json
