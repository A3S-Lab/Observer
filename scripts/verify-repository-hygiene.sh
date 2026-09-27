#!/usr/bin/env bash
set -euo pipefail

bad_paths="$(git ls-files | grep -E '(^|/)Snipaste_|(^|/)\.DS_Store$|(^|/)(id_rsa|id_ed25519|credentials|secrets?)$|\.(pem|p12|pfx|key)$' || true)"
if [[ -n "$bad_paths" ]]; then
  echo "repository hygiene verification failed: forbidden tracked path" >&2
  echo "$bad_paths" >&2
  exit 1
fi

if git grep -nI -E \
  'sk-[A-Za-z0-9_-]{24,}|Bearer[[:space:]]+[A-Za-z0-9._~-]{32,}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|/home/chensicheng/a3s/security/' \
  -- . ':(exclude)scripts/verify-repository-hygiene.sh'
then
  echo "repository hygiene verification failed: secret or local path pattern" >&2
  exit 1
fi

echo "repository hygiene verification passed"
