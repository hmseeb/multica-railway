#!/usr/bin/env bash
# Modified for Railway: the published images must be the open-source build.
# server/ee and packages/ee carry a commercial license that grants no right to
# use or redistribute them, so neither may be linked into the Railway images.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
no() { echo "FAIL: $*" >&2; fail=1; }

# Every server binary in Dockerfile is built with -tags oss.
while IFS= read -r line; do
  case "$line" in *"-tags oss"*) ;; *) no "Dockerfile builds without -tags oss: $line" ;; esac
done < <(grep -E 'go build' Dockerfile)

# The oss server does not link server/ee.
if (cd server && go list -tags oss -deps ./cmd/server | grep -q 'multica/server/ee'); then
  no "server built with -tags oss still imports server/ee"
fi

# The web app neither imports nor depends on @multica/ee.
if grep -rn --include='*.ts' --include='*.tsx' --include='*.mjs' '@multica/ee' apps/web \
     --exclude-dir=node_modules --exclude-dir=.next >/dev/null; then
  no "apps/web imports @multica/ee"
fi
grep -q '"@multica/ee"' apps/web/package.json && no "apps/web/package.json depends on @multica/ee"

[ "$fail" = 0 ] && echo "ok: Railway images are the open-source build"
exit "$fail"
