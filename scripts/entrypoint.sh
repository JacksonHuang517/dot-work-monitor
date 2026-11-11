#!/usr/bin/env bash
set -euo pipefail
umask 077
python /app/scripts/container_init.py
cd /app
gosu monitor python -m dot_feishu.server &
core_pid=$!
(cd /app/auth && exec gosu monitor node dist/main.js) &
auth_pid=$!
stop() {
  kill -TERM "$core_pid" "$auth_pid" 2>/dev/null || true
  wait "$core_pid" "$auth_pid" 2>/dev/null || true
}
trap stop TERM INT EXIT
set +e
wait -n "$core_pid" "$auth_pid"
exit_code=$?
set -e
# Either child exiting restarts the whole unit rather than leaving a half-service.
if [ "$exit_code" -eq 0 ]; then exit_code=1; fi
exit "$exit_code"
