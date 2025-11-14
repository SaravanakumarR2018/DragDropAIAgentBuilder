#!/bin/sh
set -e

LANGFLOW_HOST="${LANGFLOW_HOST:-0.0.0.0}"
LANGFLOW_PORT="${LANGFLOW_PORT:-7861}"

cleanup() {
  if [ -n "${BACKEND_PID:-}" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [ -n "${NGINX_PID:-}" ]; then
    kill "$NGINX_PID" 2>/dev/null || true
  fi
}

trap cleanup INT TERM

langflow run --host "$LANGFLOW_HOST" --port "$LANGFLOW_PORT" &
BACKEND_PID=$!

nginx -g "daemon off;" &
NGINX_PID=$!

STATUS=0

set +e
while :; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    wait "$BACKEND_PID"
    STATUS=$?
    break
  fi
  if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    wait "$NGINX_PID"
    STATUS=$?
    break
  fi
  sleep 1
done

cleanup
wait 2>/dev/null || true
exit "$STATUS"
