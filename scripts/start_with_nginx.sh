#!/bin/sh
set -e

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
BACKEND_PORT="${LANGFLOW_PORT:-7860}"

runuser -u user -- langflow run --host "$BACKEND_HOST" --port "$BACKEND_PORT" &
BACKEND_PID=$!

graceful_shutdown() {
  kill -TERM "$BACKEND_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
}

trap graceful_shutdown INT TERM EXIT

nginx -g 'daemon off;'
