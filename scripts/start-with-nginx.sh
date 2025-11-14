#!/bin/bash
set -euo pipefail

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
BACKEND_PORT="${LANGFLOW_PORT:-7861}"

echo "[startup] Starting Langflow backend on ${BACKEND_HOST}:${BACKEND_PORT}" >&2
langflow run --host "${BACKEND_HOST}" --port "${BACKEND_PORT}" &
BACKEND_PID=$!

cleanup() {
  echo "[startup] Caught signal, shutting down processes" >&2
  if kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${NGINX_PID:-}" ]] && kill -0 "$NGINX_PID" 2>/dev/null; then
    kill "$NGINX_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

NGINX_PREFIX="/app/etc/nginx"
mkdir -p "${NGINX_PREFIX}/logs"

echo "[startup] Launching nginx gateway" >&2
nginx -c "${NGINX_PREFIX}/multi-frontend.conf" -p "${NGINX_PREFIX}" -g "daemon off;" &
NGINX_PID=$!

wait -n "$BACKEND_PID" "$NGINX_PID"
EXIT_CODE=$?

if [[ $EXIT_CODE -ne 0 ]]; then
  echo "[startup] One of the processes exited with code ${EXIT_CODE}" >&2
fi

wait "$BACKEND_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null || true

exit $EXIT_CODE
