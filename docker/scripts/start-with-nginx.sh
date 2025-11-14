#!/usr/bin/env bash
set -euo pipefail

LANGFLOW_HOST="${LANGFLOW_HOST:-0.0.0.0}"
LANGFLOW_PORT="${LANGFLOW_PORT:-7860}"
DEFAULT_CMD=("langflow" "run" "--host" "${LANGFLOW_HOST}" "--port" "${LANGFLOW_PORT}")

if [[ $# -gt 0 ]]; then
  LANGFLOW_CMD=("$@")
else
  LANGFLOW_CMD=("${DEFAULT_CMD[@]}")
fi

BACKEND_PID=""
NGINX_PID=""

cleanup() {
  if [[ -n "${NGINX_PID}" ]]; then
    kill "${NGINX_PID}" 2>/dev/null || true
    NGINX_PID=""
  fi
  if [[ -n "${BACKEND_PID}" ]]; then
    kill "${BACKEND_PID}" 2>/dev/null || true
    BACKEND_PID=""
  fi
}

trap 'cleanup; exit 0' INT TERM
trap cleanup EXIT

"${LANGFLOW_CMD[@]}" &
BACKEND_PID=$!

nginx -g "daemon off;" -c /app/nginx/multi-frontend.conf &
NGINX_PID=$!

set +e
wait -n "${BACKEND_PID}" "${NGINX_PID}"
STATUS=$?
set -e

cleanup
wait "${BACKEND_PID}" 2>/dev/null || true
wait "${NGINX_PID}" 2>/dev/null || true

exit "${STATUS}"
