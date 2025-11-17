#!/usr/bin/env bash
set -euo pipefail

# Resolve runtime networking defaults before rendering configs.
LANGFLOW_HOST="${LANGFLOW_HOST:-0.0.0.0}"
LANGFLOW_PORT="${LANGFLOW_PORT:-7861}"
LANGFLOW_BACKEND_PORT="${LANGFLOW_BACKEND_PORT:-${LANGFLOW_PORT}}"
export LANGFLOW_HOST LANGFLOW_PORT LANGFLOW_BACKEND_PORT

# Render the nginx config with the runtime ports.
ENV_VARS='${NGINX_PORT} ${LANGFLOW_BACKEND_PORT}'
if [ -f /etc/nginx/nginx.conf.template ]; then
  envsubst "${ENV_VARS}" < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf
fi

langflow run --host "${LANGFLOW_HOST}" --port "${LANGFLOW_PORT}" &
LANGFLOW_PID=$!

nginx -g "daemon off;" &
NGINX_PID=$!

terminate() {
  kill -TERM "$LANGFLOW_PID" "$NGINX_PID" 2>/dev/null || true
}

trap terminate INT TERM

set +e
wait -n "$LANGFLOW_PID" "$NGINX_PID"
EXIT_CODE=$?
terminate
wait "$LANGFLOW_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null || true
exit "$EXIT_CODE"