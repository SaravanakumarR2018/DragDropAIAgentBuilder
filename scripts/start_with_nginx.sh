#!/bin/sh
set -eu

BACKEND_HOST="${LANGFLOW_HOST:-0.0.0.0}"
PUBLIC_PORT="${LANGFLOW_PORT:-7860}"
BACKEND_PORT="${LANGFLOW_BACKEND_PORT:-7861}"

export LANGFLOW_HOST="$BACKEND_HOST"
export LANGFLOW_BACKEND_PORT="$BACKEND_PORT"
export LANGFLOW_PUBLIC_PORT="$PUBLIC_PORT"
export LANGFLOW_PORT="$BACKEND_PORT"

CONFIG_TEMPLATE="/etc/nginx/conf.d/frontend2.conf.template"
CONFIG_PATH="/etc/nginx/conf.d/frontend2.conf"

if [ -f "$CONFIG_TEMPLATE" ]; then
  sed \
    -e "s/{{NGINX_PORT}}/${PUBLIC_PORT}/g" \
    -e "s/{{BACKEND_PORT}}/${BACKEND_PORT}/g" \
    "$CONFIG_TEMPLATE" > "$CONFIG_PATH"
fi

cleanup() {
  if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID"
  fi
  if [ -n "${NGINX_PID:-}" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
    kill "$NGINX_PID"
  fi
}

trap 'cleanup' INT TERM

/usr/sbin/runuser -u user -- langflow run --host "$BACKEND_HOST" --port "$BACKEND_PORT" --log-level info &
BACKEND_PID=$!

/usr/sbin/nginx -g "daemon off;" &
NGINX_PID=$!

while :; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    wait "$BACKEND_PID"
    EXIT_CODE=$?
    cleanup
    wait "$NGINX_PID" 2>/dev/null || true
    exit "$EXIT_CODE"
  fi

  if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    wait "$NGINX_PID"
    EXIT_CODE=$?
    cleanup
    wait "$BACKEND_PID" 2>/dev/null || true
    exit "$EXIT_CODE"
  fi

  sleep 1
done
