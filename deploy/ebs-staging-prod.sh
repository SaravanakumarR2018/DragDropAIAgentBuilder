#!/usr/bin/env bash
set -Eeuo pipefail

#############################################
# Stop-First Docker Deploy (NO Nginx / No TLS)
# - Direct container port exposed to host
# - Blue/Green swap on host ports
# - Safe rollback if new container fails
#############################################

# ---------- Logging + state ----------
CURRENT_STEP=""
DEPLOY_SUCCESS=0
CLEANED_UP=0
SWITCHED=0
STOPPED_ACTIVE=0
HAD_ACTIVE=0

# ---------- Deploy status history rotation ----------
DEPLOY_ENV="/root/deploy_status.env"
DEPLOY_HISTORY="/root/deploy_status_history.env"
if [[ -f "$DEPLOY_ENV" ]]; then
  cat "$DEPLOY_ENV" >> "$DEPLOY_HISTORY"
  echo "" >> "$DEPLOY_HISTORY"
  rm -f "$DEPLOY_ENV"
fi

log()  { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[0;32m✅ %s\033[0m\n" "$*"; }
warn() { printf "\033[0;33m⚠️  %s\033[0m\n" "$*"; }
err()  { printf "\033[0;31m❌ %s\033[0m\n" "$*"; }
step() { CURRENT_STEP="$*"; log "$*"; }

trap 'err "Failed during: ${CURRENT_STEP:-unknown step}"; cleanup_on_failure; exit 1' ERR
trap 'warn "Interrupted (SIGINT/SIGTERM)"; cleanup_on_failure; exit 130' SIGINT SIGTERM
trap 'if [[ "$DEPLOY_SUCCESS" -ne 1 ]]; then warn "Exiting without success"; cleanup_on_failure; fi; report_status' EXIT

# ---------- Defaults ----------
APP_NAME="app"
CONFIG_FILE=""
DOCKER_IMAGE=""
DOCKERHUB_USERNAME=""
DOCKERHUB_TOKEN=""
CONTAINER_ENV_FILE=""
CONTAINER_PORT="7860"
BLUE_PORT="7861"
GREEN_PORT="7862"
HEALTH_PATH="/health"
HEALTH_TIMEOUT="300"
RETRY_MAX="5"
RETRY_SLEEP="5"
KEEP_OLD="1"
DB_USER=""
DB_PASSWORD=""
DB_NAME=""
VOLUME_NAME=""

# ---------- Parse args ----------
usage() {
  cat <<USAGE
Usage: $0 [--config <file>] [--image <repo:tag>]
          [--docker-username <user>] [--docker-token <token>]
          [--env-file <path>] [--container-port <port>]
          [--blue-port <port>] [--green-port <port>]
          [--health-path </health>]
          [--db-user <user>] [--db-password <pass>] [--db-name <db>]
          [--volume-name <volume>] [--app-name <name>] [--prune-old]
USAGE
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)           CONFIG_FILE="${2:-}"; shift 2;;
    --image)            DOCKER_IMAGE="${2:-}"; shift 2;;
    --docker-username)  DOCKERHUB_USERNAME="${2:-}"; shift 2;;
    --docker-token)     DOCKERHUB_TOKEN="${2:-}"; shift 2;;
    --env-file)         CONTAINER_ENV_FILE="${2:-}"; shift 2;;
    --container-port)   CONTAINER_PORT="${2:-}"; shift 2;;
    --blue-port)        BLUE_PORT="${2:-}"; shift 2;;
    --green-port)       GREEN_PORT="${2:-}"; shift 2;;
    --health-path)      HEALTH_PATH="${2:-}"; shift 2;;
    --db-user)          DB_USER="${2:-}"; shift 2;;
    --db-password)      DB_PASSWORD="${2:-}"; shift 2;;
    --db-name)          DB_NAME="${2:-}"; shift 2;;
    --volume-name)      VOLUME_NAME="${2:-}"; shift 2;;
    --app-name)         APP_NAME="${2:-}"; shift 2;;
    --prune-old)        KEEP_OLD="0"; shift 1;;
    -h|--help)          usage;;
    *) err "Unknown option: $1"; usage;;
  esac
done

# ---------- Load config .env ----------
if [[ -n "${CONFIG_FILE}" ]]; then
  step "Loading config from ${CONFIG_FILE}"
  [[ -f "${CONFIG_FILE}" ]] || { err "Config file not found: ${CONFIG_FILE}"; exit 1; }
  set -a; source "${CONFIG_FILE}"; set +a
  ok "Config loaded"
fi

# ---------- Validate ----------
[[ -z "${DOCKER_IMAGE}" ]]  && { err "--image (DOCKER_IMAGE) is required"; usage; }
[[ -z "${VOLUME_NAME}" ]]   && { err "--volume-name is required"; usage; }

# ---------- Root check ----------
[[ $EUID -ne 0 ]] && { err "Please run as root (sudo)."; exit 1; }

# ---------- Helpers ----------
retry() {
  local tries="${1}"; shift
  local sleep_s="${1}"; shift
  for ((i=1; i<=tries; i++)); do
    if "$@"; then return 0; fi
    warn "Attempt ${i}/${tries} failed. Retrying in ${sleep_s}s..."
    sleep "${sleep_s}"
  done
  return 1
}

pkg_installed()  { dpkg -s "$1" >/dev/null 2>&1; }
docker_safe_rm() { docker rm -f "$1" >/dev/null 2>&1 || true; }
docker_exists()  { docker ps -a --format '{{.Names}}' | grep -Fxq "$1"; }
docker_running() { docker ps    --format '{{.Names}}' | grep -Fxq "$1"; }

http_ok() {
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$1" || true)
  [[ "$code" -ge 200 && "$code" -lt 400 ]]
}

# ---------- Install only what's needed (no nginx/certbot) ----------
step "Updating apt package index"; apt-get update -y; ok "apt updated"

install_if_missing() {
  local pkg="$1"
  if ! pkg_installed "$pkg"; then
    step "Installing ${pkg}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    ok "${pkg} installed"
  else
    ok "${pkg} already installed"
  fi
}

install_if_missing curl
install_if_missing jq
install_if_missing docker.io        # nginx / certbot — NOT installed

step "Enabling & starting Docker"
systemctl enable docker >/dev/null 2>&1 || true
systemctl start  docker || true
ok "Docker service ensured"

# ---------- Docker login (optional) ----------
if [[ -n "${DOCKERHUB_USERNAME}" && -n "${DOCKERHUB_TOKEN}" ]]; then
  step "Docker Hub login"
  echo "${DOCKERHUB_TOKEN}" | docker login --username "${DOCKERHUB_USERNAME}" --password-stdin
  ok "Logged in to Docker Hub"
fi

docker info >/dev/null 2>&1 || { err "Docker daemon not reachable"; exit 1; }
ok "Docker daemon reachable"

# ---------- Cleanup old images ----------
cleanup_old_images() {
  step "Cleaning up old Docker images (keeping last 2)"
  local PG_IMAGE=""
  [[ -f "$CONTAINER_ENV_FILE" ]] && \
    PG_IMAGE=$(grep '^POSTGRES_IMAGE=' "$CONTAINER_ENV_FILE" | cut -d'=' -f2- || true)

  local images
  images=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}' \
    | sort -k3 -r | awk 'NR>2 {print $2}')

  if [[ -n "$images" ]]; then
    for img in $images; do
      if [[ -n "$PG_IMAGE" ]] && \
         docker image inspect --format='{{index .RepoDigests 0}}' "$img" 2>/dev/null \
           | grep -q "$PG_IMAGE"; then
        ok "Skipping Postgres image"; continue
      fi
      docker rmi -f "$img" >/dev/null 2>&1 || true
    done
    ok "Old images removed"
  else
    ok "No old images to remove"
  fi
}

# ---------- EBS Volume ----------
ensure_ebs_volume() {
  step "Ensuring EBS volume is mounted and configured"

  local SYSTEM_MOUNT_POINT="/mnt/${VOLUME_NAME}"
  local APP_MOUNT_POINT="/app/ebsstorage"
  local VOLUME_DEVICE="/dev/disk/by-id/scsi-0DO_Volume_${VOLUME_NAME}"
  local LANGFLOW_STORAGE_PATH="${APP_MOUNT_POINT}/langflowstorage"
  local POSTGRES_STORAGE_PATH="${APP_MOUNT_POINT}/postgres"

  if mountpoint -q "${SYSTEM_MOUNT_POINT}"; then
    ok "Volume already mounted at ${SYSTEM_MOUNT_POINT}"
  else
    warn "Volume not mounted. Attempting to mount..."
    mkdir -p "${SYSTEM_MOUNT_POINT}"
    mount -o discard,defaults,noatime "${VOLUME_DEVICE}" "${SYSTEM_MOUNT_POINT}"
    ok "Mounted ${VOLUME_DEVICE} → ${SYSTEM_MOUNT_POINT}"
    if ! grep -qs "${VOLUME_DEVICE}" /etc/fstab; then
      echo "${VOLUME_DEVICE} ${SYSTEM_MOUNT_POINT} ext4 defaults,nofail,discard 0 0" >> /etc/fstab
      ok "Added fstab entry"
    fi
  fi

  if mountpoint -q "${APP_MOUNT_POINT}"; then
    ok "/app/ebsstorage already bound"
  else
    mkdir -p "${APP_MOUNT_POINT}"
    mount --bind "${SYSTEM_MOUNT_POINT}" "${APP_MOUNT_POINT}" || {
      warn "Bind mount failed; symlinking instead"
      ln -sfn "${SYSTEM_MOUNT_POINT}" "${APP_MOUNT_POINT}"
    }
    ok "Linked ${SYSTEM_MOUNT_POINT} → ${APP_MOUNT_POINT}"
  fi

  for dir in "${LANGFLOW_STORAGE_PATH}" "${POSTGRES_STORAGE_PATH}"; do
    [[ -d "$dir" ]] && ok "Exists: $dir" || { mkdir -p "$dir"; ok "Created: $dir"; }
  done

  chown -R 1000:1000 "${LANGFLOW_STORAGE_PATH}"
  chown -R 999:999   "${POSTGRES_STORAGE_PATH}"
  ok "EBS volume ready"
}

# ---------- Active color tracking ----------
ACTIVE_FILE="/var/run/${APP_NAME}-active-color"

ACTIVE_COLOR=""
[[ -f "${ACTIVE_FILE}" ]] && ACTIVE_COLOR="$(cat "${ACTIVE_FILE}" || true)"
[[ -z "${ACTIVE_COLOR}" ]] && ACTIVE_COLOR="green"

if [[ "${ACTIVE_COLOR}" == "blue" ]]; then
  TARGET_COLOR="green"; TARGET_PORT="${GREEN_PORT}"
else
  TARGET_COLOR="blue";  TARGET_PORT="${BLUE_PORT}"
fi

ACTIVE_NAME="${APP_NAME}_${ACTIVE_COLOR}"
TARGET_NAME="${APP_NAME}_${TARGET_COLOR}"

docker_exists "${ACTIVE_NAME}" && HAD_ACTIVE=1 || HAD_ACTIVE=0

ok "Active: ${ACTIVE_COLOR} (${ACTIVE_NAME}) | Target: ${TARGET_COLOR} on port ${TARGET_PORT}"

# ---------- Langflow env prep ----------
prepare_langflow_env() {
  [[ -n "$DB_USER" && -n "$DB_PASSWORD" && -n "$DB_NAME" ]] || {
    err "--db-user, --db-password and --db-name are required"; exit 1;
  }
  [[ -f "$CONTAINER_ENV_FILE" ]] || { err "Env file not found: $CONTAINER_ENV_FILE"; exit 1; }

  local PG_IMAGE="postgres@sha256:d0f363f8366fbc3f52d172c6e76bc27151c3d643b870e1062b4e8bfe65baf609"

  if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
    step "Pulling PostgreSQL image"
    docker pull "$PG_IMAGE"
    ok "PostgreSQL image pulled"
  else
    ok "PostgreSQL image already present"
  fi

  tail -c1 "$CONTAINER_ENV_FILE" | read -r _ || echo >> "$CONTAINER_ENV_FILE"

  _upsert_env() {
    local key="$1" val="$2"
    if grep -q "^${key}=" "$CONTAINER_ENV_FILE"; then
      sed -i "s|^${key}=.*|${key}=${val}|" "$CONTAINER_ENV_FILE"
    else
      echo "${key}=${val}" >> "$CONTAINER_ENV_FILE"
    fi
  }

  _upsert_env "LANGFLOW_DATABASE_URL" "postgresql://$DB_USER:$DB_PASSWORD@postgres:5432/$DB_NAME"
  _upsert_env "POSTGRES_IMAGE"         "$PG_IMAGE"
  _upsert_env "LANGFLOW_CONFIG_DIR"    "/app/langflow"
  _upsert_env "LANGFLOW_SAVE_DB_IN_CONFIG_DIR" "false"
}

# ---------- PostgreSQL ----------
ensure_postgres() {
  step "Ensuring PostgreSQL container"
  docker network inspect langflow-net >/dev/null 2>&1 || docker network create langflow-net

  local PG_IMAGE
  PG_IMAGE=$(grep '^POSTGRES_IMAGE=' "$CONTAINER_ENV_FILE" | cut -d= -f2-)

  if docker_exists "postgres"; then
    if docker_running "postgres"; then
      local current_mount
      current_mount=$(docker inspect -f \
        '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}' \
        postgres 2>/dev/null || true)
      if [[ "${current_mount}" == "/app/ebsstorage/postgres" ]]; then
        ok "PostgreSQL already running with correct mount"; return 0
      fi
      warn "Wrong mount detected — recreating"
    else
      warn "Postgres stopped — recreating"
    fi
    docker stop postgres >/dev/null 2>&1 || true
    docker rm -f postgres >/dev/null 2>&1 || true
    docker volume rm -f langflow-postgres >/dev/null 2>&1 || true
  fi

  docker run -d \
    --name postgres \
    --network langflow-net \
    -e POSTGRES_USER="${DB_USER}" \
    -e POSTGRES_PASSWORD="${DB_PASSWORD}" \
    -e POSTGRES_DB="${DB_NAME}" \
    -v /app/ebsstorage/postgres:/var/lib/postgresql/data \
    --restart unless-stopped \
    "${PG_IMAGE}"
  ok "PostgreSQL started"
}

# ---------- Stop / Start containers ----------
stop_active_container() {
  if [[ "${HAD_ACTIVE}" -eq 1 ]] && docker_running "${ACTIVE_NAME}"; then
    step "Stopping active container ${ACTIVE_NAME}"
    docker stop "${ACTIVE_NAME}" >/dev/null
    STOPPED_ACTIVE=1
    ok "Stopped ${ACTIVE_NAME}"
  else
    ok "No running active container to stop"
  fi
}

start_target_container() {
  step "Starting ${TARGET_NAME} on host port ${TARGET_PORT}"
  docker_safe_rm "${TARGET_NAME}"

  local run_cmd=(
    docker run -d
    --restart unless-stopped
    --name "${TARGET_NAME}"
    -l "app=${APP_NAME}"
    -l "color=${TARGET_COLOR}"
    -p "${TARGET_PORT}:${CONTAINER_PORT}"   # ← direct host port, no nginx
    --network langflow-net
    -v /app/ebsstorage/langflowstorage:/app/langflow
  )

  if [[ -n "${CONTAINER_ENV_FILE}" ]]; then
    [[ -f "${CONTAINER_ENV_FILE}" ]] || { err "Env file not found: ${CONTAINER_ENV_FILE}"; exit 1; }
    run_cmd+=( --env-file "${CONTAINER_ENV_FILE}" )
  fi

  run_cmd+=( "${DOCKER_IMAGE}" )
  "${run_cmd[@]}"
  ok "Container started"
}

wait_until_healthy() {
  step "Health-checking ${TARGET_NAME} on port ${TARGET_PORT}"
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  local has_healthcheck="0"
  local last_log=0

  docker inspect --format '{{if .Config.Healthcheck}}yes{{else}}no{{end}}' \
    "${TARGET_NAME}" 2>/dev/null | grep -q yes && has_healthcheck="1"

  [[ "$has_healthcheck" == "1" ]] \
    && ok "Docker HEALTHCHECK found; waiting for 'healthy'" \
    || warn "No Docker HEALTHCHECK; using HTTP ${HEALTH_PATH}"

  while (( SECONDS < deadline )); do
    if [[ "${has_healthcheck}" == "1" ]]; then
      local status
      status=$(docker inspect --format '{{.State.Health.Status}}' "${TARGET_NAME}" 2>/dev/null || echo "starting")
      [[ "$status" == "healthy"   ]] && { ok "Container healthy"; return 0; }
      [[ "$status" == "unhealthy" ]] && { err "Container unhealthy"; return 1; }
    fi

    http_ok "http://127.0.0.1:${TARGET_PORT}${HEALTH_PATH}" && { ok "HTTP health OK"; return 0; }

    (( SECONDS - last_log >= 10 )) && {
      log "Waiting... elapsed $((SECONDS - (deadline - HEALTH_TIMEOUT)))s"
      last_log=$SECONDS
    }
    sleep 2
  done

  err "Health check timed out after ${HEALTH_TIMEOUT}s"
  return 1
}

# ---------- Switch active color tracking ----------
switch_active() {
  step "Marking ${TARGET_COLOR} as active"
  echo "${TARGET_COLOR}" > "${ACTIVE_FILE}"
  SWITCHED=1
  ok "Active color updated to ${TARGET_COLOR}"
}

# ---------- Cleanup old container ----------
cleanup_old_container() {
  if [[ "${KEEP_OLD}" == "0" && "${HAD_ACTIVE}" -eq 1 ]]; then
    step "Pruning old container ${ACTIVE_NAME}"
    docker_safe_rm "${ACTIVE_NAME}"
    ok "Old container removed"
  else
    ok "Keeping old container for quick rollback (${ACTIVE_NAME})"
  fi
}

# ---------- Failure cleanup ----------
cleanup_on_failure() {
  [[ "${CLEANED_UP}" -eq 1 ]] && return 0
  CLEANED_UP=1
  warn "Running failure cleanup"

  # If we already switched the color file, revert it
  if [[ "${SWITCHED}" -eq 1 ]]; then
    step "Reverting active color back to ${ACTIVE_COLOR}"
    echo "${ACTIVE_COLOR}" > "${ACTIVE_FILE}"
  fi

  # Remove failed target container
  docker_exists "${TARGET_NAME}" && {
    warn "Removing failed container ${TARGET_NAME}"
    docker rm -f "${TARGET_NAME}" >/dev/null 2>&1 || true
  }

  # Restart old container if we stopped it
  if [[ "${STOPPED_ACTIVE}" -eq 1 && "${HAD_ACTIVE}" -eq 1 ]]; then
    docker_running "${ACTIVE_NAME}" || {
      warn "Restarting previous container ${ACTIVE_NAME}"
      docker start "${ACTIVE_NAME}" >/dev/null 2>&1 || true
    }
  fi

  ok "Failure cleanup done"
}

# ---------- Status report ----------
report_status() {
  local status desc running
  running=$(docker ps --filter "name=${APP_NAME}_" --format "{{.Names}} {{.Image}}" | head -n1 || true)

  if   [[ "$DEPLOY_SUCCESS" -eq 1 ]]; then
    status="success"; desc="Deployment succeeded"
  elif [[ "$STOPPED_ACTIVE" -eq 1 && "$HAD_ACTIVE" -eq 1 ]]; then
    status="failure"; desc="Deployment failed, rolled back"
  elif [[ -n "$running" ]]; then
    status="failure"; desc="Deployment failed. Older container live"
  else
    status="failure"; desc="Deployment failed. No container running"
  fi

  {
    echo "FINAL_STATUS=\"$status\""
    echo "FINAL_DESCRIPTION=\"${desc:0:140}\""
    echo "FINAL_CONTAINER=\"$running\""
  } > /root/deploy_status.env
}

# ============================================================
# MAIN FLOW
# ============================================================
cleanup_old_images

step "Pulling Docker image: ${DOCKER_IMAGE}"
retry "${RETRY_MAX}" "${RETRY_SLEEP}" docker pull "${DOCKER_IMAGE}"
ok "Image pulled"

ensure_ebs_volume
prepare_langflow_env
ensure_postgres

# 1) Stop old container (frees port + RAM)
stop_active_container

# 2) Start new container & health check
start_target_container
wait_until_healthy

# 3) Mark new color as active (no nginx reload needed)
switch_active

ok "======================================"
ok " Deployment successful!"
ok " App running: ${TARGET_NAME}"
ok " Access at  : http://<SERVER_IP>:${TARGET_PORT}"
ok "======================================"

# 4) Cleanup old container if --prune-old
cleanup_old_container
DEPLOY_SUCCESS=1