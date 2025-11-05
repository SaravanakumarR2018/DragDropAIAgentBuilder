#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#############################################
# Stop-First Docker Deploy w/ Nginx + TLS
# - Minimizes CPU/RAM: only one app container at a time
# - Safe rollback: restarts old container if new fails
# - Idempotent & CI/CD friendly
#############################################

# ---------- Logging + state ----------
CURRENT_STEP=""
DEPLOY_SUCCESS=0        # set to 1 only when deployment completes
CLEANED_UP=0            # guard to avoid double cleanup
SWITCHED=0              # set to 1 right after successful switch
STOPPED_ACTIVE=0        # set to 1 when we stop the active container
HAD_ACTIVE=0            # set to 1 if an active container existed
MAINTENANCE_ENABLED=0   # set to 1 while maintenance page is live
BACKUP_FILE=""
BACKUP_DIR="/app/ebsstorage/postgres_backups"
ACTIVE_IMAGE=""
ACTIVE_IMAGE_TAG=""
FAILURE_REASON=""
declare -a POSTGRES_DATABASES=()
EBSSTORAGE_SIZE=""
EBSTORAGE_SIZE=""
BACKUP_DIR_SIZE=""
LATEST_BACKUP_FILE=""
LATEST_BACKUP_SIZE=""
ACTIVE_PORT=""
STORAGE_METRICS_JSON=""
STORAGE_METRICS_PRETTY=""
ALEMBIC_CHANGES_REQUIRED=0
ALEMBIC_MIGRATIONS_APPLIED=0
RESTORE_POSTGRES_ON_ROLLBACK=0

# ---------- Deploy status history rotation ----------
DEPLOY_ENV="/root/deploy_status.env"
DEPLOY_HISTORY="/root/deploy_status_history.env"
if [[ -f "$DEPLOY_ENV" ]]; then
  cat "$DEPLOY_ENV" >> "$DEPLOY_HISTORY"
  echo "" >> "$DEPLOY_HISTORY"
  rm -f "$DEPLOY_ENV"
fi

log()      { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }
ok()       { printf "\033[0;32m✅ %s\033[0m\n" "$*"; }
warn()     { printf "\033[0;33m⚠️  %s\033[0m\n" "$*"; }
err()      { printf "\033[0;31m❌ %s\033[0m\n" "$*"; }
step()     { CURRENT_STEP="$*"; log "$*"; }

# Traps: run cleanup on errors/interrupts/abnormal exit
trap 'err "Failed during: ${CURRENT_STEP:-unknown step}"; cleanup_on_failure; exit 1' ERR
trap 'warn "Interrupted (SIGINT/SIGTERM)"; cleanup_on_failure; exit 130' SIGINT SIGTERM
trap 'if [[ "$DEPLOY_SUCCESS" -ne 1 ]]; then warn "Exiting without success"; cleanup_on_failure; fi; report_status' EXIT

# ---------- Defaults ----------
APP_NAME="app"
CONFIG_FILE=""            # Script config .env (DOCKER_IMAGE, DOMAIN, etc)
DOCKER_IMAGE=""           # e.g. saravanakr/langflow:2.0.4
DOCKERHUB_USERNAME=""     # optional
DOCKERHUB_TOKEN=""        # optional
DOMAIN=""                 # e.g. demo.example.com
EMAIL=""                  # certbot email, default: admin@DOMAIN
CONTAINER_ENV_FILE=""     # passed to docker via --env-file
CONTAINER_PORT="7860"     # internal port inside container
BLUE_PORT="7861"          # host port for blue
GREEN_PORT="7862"         # host port for green
HEALTH_PATH="/health"     # path checked over HTTP
HEALTH_TIMEOUT="300"      # seconds
RETRY_MAX="5"
RETRY_SLEEP="5"
KEEP_OLD="1"              # keep old color container for quick rollback (1=yes, 0=no)
DB_USER=""
DB_PASSWORD=""
DB_NAME=""
VOLUME_NAME=""
# ---------- Parse args ----------
usage() {
  cat <<USAGE
Usage: $0 [--config <file>] [--image <repo:tag>] [--domain <domain>]
          [--docker-username <user>] [--docker-token <token>]
          [--env-file <path>] [--container-port <port>]
          [--blue-port <port>] [--green-port <port>]
          [--health-path </health>] [--email <you@domain>]
          [--db-user <user>] [--db-password <pass>] [--db-name <db>]
          [--volume-name <volume>] [--app-name <name>] [--prune-old]
USAGE
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)           CONFIG_FILE="${2:-}"; shift 2;;
    --image)            DOCKER_IMAGE="${2:-}"; shift 2;;
    --domain)           DOMAIN="${2:-}"; shift 2;;
    --docker-username)  DOCKERHUB_USERNAME="${2:-}"; shift 2;;
    --docker-token)     DOCKERHUB_TOKEN="${2:-}"; shift 2;;
    --env-file)         CONTAINER_ENV_FILE="${2:-}"; shift 2;;
    --container-port)   CONTAINER_PORT="${2:-}"; shift 2;;
    --blue-port)        BLUE_PORT="${2:-}"; shift 2;;
    --green-port)       GREEN_PORT="${2:-}"; shift 2;;
    --health-path)      HEALTH_PATH="${2:-}"; shift 2;;
    --email)            EMAIL="${2:-}"; shift 2;;
    --db-user)         DB_USER="${2:-}"; shift 2;;
    --db-password)     DB_PASSWORD="${2:-}"; shift 2;;
    --db-name)         DB_NAME="${2:-}"; shift 2;;
    --volume-name)     VOLUME_NAME="${2:-}"; shift 2;;
    --app-name)         APP_NAME="${2:-}"; shift 2;;
    --prune-old)        KEEP_OLD="0"; shift 1;;
    -h|--help)          usage;;
    *) err "Unknown option: $1"; usage;;
  esac
done

# ---------- Load script config .env (optional) ----------
# Allows: DOCKER_IMAGE=..., DOMAIN=..., DOCKERHUB_USERNAME=..., DOCKERHUB_TOKEN=..., CONTAINER_ENV_FILE=..., etc.
if [[ -n "${CONFIG_FILE}" ]]; then
  step "Loading config from ${CONFIG_FILE}"
  if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    set -a; source "${CONFIG_FILE}"; set +a
    ok "Config loaded"
  else
    err "Config file not found: ${CONFIG_FILE}"; exit 1
  fi
fi

# ---------- Validate required inputs ----------
[[ -z "${DOCKER_IMAGE}" ]] && { err "--image (DOCKER_IMAGE) is required"; usage; }
[[ -z "${DOMAIN}" ]] && { err "--domain (DOMAIN) is required"; usage; }
[[ -z "${VOLUME_NAME}" ]] && { err "--volume-name is required"; usage; }
[[ -z "${EMAIL}" ]] && EMAIL="admin@${DOMAIN#www.}"

# ---------- Root check ----------
if [[ $EUID -ne 0 ]]; then
  err "Please run as root (sudo)."; exit 1
fi

# ---------- Helpers ----------
retry() {
  local tries="${1}"; shift
  local sleep_s="${1}"; shift
  local i
  for ((i=1; i<=tries; i++)); do
    if "$@"; then return 0; fi
    warn "Attempt ${i}/${tries} failed. Retrying in ${sleep_s}s..."
    sleep "${sleep_s}"
  done
  return 1
}

pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }
service_active() { systemctl is-active --quiet "$1"; }
docker_safe_rm() { docker rm -f "$1" >/dev/null 2>&1 || true; }
docker_exists()  { docker ps -a --format '{{.Names}}' | grep -Fxq "$1"; }
docker_running() { docker ps --format '{{.Names}}' | grep -Fxq "$1"; }

disable_restart_policy() {
  local cname="$1"
  if docker_exists "$cname"; then
    log "Disabling restart policy for ${cname}"
    docker update --restart=no "$cname" >/dev/null 2>&1 || warn "Could not disable restart policy for ${cname}"
  fi
}

enable_restart_policy() {
  local cname="$1"
  if docker_exists "$cname"; then
    log "Restoring restart policy for ${cname}"
    docker update --restart=unless-stopped "$cname" >/dev/null 2>&1 || warn "Could not re-enable restart policy for ${cname}"
  fi
}

http_ok() {
  local url="$1"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" || true)
  [[ "$code" -ge 200 && "$code" -lt 400 ]]
}

sanitize_for_filename() {
  local input="$1"
  if [[ -z "$input" ]]; then
    echo "unknown"
    return
  fi
  echo "$input" | tr -c 'A-Za-z0-9._-' '_'
}

human_readable_dir_size() {
  local path="$1"
  if [[ -d "$path" ]]; then
    du -sh "$path" 2>/dev/null | awk '{print $1}'
  else
    echo "missing"
  fi
}

human_readable_file_size() {
  local path="$1"
  if [[ -f "$path" ]]; then
    du -sh "$path" 2>/dev/null | awk '{print $1}'
  else
    echo "missing"
  fi
}

bytes_for_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    du -sb "$path" 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

humanize_bytes() {
  local bytes="$1"
  if [[ -z "$bytes" ]]; then
    echo "missing"
    return
  fi
  numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || echo "${bytes}B"
}

json_escape() {
  local str="$1"
  str="${str//\\/\\\\}"
  str="${str//\"/\\\"}"
  str="${str//$'\n'/\\n}"
  str="${str//$'\r'/}"
  echo "$str"
}

collect_storage_metrics() {
  local context="${1:-Storage usage snapshot}"
  local quiet="0"
  if [[ "${2:-}" == "--quiet" ]]; then
    quiet="1"
  fi

  local ebsstorage_path="/app/ebsstorage"
  local ebstorage_path="/app/ebstorage"
  local backup_path="${BACKUP_DIR}"

  local ebsstorage_bytes="$(bytes_for_path "$ebsstorage_path")"
  local ebstorage_bytes="$(bytes_for_path "$ebstorage_path")"
  local backup_dir_bytes="$(bytes_for_path "$backup_path")"

  local ebsstorage_bytes_json="null"
  local ebstorage_bytes_json="null"
  local backup_dir_bytes_json="null"

  [[ -n "$ebsstorage_bytes" ]] && ebsstorage_bytes_json="$ebsstorage_bytes"
  [[ -n "$ebstorage_bytes" ]] && ebstorage_bytes_json="$ebstorage_bytes"
  [[ -n "$backup_dir_bytes" ]] && backup_dir_bytes_json="$backup_dir_bytes"

  local ebsstorage_human="$(humanize_bytes "$ebsstorage_bytes")"
  local ebstorage_human="$(humanize_bytes "$ebstorage_bytes")"
  local backup_dir_human="$(humanize_bytes "$backup_dir_bytes")"

  local -a ebstorage_sub_entries=()
  local -a ebstorage_pretty_entries=()
  if [[ -d "$ebstorage_path" ]]; then
    local -a subdirs=()
    mapfile -t subdirs < <(find "$ebstorage_path" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort)
    local dir
    for dir in "${subdirs[@]}"; do
      [[ -n "$dir" ]] || continue
      local dir_bytes="$(bytes_for_path "$dir")"
      local dir_bytes_json="null"
      [[ -n "$dir_bytes" ]] && dir_bytes_json="$dir_bytes"
      local dir_human="$(humanize_bytes "$dir_bytes")"
      local dir_name="$(basename "$dir")"
      local escaped_path="$(json_escape "$dir")"
      local escaped_name="$(json_escape "$dir_name")"
      local escaped_human="$(json_escape "$dir_human")"
      ebstorage_sub_entries+=("{\"path\":\"${escaped_path}\",\"name\":\"${escaped_name}\",\"size_bytes\":${dir_bytes_json},\"size_human\":\"${escaped_human}\"}")
      ebstorage_pretty_entries+=("      {\n        \"path\": \"${escaped_path}\",\n        \"name\": \"${escaped_name}\",\n        \"size_bytes\": ${dir_bytes_json},\n        \"size_human\": \"${escaped_human}\"\n      }")
    done
  fi

  local ebstorage_subfolders_json="[]"
  if [[ ${#ebstorage_sub_entries[@]} -gt 0 ]]; then
    local IFS=,
    ebstorage_subfolders_json="[${ebstorage_sub_entries[*]}]"
  fi

  local pretty_subfolders=""
  if [[ ${#ebstorage_pretty_entries[@]} -gt 0 ]]; then
    local idx
    for idx in "${!ebstorage_pretty_entries[@]}"; do
      pretty_subfolders+="${ebstorage_pretty_entries[idx]}"
      if (( idx < ${#ebstorage_pretty_entries[@]} - 1 )); then
        pretty_subfolders+=$',\n'
      else
        pretty_subfolders+=$'\n'
      fi
    done
  fi

  local -a backup_entries=()
  local -a backup_pretty_entries=()
  local latest_entry_json="null"
  local latest_pretty="      null\n"
  local latest_path=""
  local latest_human="missing"
  if [[ -d "$backup_path" ]]; then
    local -a backup_paths=()
    mapfile -t backup_paths < <(find "$backup_path" -maxdepth 1 -type f -name '*.sql.gz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{print $2}')
    local backup
    for backup in "${backup_paths[@]}"; do
      [[ -n "$backup" ]] || continue
      local backup_bytes="$(bytes_for_path "$backup")"
      local backup_bytes_json="null"
      [[ -n "$backup_bytes" ]] && backup_bytes_json="$backup_bytes"
      local backup_human="$(humanize_bytes "$backup_bytes")"
      local backup_name="$(basename "$backup")"
      local mtime_epoch="$(stat -c %Y "$backup" 2>/dev/null || echo "")"
      local mtime_iso=""
      if [[ -n "$mtime_epoch" ]]; then
        mtime_iso="$(date -u -d "@${mtime_epoch}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")"
      fi
      local mtime_json="null"
      local escaped_iso=""
      if [[ -n "$mtime_iso" ]]; then
        escaped_iso="$(json_escape "$mtime_iso")"
        mtime_json="\"${escaped_iso}\""
      fi
      local escaped_path="$(json_escape "$backup")"
      local escaped_name="$(json_escape "$backup_name")"
      local escaped_human="$(json_escape "$backup_human")"
      local entry="{\"path\":\"${escaped_path}\",\"name\":\"${escaped_name}\",\"size_bytes\":${backup_bytes_json},\"size_human\":\"${escaped_human}\",\"modified\":${mtime_json}}"
      backup_entries+=("${entry}")
      local pretty_entry="      {\n        \"path\": \"${escaped_path}\",\n        \"name\": \"${escaped_name}\",\n        \"size_bytes\": ${backup_bytes_json},\n        \"size_human\": \"${escaped_human}\",\n        \"modified\": ${mtime_json}\n      }"
      backup_pretty_entries+=("${pretty_entry}")
      if [[ -z "$latest_entry_json" || "$latest_entry_json" == "null" ]]; then
        latest_entry_json="${entry}"
        latest_pretty="      {\n        \"path\": \"${escaped_path}\",\n        \"name\": \"${escaped_name}\",\n        \"size_bytes\": ${backup_bytes_json},\n        \"size_human\": \"${escaped_human}\",\n        \"modified\": ${mtime_json}\n      }\n"
        latest_path="$backup"
        latest_human="$backup_human"
      fi
    done
  fi

  local backups_files_json="[]"
  if [[ ${#backup_entries[@]} -gt 0 ]]; then
    local IFS=,
    backups_files_json="[${backup_entries[*]}]"
  fi

  local pretty_backups=""
  if [[ ${#backup_pretty_entries[@]} -gt 0 ]]; then
    local idx
    for idx in "${!backup_pretty_entries[@]}"; do
      pretty_backups+="${backup_pretty_entries[idx]}"
      if (( idx < ${#backup_pretty_entries[@]} - 1 )); then
        pretty_backups+=$',\n'
      else
        pretty_backups+=$'\n'
      fi
    done
  fi

  [[ -z "$latest_entry_json" ]] && latest_entry_json="null"

  local ebsstorage_json="{\"path\":\"$(json_escape "$ebsstorage_path")\",\"size_bytes\":${ebsstorage_bytes_json},\"size_human\":\"$(json_escape "$ebsstorage_human")\"}"
  local ebstorage_json="{\"path\":\"$(json_escape "$ebstorage_path")\",\"size_bytes\":${ebstorage_bytes_json},\"size_human\":\"$(json_escape "$ebstorage_human")\",\"subfolders\":${ebstorage_subfolders_json}}"
  local backups_json="{\"path\":\"$(json_escape "$backup_path")\",\"size_bytes\":${backup_dir_bytes_json},\"size_human\":\"$(json_escape "$backup_dir_human")\",\"files\":${backups_files_json},\"latest\":${latest_entry_json}}"

  STORAGE_METRICS_JSON="{\"ebsstorage\":${ebsstorage_json},\"ebstorage\":${ebstorage_json},\"postgres_backups\":${backups_json}}"

  local pretty="{
  \"ebsstorage\": {
    \"path\": \"$(json_escape "$ebsstorage_path")\",
    \"size_bytes\": ${ebsstorage_bytes_json},
    \"size_human\": \"$(json_escape "$ebsstorage_human")\"
  },
  \"ebstorage\": {
    \"path\": \"$(json_escape "$ebstorage_path")\",
    \"size_bytes\": ${ebstorage_bytes_json},
    \"size_human\": \"$(json_escape "$ebstorage_human")\",
    \"subfolders\": [
$( [[ -n "$pretty_subfolders" ]] && printf '%s' "$pretty_subfolders" || printf '      ' )    ]
  },
  \"postgres_backups\": {
    \"path\": \"$(json_escape "$backup_path")\",
    \"size_bytes\": ${backup_dir_bytes_json},
    \"size_human\": \"$(json_escape "$backup_dir_human")\",
    \"files\": [
$( [[ -n "$pretty_backups" ]] && printf '%s' "$pretty_backups" || printf '      ' )    ],
    \"latest\":
$(printf '%s' "$latest_pretty")  }
}
"

  STORAGE_METRICS_PRETTY="${pretty%$'\n'}"

  EBSSTORAGE_SIZE="$ebsstorage_human"
  EBSTORAGE_SIZE="$ebstorage_human"
  BACKUP_DIR_SIZE="$backup_dir_human"
  LATEST_BACKUP_FILE="$latest_path"
  LATEST_BACKUP_SIZE="$latest_human"

  if [[ "${quiet}" -ne 1 ]]; then
    log "${context}" || true
    printf '%s\n' "${STORAGE_METRICS_PRETTY}" || true
  fi
}

prune_old_backups() {
  local keep=3
  [[ -d "${BACKUP_DIR}" ]] || return 0

  local -a _backups=()
  mapfile -t _backups < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -name '*.sql.gz' -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr | awk '{print $2}')

  local count=${#_backups[@]}
  if (( count <= keep )); then
    ok "Backup rotation not required (count: ${count})"
    return 0
  fi

  log "Pruning old PostgreSQL backups (keeping latest ${keep})"
  local idx
  for (( idx=keep; idx<count; idx++ )); do
    local old_file="${_backups[idx]}"
    [[ -n "$old_file" ]] || continue
    rm -f "$old_file" && ok "Removed old backup $(basename "$old_file")" || warn "Failed to remove $old_file"
  done
}

record_active_image_info() {
  if docker_exists "${ACTIVE_NAME}"; then
    ACTIVE_IMAGE=$(docker inspect --format '{{.Config.Image}}' "${ACTIVE_NAME}" 2>/dev/null || echo "")
    if [[ -n "$ACTIVE_IMAGE" ]]; then
      if [[ "$ACTIVE_IMAGE" == *":"* ]]; then
        ACTIVE_IMAGE_TAG=$(sanitize_for_filename "${ACTIVE_IMAGE##*:}")
      else
        ACTIVE_IMAGE_TAG=$(sanitize_for_filename "${ACTIVE_IMAGE}")
      fi
    else
      ACTIVE_IMAGE_TAG="unknown"
    fi
    ok "Recorded active container image: ${ACTIVE_IMAGE:-unknown}"
  else
    ACTIVE_IMAGE=""
    ACTIVE_IMAGE_TAG="none"
    ok "No existing active container image detected"
  fi
}

backup_postgres_server() {
  [[ -d "${BACKUP_DIR}" ]] || mkdir -p "${BACKUP_DIR}"
  local tag timestamp
  tag=$(sanitize_for_filename "${ACTIVE_IMAGE_TAG:-previous}")
  timestamp=$(date +%Y%m%d-%H%M%S)
  BACKUP_FILE="${BACKUP_DIR}/${timestamp}_${tag}.sql.gz"

  step "Backing up PostgreSQL cluster to ${BACKUP_FILE}"
  retry "${RETRY_MAX}" "${RETRY_SLEEP}" docker exec -e PGPASSWORD="${DB_PASSWORD}" postgres pg_isready -U "${DB_USER}"
  docker exec -e PGPASSWORD="${DB_PASSWORD}" postgres pg_dumpall -U "${DB_USER}" --clean --if-exists \
    | gzip > "${BACKUP_FILE}"
  ok "PostgreSQL backup complete"
  prune_old_backups
  collect_storage_metrics "Storage usage snapshot (post-backup)"
}

list_postgres_databases() {
  docker exec -e PGPASSWORD="${DB_PASSWORD}" postgres \
    psql -U "${DB_USER}" -tAc "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname" \
    | awk 'NF'
}

collect_postgres_databases() {
  mapfile -t POSTGRES_DATABASES < <(list_postgres_databases)
  if [[ ${#POSTGRES_DATABASES[@]} -eq 0 ]]; then
    err "No PostgreSQL databases detected"
    exit 1
  fi
  ok "Databases detected: ${POSTGRES_DATABASES[*]}"
}

alembic_revisions_in_sync() {
  local current="${1:-}"
  local heads="${2:-}"

  current=$(echo "$current" | tr -d '[:space:]')
  heads=$(echo "$heads" | tr -d '[:space:]')
  local current_lower=$(echo "$current" | tr '[:upper:]' '[:lower:]')
  local heads_lower=$(echo "$heads" | tr '[:upper:]' '[:lower:]')

  if [[ -z "$current_lower" || "$current_lower" == "none" ]]; then
    if [[ -z "$heads_lower" || "$heads_lower" == "none" ]]; then
      return 0
    else
      return 1
    fi
  fi

  if [[ -z "$heads_lower" || "$heads_lower" == "none" ]]; then
    return 0
  fi

  if [[ "$heads_lower" == "$current_lower" ]]; then
    return 0
  fi

  if [[ "$heads_lower" == *,* ]]; then
    return 1
  fi

  if [[ ",$heads_lower," == *",$current_lower,"* ]]; then
    return 1
  fi

  return 1
}

fetch_alembic_revisions() {
  local db="$1"

  local -a script_lines=(
    "set -euo pipefail"
    "cd /app/src/backend/base"
    "current=\$(alembic current 2>/dev/null | awk -F': ' 'NF{print \\$NF}' | tail -n1)"
    "heads=\$(alembic heads 2>/dev/null | awk 'NF{print \\$1}' | tr '\n' ',' | sed 's/,$//')"
    "echo 'ALEMBIC_CURRENT='\"\${current:-none}\""
    "echo 'ALEMBIC_HEADS='\"\${heads:-none}\""
    "echo '--- Alembic current (${db}) ---'"
    "alembic current"
    "echo '--- Alembic heads (${db}) ---'"
    "alembic heads"
  )

  local script=""
  printf -v script '%s\n' "${script_lines[@]}"

  local run_args=( docker run --rm --network langflow-net )

  if [[ -n "${CONTAINER_ENV_FILE}" ]]; then
    run_args+=( --env-file "${CONTAINER_ENV_FILE}" )
  fi

  run_args+=(
    -e LANGFLOW_DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${db}"
    -e LANGFLOW_CONFIG_DIR="/app/langflow"
    -e LANGFLOW_SAVE_DB_IN_CONFIG_DIR="false"
    -v /app/ebsstorage/langflowstorage:/app/langflow
    "${DOCKER_IMAGE}"
    bash -lc "$script"
  )

  local output
  if ! output=$("${run_args[@]}"); then
    return 1
  fi

  printf '%s\n' "$output"
}

check_alembic_changes() {
  ALEMBIC_CHANGES_REQUIRED=0
  local db
  for db in "${POSTGRES_DATABASES[@]}"; do
    [[ -z "$db" ]] && continue
    step "Checking Alembic revisions for database ${db}"
    local output
    if ! output=$(fetch_alembic_revisions "$db"); then
      FAILURE_REASON="Unable to inspect Alembic revisions for ${db}"
      err "Failed to inspect Alembic revisions for ${db}"
      exit 1
    fi
    printf '%s\n' "$output"
    local current heads
    current=$(grep '^ALEMBIC_CURRENT=' <<< "$output" | tail -n1 | cut -d= -f2-)
    heads=$(grep '^ALEMBIC_HEADS=' <<< "$output" | tail -n1 | cut -d= -f2-)
    if ! alembic_revisions_in_sync "$current" "$heads"; then
      ALEMBIC_CHANGES_REQUIRED=1
      warn "Alembic migrations required for ${db} (current=${current:-none}, heads=${heads:-none})"
    else
      ok "Alembic revisions already applied for ${db}"
    fi
  done
}

run_alembic_for_db() {
  local db="$1"
  local mode="$2"
  local db_safe
  db_safe=$(sanitize_for_filename "$db")

  local -a script_lines=(
    "set -euo pipefail"
    "cd /app/src/backend/base"
    "echo '--- Alembic current (${db}) ---'"
    "alembic current"
    "echo '--- Alembic heads (${db}) ---'"
    "alembic heads"
  )

  if [[ "$mode" == "dry" ]]; then
    local dry_file="/tmp/alembic-dry-${db_safe}.sql"
    script_lines+=(
      "echo '--- Alembic dry-run (${db}) ---'"
      "alembic upgrade head --sql > ${dry_file}"
    )
  else
    script_lines+=(
      "echo '--- Alembic upgrade (${db}) ---'"
      "alembic upgrade head"
    )
  fi

  local script=""
  printf -v script '%s\n' "${script_lines[@]}"

  local run_args=( docker run --rm --network langflow-net )

  if [[ -n "${CONTAINER_ENV_FILE}" ]]; then
    run_args+=( --env-file "${CONTAINER_ENV_FILE}" )
  fi

  run_args+=(
    -e LANGFLOW_DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${db}"
    -e LANGFLOW_CONFIG_DIR="/app/langflow"
    -e LANGFLOW_SAVE_DB_IN_CONFIG_DIR="false"
    -v /app/ebsstorage/langflowstorage:/app/langflow
    "${DOCKER_IMAGE}"
    bash -lc "$script"
  )

  "${run_args[@]}"
}

run_alembic_dry_run() {
  local db
  for db in "${POSTGRES_DATABASES[@]}"; do
    [[ -z "$db" ]] && continue
    step "Alembic dry run for database ${db}"
    if ! run_alembic_for_db "$db" dry; then
      FAILURE_REASON="Alembic dry run failed for ${db}"
      err "Alembic dry run failed for ${db}. Aborting deployment."
      warn "Restarting previous container due to Alembic dry run failure"
      exit 1
    fi
    ok "Dry run successful for ${db}"
  done
}

restore_postgres_backup() {
  local file="$1"
  [[ -f "$file" ]] || { warn "Backup file not found: $file"; return 1; }
  step "Restoring PostgreSQL backup from ${file}"
  gunzip -c "$file" | docker exec -i -e PGPASSWORD="${DB_PASSWORD}" postgres psql -U "${DB_USER}"
  ok "PostgreSQL restore complete"
}

run_alembic_migrations() {
  local db
  for db in "${POSTGRES_DATABASES[@]}"; do
    [[ -z "$db" ]] && continue
    step "Running Alembic migrations for database ${db}"
    if ! run_alembic_for_db "$db" apply; then
      FAILURE_REASON="Alembic migration failed for ${db}"
      err "Alembic migration failed for ${db}. Restoring from backup."
      if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
        restore_postgres_backup "$BACKUP_FILE" || warn "Failed to restore backup ${BACKUP_FILE}"
      else
        warn "No backup available to restore"
      fi
      warn "Deployment failed but previous container will be restored"
      exit 1
    fi
    ok "Migrations applied for ${db}"
  done
  ALEMBIC_MIGRATIONS_APPLIED=1
  RESTORE_POSTGRES_ON_ROLLBACK=1
}

prepare_langflow_env() {
  [[ -n "$DB_USER" && -n "$DB_PASSWORD" && -n "$DB_NAME" ]] || {
    err "--db-user, --db-password and --db-name are required"; exit 1;
  }
  [[ -f "$CONTAINER_ENV_FILE" ]] || { err "Env file not found: $CONTAINER_ENV_FILE"; exit 1; }

  local PG_IMAGE="postgres@sha256:d0f363f8366fbc3f52d172c6e76bc27151c3d643b870e1062b4e8bfe65baf609"

  if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
    step "Pulling required PostgreSQL image: $PG_IMAGE"
    docker pull "$PG_IMAGE"
    ok "PostgreSQL image pulled"
  else
    ok "PostgreSQL image already present"
  fi

  tail -c1 "$CONTAINER_ENV_FILE" | read -r _ || echo >> "$CONTAINER_ENV_FILE"

  if grep -q '^LANGFLOW_DATABASE_URL=' "$CONTAINER_ENV_FILE"; then
    sed -i "s|^LANGFLOW_DATABASE_URL=.*|LANGFLOW_DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@postgres:5432/$DB_NAME|" "$CONTAINER_ENV_FILE"
  else
    echo "LANGFLOW_DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@postgres:5432/$DB_NAME" >> "$CONTAINER_ENV_FILE"
  fi

  if ! grep -q '^POSTGRES_IMAGE=' "$CONTAINER_ENV_FILE"; then
    echo "POSTGRES_IMAGE=$PG_IMAGE" >> "$CONTAINER_ENV_FILE"
  fi

  if grep -q '^LANGFLOW_CONFIG_DIR=' "$CONTAINER_ENV_FILE"; then
    sed -i "s|^LANGFLOW_CONFIG_DIR=.*|LANGFLOW_CONFIG_DIR=/app/langflow|" "$CONTAINER_ENV_FILE"
  else
    echo "LANGFLOW_CONFIG_DIR=/app/langflow" >> "$CONTAINER_ENV_FILE"
  fi

  if grep -q '^LANGFLOW_SAVE_DB_IN_CONFIG_DIR=' "$CONTAINER_ENV_FILE"; then
    sed -i "s|^LANGFLOW_SAVE_DB_IN_CONFIG_DIR=.*|LANGFLOW_SAVE_DB_IN_CONFIG_DIR=false|" "$CONTAINER_ENV_FILE"
  else
    echo "LANGFLOW_SAVE_DB_IN_CONFIG_DIR=false" >> "$CONTAINER_ENV_FILE"
  fi
}

# ---------- Docker cleanup (keep last 2 images only) ----------
cleanup_old_images() {
  step "Cleaning up old Docker images (keeping last 2)"
  local PG_IMAGE
  if [[ -f "$CONTAINER_ENV_FILE" ]]; then
    PG_IMAGE=$(grep '^POSTGRES_IMAGE=' "$CONTAINER_ENV_FILE" | cut -d'=' -f2- || true)
    if [[ -n "$PG_IMAGE" ]]; then
      ok "POSTGRES_IMAGE is present in env file"
    else
      ok "No POSTGRES_IMAGE found in env file"
    fi
  fi

  local images
  images=$(docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}' \
    | sort -k3 -r \
    | awk 'NR>2 {print $2}')

  if [[ -n "$images" ]]; then
    for img in $images; do
      if [[ -n "$PG_IMAGE" ]] && docker image inspect "$img" >/dev/null 2>&1; then
        if docker image inspect --format='{{index .RepoDigests 0}}' "$img" 2>/dev/null | grep -q "$PG_IMAGE"; then
          ok "Skipping Postgres image to delete"
          continue
        fi
      fi
      # Try to remove other images
      docker rmi -f "$img" >/dev/null 2>&1 || true
    done
    ok "Old images removed (pinned Postgres preserved)"
  else
    ok "No old images to remove"
  fi
}

# ---------- Ensure EBS Volume is Mounted ----------
ensure_ebs_volume() {
    step "Ensuring EBS volume is mounted and configured"

    # 1️ Detect environment and pick correct volume
    if [[ "$DOMAIN" == *"staging."* ]]; then
        ENVIRONMENT="staging"
    else
        ENVIRONMENT="prod"
    fi
    ok "Detected environment: ${ENVIRONMENT}"

    # 2 Define paths
    local SYSTEM_MOUNT_POINT="/mnt/${VOLUME_NAME}"
    local APP_MOUNT_POINT="/app/ebsstorage"
    local VOLUME_DEVICE="/dev/disk/by-id/scsi-0DO_Volume_${VOLUME_NAME}"
    local LANGFLOW_STORAGE_PATH="${APP_MOUNT_POINT}/langflowstorage"
    local POSTGRES_STORAGE_PATH="${APP_MOUNT_POINT}/postgres"
    local POSTGRES_BACKUP_PATH="${APP_MOUNT_POINT}/postgres_backups"

    # 3 Ensure system-level mount exists
    if mountpoint -q "${SYSTEM_MOUNT_POINT}"; then
        ok "Volume already mounted at ${SYSTEM_MOUNT_POINT}"
    else
        warn "Volume not mounted. Attempting to mount..."
        mkdir -p "${SYSTEM_MOUNT_POINT}"
        mount -o discard,defaults,noatime "${VOLUME_DEVICE}" "${SYSTEM_MOUNT_POINT}"
        ok "Mounted ${VOLUME_DEVICE} → ${SYSTEM_MOUNT_POINT}"

        # Ensure persistence after reboot
        if ! grep -qs "${VOLUME_DEVICE}" /etc/fstab; then
            echo "${VOLUME_DEVICE} ${SYSTEM_MOUNT_POINT} ext4 defaults,nofail,discard 0 0" >> /etc/fstab
            ok "Added fstab entry for persistence"
        else
            ok "fstab entry already exists"
        fi
    fi

    # 4️ Bind system mount to /app/ebsstorage
    if mountpoint -q "${APP_MOUNT_POINT}"; then
        ok "/app/ebsstorage already points to ${SYSTEM_MOUNT_POINT}"
    else
        mkdir -p "${APP_MOUNT_POINT}"
        mount --bind "${SYSTEM_MOUNT_POINT}" "${APP_MOUNT_POINT}" || {
            warn "Bind mount failed; creating symlink instead"
            ln -sfn "${SYSTEM_MOUNT_POINT}" "${APP_MOUNT_POINT}"
        }
        ok "Linked ${SYSTEM_MOUNT_POINT} → ${APP_MOUNT_POINT}"
    fi

    # 5️ Verify subdirectories
    for dir in "${LANGFLOW_STORAGE_PATH}" "${POSTGRES_STORAGE_PATH}" "${POSTGRES_BACKUP_PATH}"; do
        if [ -d "$dir" ]; then
            ok "Storage directory already exists: $dir"
        else
            mkdir -p "$dir"
            ok "Created storage directory: $dir"
        fi
    done

    # 6️ Detect container UID/GID if exists
    local CONTAINER_UID=1000
    local CONTAINER_GID=1000

    # 7️ Apply correct permissions
    chown -R "${CONTAINER_UID}:${CONTAINER_GID}" "${LANGFLOW_STORAGE_PATH}"
    chown -R 999:999 "${POSTGRES_STORAGE_PATH}" # Postgres often runs as UID 999
    chown -R 999:999 "${POSTGRES_BACKUP_PATH}" || true
    ok "Permissions set for Docker (Langflow UID:${CONTAINER_UID}, Postgres UID:999)"

    ok "✅ EBS volume ready and linked: ${SYSTEM_MOUNT_POINT} → ${APP_MOUNT_POINT}"
}


# Paths used by Nginx toggling
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
APP_CONF="${APP_NAME}.conf"
MAINT_CONF="${APP_NAME}-maintenance.conf"
DEFAULT_LINK="${NGINX_SITES_ENABLED}/${APP_CONF}"
NGINX_SITE="${NGINX_SITES_AVAILABLE}/${APP_CONF}"
NGINX_SITE_LINK="${DEFAULT_LINK}"
SNIPPETS_DIR="/etc/nginx/snippets"
UP_BLUE="${SNIPPETS_DIR}/${APP_NAME}-upstream-blue.conf"
UP_GREEN="${SNIPPETS_DIR}/${APP_NAME}-upstream-green.conf"
UP_ACTIVE="${SNIPPETS_DIR}/${APP_NAME}-upstream-active.conf"
PROXY_SNIPPET="${SNIPPETS_DIR}/${APP_NAME}-proxy.conf"
CERT_ROOT="/var/www/certbot"
MAINTENANCE_SITE="${NGINX_SITES_AVAILABLE}/${MAINT_CONF}"
MAINTENANCE_ROOT="/var/www/${APP_NAME}-maintenance"

ACTIVE_FILE="/var/run/${APP_NAME}-active-color" # stores "blue" or "green"

reload_nginx_safely() {
  log "Reloading Nginx"
  if ! nginx -t >/dev/null 2>&1; then
    err "Nginx config test failed"
    return 1
  fi
  if ! systemctl reload nginx >/dev/null 2>&1; then
    nginx -s reload >/dev/null 2>&1 || { err "Failed to reload Nginx"; return 1; }
  fi
  sleep 2
  ok "Nginx reload complete"
}

enable_maintenance_page() {
  if [[ "${MAINTENANCE_ENABLED}" -eq 1 ]]; then
    ok "Maintenance page already enabled"
    return 0
  fi

  step "Enabling maintenance page"
  mkdir -p "${MAINTENANCE_ROOT}"

  local maintenance_source="${SCRIPT_DIR}/maintenance-page.html"
  if [[ ! -f "${maintenance_source}" ]]; then
    err "Maintenance page source not found: ${maintenance_source}"
    exit 1
  fi

  install -m 644 "${maintenance_source}" "${MAINTENANCE_ROOT}/index.html"

  local have_cert=0
  [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] && have_cert=1

  cat > "${MAINTENANCE_SITE}" <<EOF
server {
  listen 80;
  server_name ${DOMAIN} www.${DOMAIN};
  root ${MAINTENANCE_ROOT};
  location ^~ /.well-known/acme-challenge/ { root ${CERT_ROOT}; }
  location / { try_files \$uri /index.html; }
}
EOF

  if [[ "${have_cert}" -eq 1 ]]; then
    cat >> "${MAINTENANCE_SITE}" <<EOF
server {
  listen 443 ssl; http2 on;
  server_name ${DOMAIN} www.${DOMAIN};
  ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
  root ${MAINTENANCE_ROOT};
  location / { try_files \$uri /index.html; }
}
EOF
  fi

  ln -sf "${MAINTENANCE_SITE}" "${DEFAULT_LINK}"
  reload_nginx_safely || { err "Failed to reload Nginx during maintenance enable"; return 1; }
  if curl -sf --max-time 5 http://127.0.0.1 | grep -qi "maintenance"; then
    ok "Maintenance page active"
  else
    warn "Maintenance page not detected — check Nginx config"
  fi
  MAINTENANCE_ENABLED=1
}

disable_maintenance_page() {
  if [[ "${MAINTENANCE_ENABLED}" -ne 1 ]]; then
    return 0
  fi

  step "Disabling maintenance page"
  ln -sf "${NGINX_SITE}" "${DEFAULT_LINK}"
  reload_nginx_safely || { err "Failed to reload Nginx during maintenance disable"; return 1; }
  local retries=5
  while (( retries-- > 0 )); do
    if curl -sf --max-time 5 "http://127.0.0.1${HEALTH_PATH}" | grep -qi "ok"; then
      ok "App health OK, maintenance disabled"
      MAINTENANCE_ENABLED=0
      return 0
    fi
    warn "Waiting for app to respond..."
    sleep 3
  done
  warn "App not responding post-maintenance; check container logs"
  return 1
}

# ---------- Install system deps (idempotent) ----------
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
install_if_missing nginx
install_if_missing certbot
install_if_missing python3-certbot-nginx
install_if_missing docker.io

step "Enabling & starting Docker and Nginx"
systemctl enable docker >/dev/null 2>&1 || true
systemctl start docker || true
systemctl enable nginx >/dev/null 2>&1 || true
service_active nginx || systemctl start nginx
ok "Services ensured"

# ---------- Docker login (optional) ----------
if [[ -n "${DOCKERHUB_USERNAME}" && -n "${DOCKERHUB_TOKEN}" ]]; then
  step "Docker Hub login"
  echo "${DOCKERHUB_TOKEN}" | docker login --username "${DOCKERHUB_USERNAME}" --password-stdin
  ok "Logged in to Docker Hub"
else
  step "Skipping Docker Hub login"
fi

# Quick sanity check that the daemon is reachable
docker info >/dev/null 2>&1 || { err "Docker daemon not reachable"; exit 1; }
ok "Docker daemon reachable"

# ---------- Pull image (with retries) ----------
cleanup_old_images
step "Pulling Docker image: ${DOCKER_IMAGE}"
retry "${RETRY_MAX}" "${RETRY_SLEEP}" docker pull "${DOCKER_IMAGE}"
ok "Image pulled"

# ---------- Determine colors & names ----------
get_symlink_color() {
  if [[ -L "${UP_ACTIVE}" ]]; then
    readlink -f "${UP_ACTIVE}" | grep -q "blue" && echo "blue" && return
    readlink -f "${UP_ACTIVE}" | grep -q "green" && echo "green" && return
  fi
  echo ""
}

ACTIVE_COLOR=""
[[ -f "${ACTIVE_FILE}" ]] && ACTIVE_COLOR="$(cat "${ACTIVE_FILE}" || true)"
[[ -z "${ACTIVE_COLOR}" ]] && ACTIVE_COLOR="$(get_symlink_color)"
[[ -z "${ACTIVE_COLOR}" ]] && ACTIVE_COLOR="green"   # default first active

if [[ "${ACTIVE_COLOR}" == "blue" ]]; then
  TARGET_COLOR="green"; TARGET_PORT="${GREEN_PORT}"
else
  TARGET_COLOR="blue";  TARGET_PORT="${BLUE_PORT}"
fi

ACTIVE_NAME="${APP_NAME}_${ACTIVE_COLOR}"
TARGET_NAME="${APP_NAME}_${TARGET_COLOR}"

if [[ "${ACTIVE_COLOR}" == "blue" ]]; then
  ACTIVE_PORT="${BLUE_PORT}"
else
  ACTIVE_PORT="${GREEN_PORT}"
fi

docker_exists "${ACTIVE_NAME}" && HAD_ACTIVE=1 || HAD_ACTIVE=0

ok "Active color: ${ACTIVE_COLOR:-none} (container: ${ACTIVE_NAME}); Target: ${TARGET_COLOR} on port ${TARGET_PORT}"

record_active_image_info

# ---------- SSL helpers & Nginx ----------
ensure_ssl_support_files() {
  if [[ ! -f "/etc/letsencrypt/options-ssl-nginx.conf" ]]; then
    step "Downloading options-ssl-nginx.conf"
    curl -fsSL https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
      -o /etc/letsencrypt/options-ssl-nginx.conf
    ok "Downloaded options-ssl-nginx.conf"
  fi
  if [[ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]]; then
    step "Downloading ssl-dhparams.pem"
    curl -fsSL https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem \
      -o /etc/letsencrypt/ssl-dhparams.pem
    ok "Downloaded ssl-dhparams.pem"
  fi
}

ensure_snippets() {
  step "Ensuring Nginx upstream & proxy snippets"
  mkdir -p "${SNIPPETS_DIR}" "${CERT_ROOT}"

  cat > "${UP_BLUE}" <<EOF
upstream ${APP_NAME}_upstream {
    server 127.0.0.1:${BLUE_PORT};
    keepalive 32;
}
EOF
  cat > "${UP_GREEN}" <<EOF
upstream ${APP_NAME}_upstream {
    server 127.0.0.1:${GREEN_PORT};
    keepalive 32;
}
EOF
  cat > "${PROXY_SNIPPET}" <<'EOF'
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 300;
proxy_send_timeout 300;
EOF

  [[ ! -L "${UP_ACTIVE}" ]] && ln -sf "${UP_GREEN}" "${UP_ACTIVE}"
  ok "Snippets ready"
}

write_site_http_only() {
  cat > "${NGINX_SITE}" <<EOF
include ${UP_ACTIVE};
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    location ^~ /.well-known/acme-challenge/ { root ${CERT_ROOT}; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
}

write_site_https() {
  cat > "${NGINX_SITE}" <<EOF
include ${UP_ACTIVE};

server {
  listen 80;
  server_name ${DOMAIN} www.${DOMAIN};
  location ^~ /.well-known/acme-challenge/ { root ${CERT_ROOT}; }
  location / { return 301 https://\$host\$request_uri; }
}

server {
  listen 443 ssl; http2 on;
  server_name ${DOMAIN};
  ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  location / {
    proxy_pass http://${APP_NAME}_upstream;
    include ${PROXY_SNIPPET};
  }
}

server {
  listen 443 ssl; http2 on;
  server_name www.${DOMAIN};
  ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
  return 301 https://${DOMAIN}\$request_uri;
}
EOF
}

ensure_nginx() {
  ensure_snippets
  mkdir -p "$(dirname "${NGINX_SITE}")" /etc/nginx/sites-enabled
  local have_cert="0"
  [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]] && have_cert="1"

  step "Writing Nginx site config (certs present: ${have_cert})"
  if [[ "${have_cert}" == "1" ]]; then
    ensure_ssl_support_files
    write_site_https
  else
    write_site_http_only
  fi

  ln -sf "${NGINX_SITE}" "${NGINX_SITE_LINK}"
  rm -f /etc/nginx/sites-enabled/default || true

  step "Testing Nginx config"
  nginx -t
  if service_active nginx; then systemctl reload nginx; else systemctl start nginx; fi
  ok "Nginx config applied"
}

# ---------- Certbot timer (robust) ----------
ensure_certbot_timer() {
  step "Ensuring Certbot auto-renewal timer"

  _any_timer_active() {
    systemctl is-active --quiet certbot.timer && return 0
    systemctl is-active --quiet snap.certbot.renew.timer && return 0
    systemctl is-active --quiet certbot-renew.timer && return 0
    return 1
  }

  # Already active?
  if _any_timer_active; then
    ok "Certbot auto-renewal timer already active"
    return 0
  fi

  # Ensure /usr/bin/certbot exists (snap installs to /snap/bin/certbot)
  if [[ ! -x /usr/bin/certbot && -x /snap/bin/certbot ]]; then
    ln -sf /snap/bin/certbot /usr/bin/certbot
  fi

  # Try enabling known timers
  if systemctl list-unit-files --no-pager | grep -q '^certbot.timer'; then
    systemctl enable --now certbot.timer
  elif systemctl list-unit-files --no-pager | grep -q '^snap.certbot.renew.timer'; then
    systemctl enable --now snap.certbot.renew.timer
  else
    # Fallback: create our own twice-daily timer
    warn "No built-in Certbot timer found; creating certbot-renew.timer"
    cat >/etc/systemd/system/certbot-renew.service <<'EOF'
[Unit]
Description=Certbot Renew

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot -q renew
EOF

    cat >/etc/systemd/system/certbot-renew.timer <<'EOF'
[Unit]
Description=Run certbot renew twice daily

[Timer]
OnCalendar=*-*-* 00,12:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now certbot-renew.timer
  fi

  # Final verification
  if _any_timer_active; then
    ok "Certbot auto-renewal timer active"
    return 0
  fi

  # Last resort: start again and recheck
  systemctl start certbot.timer 2>/dev/null || true
  systemctl start snap.certbot.renew.timer 2>/dev/null || true
  systemctl start certbot-renew.timer 2>/dev/null || true
  sleep 1

  if _any_timer_active; then
    ok "Certbot auto-renewal timer active"
  else
    err "Certbot auto-renewal timer NOT active"
    systemctl list-timers --no-pager --all | sed -n '1,200p' || true
    exit 1
  fi
}

issue_cert_if_needed() {
  if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
    ok "TLS certificate already exists"
    ensure_certbot_timer
    step "Verifying certbot timer"
    if systemctl is-active --quiet certbot.timer || \
       systemctl is-active --quiet snap.certbot.renew.timer || \
       systemctl is-active --quiet certbot-renew.timer; then
      ok "Certbot auto-renewal timer active"
    else
      err "Certbot auto-renewal timer NOT active"
      systemctl list-timers --no-pager --all | sed -n '1,200p' || true
      exit 1
    fi
    return
  fi

  step "Issuing Let's Encrypt certificate (webroot)"
  ensure_nginx
  certbot certonly --webroot -w "${CERT_ROOT}" -d "${DOMAIN}" -d "www.${DOMAIN}" \
    --email "${EMAIL}" --agree-tos --non-interactive
  ok "Certificate issued"
  ensure_ssl_support_files
  ensure_nginx

  ensure_certbot_timer
  step "Verifying certbot timer"
  if systemctl is-active --quiet certbot.timer || \
     systemctl is-active --quiet snap.certbot.renew.timer || \
     systemctl is-active --quiet certbot-renew.timer; then
    ok "Certbot auto-renewal timer active"
  else
    err "Certbot auto-renewal timer NOT active"
    systemctl list-timers --no-pager --all | sed -n '1,200p' || true
    exit 1
  fi
}

# ---------- Traffic switching (only after health passes) ----------
switch_traffic() {
  step "Switching Nginx upstream to ${TARGET_COLOR} (port ${TARGET_PORT})"
  if [[ "${TARGET_COLOR}" == "blue" ]]; then
    ln -sf "${UP_BLUE}" "${UP_ACTIVE}"
  else
    ln -sf "${UP_GREEN}" "${UP_ACTIVE}"
  fi
  echo "${TARGET_COLOR}" > "${ACTIVE_FILE}"
  nginx -t
  systemctl reload nginx
  ok "Switched traffic to ${TARGET_COLOR}"
  SWITCHED=1
}

verify_domain() {
  step "Verifying domain is serving over HTTPS: https://${DOMAIN}"
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if http_ok "https://${DOMAIN}"; then
      ok "Domain reachable over HTTPS"
      return 0
    fi
    sleep 2
  done
  err "Domain did not become healthy over HTTPS"
  return 1
}

rollback_switch() {
  step "Rolling back Nginx to ${ACTIVE_COLOR}"
  if [[ "${ACTIVE_COLOR}" == "blue" ]]; then
    ln -sf "${UP_BLUE}" "${UP_ACTIVE}"
  else
    ln -sf "${UP_GREEN}" "${UP_ACTIVE}"
  fi
  nginx -t
  systemctl reload nginx
  ok "Rollback complete"
}

cleanup_old_container() {
  if [[ "${KEEP_OLD}" == "0" && "${HAD_ACTIVE}" -eq 1 ]]; then
    local old="${ACTIVE_NAME}"
    step "Pruning old container ${old}"
    docker_safe_rm "${old}"
    ok "Old container removed"
  else
    ok "Keeping old container for quick rollback"
  fi
}

# ---------- Ensure PostgreSQL and network ----------
ensure_postgres() {
  step "Ensuring PostgreSQL container"

  # Ensure network exists
  docker network inspect langflow-net >/dev/null 2>&1 || docker network create langflow-net

  # Load image from env if missing
  if [[ -z "${POSTGRES_IMAGE:-}" ]]; then
    POSTGRES_IMAGE=$(grep '^POSTGRES_IMAGE=' "$CONTAINER_ENV_FILE" | cut -d= -f2-)
  fi

  # Case 1: Container exists
  if docker_exists "postgres"; then
    if docker_running "postgres"; then
      # Container is running — verify mount
      local current_mount
      current_mount=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}' postgres 2>/dev/null || true)

      if [[ "${current_mount}" == "/app/ebsstorage/postgres" ]]; then
        ok "PostgreSQL container already running with correct bind mount"
        return 0
      else
        warn "Incorrect mount (${current_mount:-none}) detected — recreating container"
      fi
    else
      # Container exists but not running — clean up before recreating
      warn "PostgreSQL container exists but is stopped — removing stale container"
    fi

    # Stop & remove container safely
    docker stop postgres >/dev/null 2>&1 || true
    docker rm -f postgres >/dev/null 2>&1 || true

    # Remove lingering named volume
    if docker volume inspect langflow-postgres >/dev/null 2>&1; then
      step "Removing old named volume 'langflow-postgres'"
      docker volume rm -f langflow-postgres >/dev/null 2>&1 || true
    fi
  fi

  # Case 2: Start a fresh container
  step "Starting PostgreSQL container with correct bind mount"
  docker run -d \
    --name postgres \
    --network langflow-net \
    -e POSTGRES_USER="${DB_USER}" \
    -e POSTGRES_PASSWORD="${DB_PASSWORD}" \
    -e POSTGRES_DB="${DB_NAME}" \
    -v /app/ebsstorage/postgres:/var/lib/postgresql/data \
    --restart unless-stopped \
    "${POSTGRES_IMAGE}"

  ok "PostgreSQL container started with correct bind mount"
}

# ---------- Start/stop containers (STOP-FIRST) ----------
stop_active_container() {
  if [[ "${HAD_ACTIVE}" -eq 1 ]]; then
    if docker_running "${ACTIVE_NAME}"; then
      step "Stopping active container ${ACTIVE_NAME}"
      disable_restart_policy "${ACTIVE_NAME}"
      docker stop "${ACTIVE_NAME}" >/dev/null
      STOPPED_ACTIVE=1
      ok "Stopped ${ACTIVE_NAME}"
    else
      warn "Active container ${ACTIVE_NAME} not running"
    fi
  else
    ok "No previously active container found (first deploy?)"
  fi
}

start_target_container() {
  step "Launching target ${TARGET_COLOR} container: ${TARGET_NAME} on host port ${TARGET_PORT}"
  docker_safe_rm "${TARGET_NAME}"

  local run_cmd=( docker run -d
    --restart unless-stopped
    --name "${TARGET_NAME}"
    -l "app=${APP_NAME}"
    -l "color=${TARGET_COLOR}"
    -p "${TARGET_PORT}:${CONTAINER_PORT}"
    --network langflow-net
    -v /app/ebsstorage/langflowstorage:/app/langflow
  )

  if [[ -n "${CONTAINER_ENV_FILE}" ]]; then
    [[ -f "${CONTAINER_ENV_FILE}" ]] || { err "Container env file not found: ${CONTAINER_ENV_FILE}"; exit 1; }
    run_cmd+=( --env-file "${CONTAINER_ENV_FILE}" )
  fi

  run_cmd+=( "${DOCKER_IMAGE}" )
  "${run_cmd[@]}"
  ok "Container started"
}

wait_for_container_health() {
  local container="$1"
  local port="$2"
  local label="${3:-container}"

  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  local has_healthcheck="0"
  local last_log=0
  local status="starting"

  log "Health-checking ${label} (${container})"

  if docker inspect --format '{{if .Config.Healthcheck}}yes{{else}}no{{end}}' "${container}" 2>/dev/null | grep -q yes; then
    has_healthcheck="1"
    ok "Docker HEALTHCHECK detected for ${container}; waiting for 'healthy'"
  else
    warn "No Docker HEALTHCHECK on ${container}; will use HTTP ${HEALTH_PATH}"
  fi

  while (( SECONDS < deadline )); do
    if [[ "${has_healthcheck}" == "1" ]]; then
      status=$(docker inspect --format '{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "starting")
      [[ "${status}" == "healthy" ]] && { ok "${container} reported healthy"; return 0; }
      [[ "${status}" == "unhealthy" ]] && { err "${container} reported UNHEALTHY"; return 1; }
    fi

    if [[ -n "${port}" ]] && http_ok "http://127.0.0.1:${port}${HEALTH_PATH}"; then
      ok "HTTP health OK for ${container}"; return 0
    fi

    if (( SECONDS - last_log >= 10 )); then
      log "Waiting for ${container} health... retrying in 2s (elapsed: $((SECONDS - (deadline - HEALTH_TIMEOUT)))s)"
      last_log=$SECONDS
    fi
    sleep 2
  done

  err "Health check timed out for ${container} after ${HEALTH_TIMEOUT}s"
  return 1
}

wait_until_healthy() {
  step "Health-checking ${TARGET_NAME}"
  wait_for_container_health "${TARGET_NAME}" "${TARGET_PORT}" "target container"
  enable_restart_policy "${TARGET_NAME}"
}

# ---------- Cleanup on failure / interrupt ----------
cleanup_on_failure() {
  [[ "${CLEANED_UP}" -eq 1 ]] && return 0
  CLEANED_UP=1
  warn "Running failure cleanup"

  # If we switched traffic already, roll back Nginx to previous color
  if [[ "${SWITCHED}" -eq 1 ]]; then
    rollback_switch || true
  fi

  # Kill the target container if it exists (failed health/verify or interrupt)
  if docker_exists "${TARGET_NAME}"; then
    warn "Removing target container ${TARGET_NAME}"
    docker rm -f "${TARGET_NAME}" >/dev/null 2>&1 || true
  fi

  # If we had stopped the active one but haven't switched yet, bring it back up
  local restarted_previous=0
  local previous_healthy=0
  if [[ "${STOPPED_ACTIVE}" -eq 1 && "${HAD_ACTIVE}" -eq 1 ]]; then
    enable_restart_policy "${ACTIVE_NAME}"
    if docker_running "${ACTIVE_NAME}"; then
      ok "Previous container ${ACTIVE_NAME} already running — skipping restart"
      restarted_previous=1
    else
      warn "Restarting previous active container ${ACTIVE_NAME}"
      if [[ "${RESTORE_POSTGRES_ON_ROLLBACK}" -eq 1 ]]; then
        if [[ -n "${BACKUP_FILE}" && -f "${BACKUP_FILE}" ]]; then
          warn "Restoring PostgreSQL backup captured before migrations"
          if ! restore_postgres_backup "${BACKUP_FILE}"; then
            warn "PostgreSQL restore failed; proceeding to restart container with migrated schema"
          else
            ok "PostgreSQL state restored prior to restarting ${ACTIVE_NAME}"
            RESTORE_POSTGRES_ON_ROLLBACK=0
          fi
        else
          warn "No backup file available to restore before restarting ${ACTIVE_NAME}"
        fi
      fi

      if retry "${RETRY_MAX}" "${RETRY_SLEEP}" docker start "${ACTIVE_NAME}"; then
        ok "Restarted ${ACTIVE_NAME}"
        restarted_previous=1
      else
        err "Failed to restart ${ACTIVE_NAME} after deployment failure"
        [[ -z "${FAILURE_REASON}" ]] && FAILURE_REASON="Failed to restart previous container ${ACTIVE_NAME}"
      fi
    fi
  fi

  if [[ "${restarted_previous}" -eq 1 ]]; then
    if wait_for_container_health "${ACTIVE_NAME}" "${ACTIVE_PORT}" "previous container"; then
      previous_healthy=1
    else
      warn "Previous container did not become healthy within timeout"
    fi
  fi

  if [[ "${MAINTENANCE_ENABLED}" -eq 1 ]]; then
    if [[ "${restarted_previous}" -eq 1 && "${previous_healthy}" -eq 1 ]]; then
      disable_maintenance_page || true
    else
      warn "Keeping maintenance page enabled until a container is healthy"
    fi
  fi

  if [[ "${HAD_ACTIVE}" -eq 1 && "${restarted_previous}" -eq 0 ]]; then
    err "Previous container ${ACTIVE_NAME} is not running; investigate before re-enabling traffic"
  else
    ok "Failure cleanup completed"
  fi
}

# ---------- Final reporting ----------
report_status() {
  local status desc running
  running=$(docker ps --filter "name=${APP_NAME}_" --format "{{.Names}} {{.Image}}" | head -n1 || true)

  collect_storage_metrics "Storage usage snapshot (final)" --quiet || true

  if [[ "$DEPLOY_SUCCESS" -eq 1 ]]; then
    status="success"
    desc="Deployment succeeded"
  elif [[ -n "$FAILURE_REASON" ]]; then
    status="failure"
    desc="Deployment failed: $FAILURE_REASON"
  elif [[ "$STOPPED_ACTIVE" -eq 1 && "$HAD_ACTIVE" -eq 1 ]]; then
    status="failure"
    desc="Deployment failed, rolled back"
  elif [[ -n "$running" ]]; then
    status="failure"
    desc="Deployment failed. Older container live"
  else
    status="failure"
    desc="Deployment failed. No container running"
  fi

  local storage_json_escaped
  storage_json_escaped=$(printf '%s' "${STORAGE_METRICS_JSON}" | sed 's/\\/\\\\/g; s/"/\\"/g')

  {
    echo "FINAL_STATUS=\"$status\""
    echo "FINAL_DESCRIPTION=\"${desc:0:140}\""
    echo "FINAL_CONTAINER=\"$running\""
    echo "EBSSTORAGE_SIZE=\"${EBSSTORAGE_SIZE}\""
    echo "EBSTORAGE_SIZE=\"${EBSTORAGE_SIZE}\""
    echo "BACKUP_DIR_SIZE=\"${BACKUP_DIR_SIZE}\""
    echo "LATEST_BACKUP_FILE=\"${LATEST_BACKUP_FILE}\""
    echo "LATEST_BACKUP_SIZE=\"${LATEST_BACKUP_SIZE}\""
    echo "STORAGE_METRICS_JSON=\"${storage_json_escaped}\""
    echo "ALEMBIC_CHANGES_REQUIRED=\"${ALEMBIC_CHANGES_REQUIRED}\""
  } > /root/deploy_status.env
}

# ---------- Execute flow (STOP-FIRST) ----------
ensure_nginx
issue_cert_if_needed
ensure_ebs_volume

# Prepare but DO NOT switch Nginx yet. We will switch only after new target is healthy.
# 1) Stop active (frees CPU/RAM/port)
stop_active_container
enable_maintenance_page
prepare_langflow_env
ensure_postgres
collect_storage_metrics "Storage usage snapshot (pre-deploy)"
collect_postgres_databases
check_alembic_changes
if [[ "${ALEMBIC_CHANGES_REQUIRED}" -eq 1 ]]; then
  backup_postgres_server
  run_alembic_dry_run
  run_alembic_migrations
else
  ok "Alembic revisions unchanged; skipping PostgreSQL backup and migrations"
fi

# 2) Start target and health-check while site is temporarily down
start_target_container
wait_until_healthy
disable_maintenance_page

# 3) Switch traffic and finalize
switch_traffic
verify_domain

# 4) Success → optionally prune old container
ok "Deployment successful: ${TARGET_COLOR} is live"
cleanup_old_container
DEPLOY_SUCCESS=1