import logging
import os
import re
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO)

REVISION_PATTERN = re.compile(r"([0-9a-f]{12,40})", re.IGNORECASE)

def parse_revision(output: str) -> str:
    for line in reversed(output.splitlines()):
        match = REVISION_PATTERN.search(line)
        if match:
            return match.group(1)
    return ""

def get_revision_from_alembic() -> str:
    workdir = Path(os.getenv("ALEMBIC_WORKDIR", ".")).resolve()
    alembic_ini = os.getenv("ALEMBIC_INI", "alembic.ini")

    result = subprocess.run(
        ["alembic", "-c", alembic_ini, "heads"],
        cwd=workdir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logging.error("alembic heads failed: %s", result.stderr.strip())
        raise SystemExit(1)

    revision = parse_revision(result.stdout)
    if not revision:
        logging.error("No alembic head revision found")
        raise SystemExit(1)

    return revision

def get_revision_from_database_url(database_url: str) -> str:
    result = subprocess.run(
        [
            "psql",
            database_url,
            "-A",
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).lower()
        if os.getenv("ALEMBIC_FALLBACK_TO_HEADS") and "alembic_version" in combined:
            logging.warning("alembic_version missing, falling back to heads")
            return get_revision_from_alembic()

        logging.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        if os.getenv("ALEMBIC_FALLBACK_TO_HEADS"):
            return get_revision_from_alembic()
        raise SystemExit(1)

    return revision

def get_revision_from_docker() -> str:
    pg_user = os.getenv("PGUSER")
    pg_password = os.getenv("PGPASSWORD")
    db_name = os.getenv("DB_NAME")

    if not all([pg_user, pg_password, db_name]):
        logging.error("Missing PGUSER / PGPASSWORD / DB_NAME env vars")
        raise SystemExit(1)

    env = os.environ.copy()
    env["PGPASSWORD"] = pg_password

    container_result = subprocess.run(
        ["docker", "ps", "--filter", "name=postgres", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
    )

    containers = container_result.stdout.strip().splitlines()
    if not containers:
        logging.error("No postgres container found")
        raise SystemExit(1)

    container = containers[0]

    exec_result = subprocess.run(
        [
            "docker",
            "exec",
            "-e", "PGPASSWORD",
            "-i",
            container,
            "psql",
            "-U", pg_user,
            "-d", db_name,
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        env=env,
        capture_output=True,
        text=True,
    )

    if exec_result.returncode != 0:
        logging.error(exec_result.stderr.strip())
        raise SystemExit(1)

    return exec_result.stdout.strip()


def main():
    database_url = os.getenv("LOCAL_GITHUB_POSTGRES_DATABASE_URL") or os.getenv("DATABASE_URL")
    if database_url:
        revision = get_revision_from_database_url(database_url)
    else:
        revision = get_revision_from_docker()

    print(revision)

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        key = os.getenv("ALEMBIC_OUTPUT_KEY", "alembic_version")
        with Path(github_output).open("a") as f:
            f.write(f"{key}={revision}\n")


if __name__ == "__main__":
    main()
