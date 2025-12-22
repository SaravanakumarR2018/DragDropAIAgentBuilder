import logging
import re

import os
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO)

REVISION_PATTERN = re.compile(r"([0-9a-f]{12,})", re.IGNORECASE)

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
        check=False,
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

def get_revision_from_db_url(database_url: str) -> str:
    result = subprocess.run(
        [
            "psql",
            database_url,
            "-A",
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        combined = f"{stderr}\n{stdout}".lower()
        if os.getenv("ALEMBIC_FALLBACK_TO_HEADS") and "alembic_version" in combined and (
            "does not exist" in combined
            or "undefined table" in combined
            or "no such table" in combined
        ):
            logging.warning("alembic_version missing; falling back to alembic heads")
            return get_revision_from_alembic()

        logging.error("psql failed: %s", stderr or stdout)
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        if os.getenv("ALEMBIC_FALLBACK_TO_HEADS"):
            logging.warning("No alembic revision found in database; using alembic heads")
            return get_revision_from_alembic()

        logging.error("No alembic revision found in database")
        raise SystemExit(1)

    return revision

def get_revision_from_docker() -> str:
    """Get alembic version from Postgres container inside VM."""
    ps_result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            "name=postgres",
            "--format",
            "{{.Names}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    containers = ps_result.stdout.strip().splitlines()
    if not containers:
        return "NO CONTAINERS"
    
    container_name = containers[0]

    exec_result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container_name,
            "psql",
            "-U",
            "langflow",
            "-d",
            "langflow",
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    return exec_result.stdout.strip()


def main():
    database_url = os.getenv("LOCAL_GITHUB_POSTGRES_DATABASE_URL") or os.getenv("DATABASE_URL")
    if database_url:
        revision = get_revision_from_db_url(database_url)
        logging.info("Database Alembic Revision: %s", revision)
    else:
        revision = get_revision_from_docker()
        logging.info("VM Alembic Revision: %s", revision)

    print(revision)

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        output_key = os.getenv("ALEMBIC_OUTPUT_KEY", "alembic_version")
        output_path = Path(github_output)
        with output_path.open("a") as file:
            file.write(f"{output_key}={revision}\n")


if __name__ == "__main__":
    main()
