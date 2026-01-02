import argparse
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

REVISION_PATTERN = re.compile(r"([0-9a-f]{12,40})", re.IGNORECASE)

# Exception messages (required for TRY003 / EM101)
ERR_ALEMBIC_NOT_FOUND = "alembic binary not found in PATH"
ERR_PSQL_NOT_FOUND = "psql binary not found in PATH"
ERR_DOCKER_NOT_FOUND = "docker binary not found in PATH"

# Resolve executables explicitly
ALEMBIC_BIN = shutil.which("alembic")
PSQL_BIN = shutil.which("psql")
DOCKER_BIN = shutil.which("docker")

def parse_revision(output: str) -> str:
    for line in reversed(output.splitlines()):
        match = REVISION_PATTERN.search(line)
        if match:
            return match.group(1)
    return ""


def get_revision_from_alembic(workdir: Path, alembic_ini: str) -> str:
    if not ALEMBIC_BIN:
        raise RuntimeError(ERR_ALEMBIC_NOT_FOUND)
    result = subprocess.run(  # noqa: S603 - inputs are trusted CI configuration
        [ALEMBIC_BIN, "-c", alembic_ini, "heads"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        logger.error("alembic heads failed: %s", result.stderr.strip())
        raise SystemExit(1)

    revision = parse_revision(result.stdout)
    if not revision:
        logger.error("No alembic head revision found")
        raise SystemExit(1)

    return revision


def build_database_url(
    database_url: str | None,
    db_user: str | None,
    db_password: str | None,
    db_name: str | None,
    db_host: str,
    db_port: str,
) -> str:
    if database_url:
        return database_url

    required = {
        "db_user": db_user,
        "db_password": db_password,
        "db_name": db_name,
    }
    missing = [key for key, value in required.items() if not value]

    if missing:
        logger.error(
            "Missing required database parameters: %s",
            ", ".join(missing),
        )
        raise SystemExit(1)

    return (
        f"postgresql://{quote_plus(db_user)}:{quote_plus(db_password)}"
        f"@{db_host}:{db_port}/{quote_plus(db_name)}"
    )


def get_revision_from_database_url(database_url: str) -> str:
    if not PSQL_BIN:
        raise RuntimeError(ERR_PSQL_NOT_FOUND)
    result = subprocess.run(  # noqa: S603 - database_url comes from CI inputs
        [
            PSQL_BIN,
            database_url,
            "-A",
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        logger.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        logger.error("No alembic version found in database")
        raise SystemExit(1)

    return revision


def get_revision_from_vm_docker(
    db_user: str,
    db_name: str,
    container_name: str,
) -> str:
    if not DOCKER_BIN:
        raise RuntimeError(ERR_DOCKER_NOT_FOUND)
    if not PSQL_BIN:
        raise RuntimeError(ERR_PSQL_NOT_FOUND)
    result = subprocess.run(  # noqa: S603 - docker/psql args are trusted VM config
        [
            DOCKER_BIN,
            "exec",
            "-i",
            container_name,
            PSQL_BIN,
            "-U",
            db_user,
            "-d",
            db_name,
            "-t",
            "-A",
            "-c",
            "select version_num from alembic_version;",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        logger.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        logger.error("No alembic version found in VM DB")
        raise SystemExit(1)

    return revision


def write_github_output(revision: str, output_key: str) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a") as file:
        file.write(f"{output_key}={revision}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve Alembic revision from PostgreSQL."
    )
    parser.add_argument("--database-url")
    parser.add_argument("--db-user")
    parser.add_argument("--db-password")
    parser.add_argument("--db-name")
    parser.add_argument("--db-host", default="localhost")
    parser.add_argument("--db-port", default="5432")
    parser.add_argument("--vm-docker", action="store_true")
    parser.add_argument("--docker-container", default="postgres")
    parser.add_argument("--output-key", default="alembic_version")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.vm_docker:
        revision = get_revision_from_vm_docker(
            db_user=args.db_user,
            db_name=args.db_name,
            container_name=args.docker_container,
        )
    else:
        database_url = build_database_url(
            args.database_url,
            args.db_user,
            args.db_password,
            args.db_name,
            args.db_host,
            args.db_port,
        )
        revision = get_revision_from_database_url(database_url)

    write_github_output(revision, args.output_key)


if __name__ == "__main__":
    main()
