import argparse
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus

logging.basicConfig(level=logging.INFO)

REVISION_PATTERN = re.compile(r"([0-9a-f]{12,40})", re.IGNORECASE)


def parse_revision(output: str) -> str:
    for line in reversed(output.splitlines()):
        match = REVISION_PATTERN.search(line)
        if match:
            return match.group(1)
    return ""


def get_revision_from_alembic(workdir: Path, alembic_ini: str) -> str:
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


def build_database_url(
    database_url: Optional[str],
    db_user: Optional[str],
    db_password: Optional[str],
    db_name: Optional[str],
    db_host: str,
    db_port: str,
) -> str:
    if database_url:
        return database_url

    missing = [field for field, value in {"db_user": db_user, "db_password": db_password, "db_name": db_name}.items() if not value]
    if missing:
        logging.error("Missing required database parameters: %s", ", ".join(missing))
        raise SystemExit(1)

    return (
        f"postgresql://{quote_plus(db_user)}:{quote_plus(db_password)}"
        f"@{db_host}:{db_port}/{quote_plus(db_name)}"
    )


def get_revision_from_database_url(
    database_url: str,
) -> str:
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
        logging.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        raise SystemExit(1)

    return revision

def get_revision_from_vm_docker(
    db_user: str,
    db_name: str,
    container_name: str,
) -> str:
    result = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container_name,
            "psql",
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
    )

    if result.returncode != 0:
        logging.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        logging.error("No alembic version found in VM DB")
        raise SystemExit(1)

    return revision

def write_github_output(revision: str, output_key: str) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return

    with Path(github_output).open("a") as f:
        f.write(f"{output_key}={revision}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retrieve Alembic revision from PostgreSQL.")
    parser.add_argument("--database-url", dest="database_url", help="Full PostgreSQL database URL.")
    parser.add_argument("--db-user", dest="db_user", help="Database username.")
    parser.add_argument("--db-password", dest="db_password", help="Database password.")
    parser.add_argument("--db-name", dest="db_name", help="Database name.")
    parser.add_argument("--db-host", dest="db_host", default="localhost", help="Database host (default: localhost).")
    parser.add_argument("--db-port", dest="db_port", default="5432", help="Database port (default: 5432).")
    # VM Docker mode
    parser.add_argument(
        "--vm-docker",
        action="store_true",
        help="Read alembic version from postgres docker container (VM)",
    )
    parser.add_argument(
        "--docker-container",
        default="postgres",
        help="Postgres docker container name",
    )
    parser.add_argument(
        "--output-key",
        dest="output_key",
        default="alembic_version",
        help="Key to use when writing to GITHUB_OUTPUT.",
    )
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

    print(revision)
    write_github_output(revision, args.output_key)


if __name__ == "__main__":
    main()
