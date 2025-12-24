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
    fallback_to_heads: bool,
    alembic_workdir: Path,
    alembic_ini: str,
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
        combined = (result.stdout + result.stderr).lower()
        if fallback_to_heads and "alembic_version" in combined:
            logging.warning("alembic_version missing, falling back to heads")
            return get_revision_from_alembic(alembic_workdir, alembic_ini)

        logging.error(result.stderr.strip())
        raise SystemExit(1)

    revision = result.stdout.strip()
    if not revision:
        if fallback_to_heads:
            return get_revision_from_alembic(alembic_workdir, alembic_ini)
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
    parser.add_argument(
        "--fallback-to-heads",
        action="store_true",
        help="Fallback to alembic heads if alembic_version table is missing.",
    )
    parser.add_argument(
        "--alembic-workdir",
        dest="alembic_workdir",
        default=".",
        help="Path to run alembic from when falling back.",
    )
    parser.add_argument(
        "--alembic-ini",
        dest="alembic_ini",
        default="alembic.ini",
        help="Alembic ini file to use when falling back.",
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

    database_url = build_database_url(
        args.database_url,
        args.db_user,
        args.db_password,
        args.db_name,
        args.db_host,
        args.db_port,
    )
    revision = get_revision_from_database_url(
        database_url,
        args.fallback_to_heads,
        Path(args.alembic_workdir).resolve(),
        args.alembic_ini,
    )

    print(revision)
    write_github_output(revision, args.output_key)


if __name__ == "__main__":
    main()
