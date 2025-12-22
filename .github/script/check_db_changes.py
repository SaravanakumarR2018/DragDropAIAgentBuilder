import logging
import os
import subprocess
from pathlib import Path

logging.basicConfig(level=logging.INFO)

def get_revision_from_db_url(database_url: str) -> str:
    result = subprocess.run(
        [
            "psql",
            database_url,
            "-t",
            "-c",
            "select version_num from alembic_version;",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()

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

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        output_key = os.getenv("ALEMBIC_OUTPUT_KEY", "alembic_version")
        output_path = Path(github_output)
        with output_path.open("a") as file:
            file.write(f"{output_key}={revision}\n")


if __name__ == "__main__":
    main()
