import os
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)

def get_revision():
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
    revision = get_revision()
    logging.info("VM Alembic Revision: %s", revision)

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        output_path = Path(github_output)
        with output_path.open("a") as file:
            file.write(f"vm_alembic_version={revision}\n")


if __name__ == "__main__":
    main()
