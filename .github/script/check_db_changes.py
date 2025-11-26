import os
import subprocess

def get_revision_via_ssh(environment: str, host: str):
    """Fetch current alembic revision by SSH into the remote server."""

    vm_password = os.getenv("VM_PASSWORD")

    if not vm_password or not host:
        print("Warning: VM credentials not provided; skipping SSH DB check.")
        return None

    container_cmd = (
        "container=$(docker ps --filter 'ancestor=postgres' --format '{{.Names}}' | head -n1); "
        "if [ -z \"$container\" ]; then exit 1; fi; "
        "docker exec -i \"$container\" psql -U langflow -d langflow -t -c \"select version_num from alembic_version;\""
    )

    ssh_command = [
        "sshpass",
        "-p", vm_password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        f"root@{host}",
        container_cmd,
    ]

    try:
        result = subprocess.run(
            ssh_command, capture_output=True, text=True, check=True
        )
        revision = result.stdout.strip()
        return revision or None

    except subprocess.CalledProcessError as ssh_err:
        print("Warning: SSH failed.")
        print("Output:", ssh_err.stderr or ssh_err.stdout)
        return None


def main():
    environment = os.getenv("ENVIRONMENT", "staging")

    if environment == "staging":
        db_host = os.getenv("STAGING_DB_HOST")
    else:
        db_host = os.getenv("PROD_DB_HOST")

    try:
        current_revision = get_revision_via_ssh(environment, db_host)
    except Exception as e:
        if "does not exist" in str(e):
            current_revision = None
        else:
            raise e

    workspace = os.getenv("GITHUB_WORKSPACE", ".")
    alembic_dir = os.path.join(workspace, "src/backend/base/langflow")
    alembic_ini_path = os.path.join(alembic_dir, "alembic.ini")

    # get latest migration head
    latest_revision_process = subprocess.run(
        ["alembic", "-c", alembic_ini_path, "heads"],
        capture_output=True,
        text=True,
        cwd=alembic_dir,
        check=True,
    )
    latest_revision = latest_revision_process.stdout.strip().split(" ")[0]

    if current_revision != latest_revision:
        print(f"DB changes detected → current: {current_revision}, latest: {latest_revision}")

        with open(os.getenv("GITHUB_OUTPUT"), "a") as f:
            f.write("db_changes=true\n")

        # generate upgrade SQL
        upgrade_sql_path = os.path.join(alembic_dir, "upgrade.sql")
        with open(upgrade_sql_path, "w") as f:
            subprocess.run(
                ["alembic", "-c", alembic_ini_path, "upgrade", "head", "--sql"],
                stdout=f,
                cwd=alembic_dir,
                check=True,
            )

        # generate downgrade SQL
        downgrade_target = current_revision or "base"
        downgrade_sql_path = os.path.join(alembic_dir, "downgrade.sql")
        with open(downgrade_sql_path, "w") as f:
            subprocess.run(
                ["alembic", "-c", alembic_ini_path, "downgrade", downgrade_target, "--sql"],
                stdout=f,
                cwd=alembic_dir,
                check=True,
            )

    else:
        print("No DB changes detected.")
        with open(os.getenv("GITHUB_OUTPUT"), "a") as f:
            f.write("db_changes=false\n")


if __name__ == "__main__":
    main()
