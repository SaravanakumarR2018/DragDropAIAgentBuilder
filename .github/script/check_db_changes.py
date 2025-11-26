import os
import subprocess

def get_revision_via_ssh(environment: str, host: str):
    """Fetch current alembic revision by SSH into the remote server."""

    vm_password = os.getenv("STAGING_VM_PASSWORD") if environment == "staging" else os.getenv("PROD_VM_PASSWORD")

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
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        revision = result.stdout.strip()
        return revision or None

    except subprocess.CalledProcessError as ssh_err:
        print("Warning: SSH failed.")
        print("Output:", ssh_err.stderr or ssh_err.stdout)
        return None


def main():
    environment = os.getenv("ENVIRONMENT", "staging")

    db_host = os.getenv("STAGING_DB_HOST") if environment == "staging" else os.getenv("PROD_DB_HOST")

    try:
        current_revision = get_revision_via_ssh(environment, db_host)
    except Exception as e:
        if "does not exist" in str(e):
            current_revision = None
        else:
            raise e

    workspace = os.getenv("GITHUB_WORKSPACE", ".")
    alembic_dir = os.path.join(workspace, "src/backend/base/langflow")     # VERIFY THIS PATH
    alembic_ini_path = os.path.join(alembic_dir, "alembic.ini")

    print("Using alembic.ini:", alembic_ini_path)

    alembic_command = ["alembic", "-c", alembic_ini_path, "heads"]

    def write_output_flag(value: str):
        output_path = os.getenv("GITHUB_OUTPUT")
        if not output_path:
            return
        with open(output_path, "a") as f:
            f.write(f"db_changes={value}\n")

    def run_alembic(command: list[str]):
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=alembic_dir,
                check=True,
            )
        except subprocess.CalledProcessError as err:
            print("Alembic command failed.")
            if err.stdout:
                print("Stdout:", err.stdout)
            if err.stderr:
                print("Stderr:", err.stderr)
            raise

    try:
        latest_revision_process = run_alembic(alembic_command)
    except FileNotFoundError:
        print("Alembic CLI not found; retrying with uv.")
        uv_command = [
            "uv",
            "run",
            "--project",
            os.path.join(workspace, "src/backend/base"),
            *alembic_command,
        ]
        latest_revision_process = run_alembic(uv_command)

    latest_revision = latest_revision_process.stdout.strip().split(" ")[0]

    if current_revision != latest_revision:
        print(f"DB changes detected → current: {current_revision}, latest: {latest_revision}")

        write_output_flag("true")

    else:
        write_output_flag("false")


if __name__ == "__main__":
    main()
