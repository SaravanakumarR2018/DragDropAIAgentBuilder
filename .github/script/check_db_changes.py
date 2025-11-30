import os
import subprocess


def get_remote_revision(environment: str, host: str):
    """Get current alembic revision from Postgres container inside VM."""

    vm_password = (
        os.getenv("STAGING_VM_PASSWORD")
        if environment == "staging"
        else os.getenv("PROD_VM_PASSWORD")
    )

    if not vm_password:
        print("Missing VM password")
        return None

    # Command to run on the VM
    cmd = (
        "container=$(docker ps --filter 'ancestor=postgres' --format '{{.Names}}' | head -n1); "
        "if [ -z \"$container\" ]; then echo 'NO_CONTAINER'; exit 1; fi; "
        "docker exec -i \"$container\" psql -U langflow -d langflow -t -c "
        "\"select version_num from alembic_version;\""
    )

    ssh_cmd = [
        "sshpass",
        "-p", vm_password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        f"root@{host}",
        cmd,
    ]

    try:
        result = subprocess.run(
            ssh_cmd,
            text=True,
            capture_output=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print("SSH error:", e.stderr or e.stdout)
        return None


def main():
    environment = os.getenv("ENVIRONMENT", "staging")
    host = (
        os.getenv("STAGING_DB_HOST")
        if environment == "staging"
        else os.getenv("PROD_DB_HOST")
    )

    revision = get_remote_revision(environment, host)

    print(f"VM Alembic revision: {revision}")

    # Write output so GitHub Actions can read it
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"vm_alembic_version={revision}\n")


if __name__ == "__main__":
    main()
