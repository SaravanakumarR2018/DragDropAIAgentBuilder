import os
import subprocess


def get_revision():
    """Get alembic version from Postgres container inside VM."""
    cmd = (
        "container=$(docker ps --filter 'name=postgres' --format '{{.Names}}' | head -n1); "
        "if [ -z \"$container\" ]; then echo 'NO_CONTAINER'; exit 1; fi; "
        'docker exec -i "$container" '
        'psql -U langflow -d langflow -t -c "select version_num from alembic_version;"'
    )

    result = subprocess.run(
        cmd,
        check=False, shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout.strip()


def main():
    revision = get_revision()
    print(f"VM Alembic Revision: {revision}")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"vm_alembic_version={revision}\n")


if __name__ == "__main__":
    main()
