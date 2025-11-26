import os
import subprocess
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

def main():
    environment = os.getenv("ENVIRONMENT")
    if environment == "staging":
        db_user = os.getenv("STAGING_DB_USER")
        db_password = os.getenv("STAGING_DB_PASSWORD")
        db_name = os.getenv("STAGING_DB_NAME")
        db_host = os.getenv("STAGING_DB_HOST")
    else:
        db_user = os.getenv("PROD_DB_USER")
        db_password = os.getenv("PROD_DB_PASSWORD")
        db_name = os.getenv("PROD_DB_NAME")
        db_host = os.getenv("PROD_DB_HOST")

    db_url = f"postgresql://{db_user}:{db_password}@{db_host}/{db_name}"
    engine = create_engine(db_url)

    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT version_num FROM alembic_version"))
            current_revision = result.scalar_one_or_none()
    except OperationalError as e:
        # Connection issues (e.g., DB not reachable in CI) should not fail the workflow
        print(f"Warning: unable to connect to database: {e}")
        current_revision = None        
    except Exception as e:
        if "does not exist" in str(e):
            current_revision = None
        else:
            raise e

    workspace = os.getenv("GITHUB_WORKSPACE")
    alembic_dir = os.path.join(workspace, 'src/backend/base/langflow')
    alembic_ini_path = os.path.join(alembic_dir, 'alembic.ini')

    latest_revision_process = subprocess.run(
        ["alembic", "-c", alembic_ini_path, "heads"],
        capture_output=True,
        text=True,
        cwd=alembic_dir,
        check=True,
    )
    latest_revision = latest_revision_process.stdout.strip().split(" ")[0]

    if current_revision != latest_revision:
        print(f"Database changes detected. Current revision: {current_revision}, Latest revision: {latest_revision}")
        with open(os.getenv("GITHUB_OUTPUT"), "a") as f:
            f.write("db_changes=true\n")

        # Generate upgrade SQL
        upgrade_sql_path = os.path.join(alembic_dir, "upgrade.sql")
        with open(upgrade_sql_path, "w") as f:
            subprocess.run(
                ["alembic", "-c", alembic_ini_path, "upgrade", "head", "--sql"],
                stdout=f,
                cwd=alembic_dir,
                check=True,
            )
        # Generate downgrade SQL
        downgrade_target = current_revision if current_revision else "base"
        downgrade_sql_path = os.path.join(alembic_dir, "downgrade.sql")
        with open(downgrade_sql_path, "w") as f:
            subprocess.run(
                ["alembic", "-c", alembic_ini_path, "downgrade", downgrade_target, "--sql"],
                stdout=f,
                cwd=alembic_dir,
                check=True,
            )
    else:
        print("No database changes detected.")
        with open(os.getenv("GITHUB_OUTPUT"), "a") as f:
            f.write("db_changes=false\n")

if __name__ == "__main__":
    main()