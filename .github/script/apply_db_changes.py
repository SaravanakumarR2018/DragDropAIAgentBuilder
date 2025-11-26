import os
import subprocess
from sqlalchemy import create_engine, text

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

    with open('migrations/upgrade.sql', 'r') as f:
        upgrade_sql = f.read()

    engine = create_engine(db_url)
    with engine.connect() as connection:
        with connection.begin():
            connection.execute(text(upgrade_sql))

    workspace = os.getenv("GITHUB_WORKSPACE")
    alembic_dir = os.path.join(workspace, 'src/backend/base/langflow')
    alembic_ini_path = os.path.join(alembic_dir, 'alembic.ini')
    subprocess.run(
        ["alembic", "-c", alembic_ini_path, "-x", f"db_url={db_url}", "stamp", "head"],
        cwd=alembic_dir,
        check=True,
    )

if __name__ == "__main__":
    main()