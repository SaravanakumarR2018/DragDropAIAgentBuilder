import argparse
import pathlib
import re


def get_latest_revision(versions_dir: pathlib.Path) -> str:
    revision = None
    latest_mtime = -1

    for path in versions_dir.glob("*.py"):
        mtime = path.stat().st_mtime
        match = re.search(r"revision\s*=\s*['\"]([^'\"]+)['\"]", path.read_text())
        if match and mtime >= latest_mtime:
            revision = match.group(1)
            latest_mtime = mtime

    if not revision:
        raise SystemExit("No revision found in alembic versions directory")

    return revision


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect latest Alembic revision")
    parser.add_argument(
        "--versions-dir",
        type=pathlib.Path,
        default=pathlib.Path("src/backend/base/langflow/alembic/versions"),
        help="Path to Alembic versions directory",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    revision = get_latest_revision(args.versions_dir)
    print(revision)


if __name__ == "__main__":
    main()
