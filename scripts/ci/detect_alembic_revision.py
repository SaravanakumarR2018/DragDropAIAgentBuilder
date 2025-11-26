import argparse
import pathlib
import re
import subprocess
from typing import Iterable


REVISION_PATTERN = re.compile(r"([0-9a-f]{12,})", re.IGNORECASE)


def run_command(command: list[str], cwd: pathlib.Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.stdout


def parse_revision(lines: Iterable[str]) -> str:
    for line in reversed(list(lines)):
        match = REVISION_PATTERN.search(line)
        if match:
            return match.group(1)
    raise SystemExit("Could not parse Alembic revision from command output")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect latest Alembic revision")
    parser.add_argument(
        "--project-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
        help="Root of the repository where Makefile is located",
    )
    parser.add_argument(
        "--versions-dir",
        type=pathlib.Path,
        default=None,
        help="Optional Alembic versions directory; used for compatibility only",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = args.project_root
    if args.versions_dir:
        versions_dir = (
            args.versions_dir
            if args.versions_dir.is_absolute()
            else (project_root / args.versions_dir)
        )
        if not versions_dir.exists():
            raise SystemExit(f"Alembic versions directory not found: {versions_dir}")

    _ = run_command(["make", "alembic-upgrade"], cwd=project_root)
    current_output = run_command(["make", "alembic-current"], cwd=project_root)

    revision = parse_revision(current_output.splitlines())
    print(revision)


if __name__ == "__main__":
    main()