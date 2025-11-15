#!/usr/bin/env python3
"""Inject environment configuration into frontend2 static assets.

Updates Clerk publishable key meta tags when a key is available so that the
standalone static experience can bootstrap Clerk without additional scripts.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

META_PATTERN = re.compile(
    r'(\<meta\s+name="clerk-publishable-key"\s+content=")(.*?)("\s*/?>)',
    flags=re.IGNORECASE,
)


def update_meta_tag(path: Path, publishable_key: str) -> bool:
    """Update the Clerk publishable key meta tag for a single HTML file."""
    original = path.read_text(encoding="utf-8")
    match = META_PATTERN.search(original)
    if not match:
        return False

    if match.group(2) == publishable_key:
        return True

    updated = META_PATTERN.sub(
        lambda m: f"{m.group(1)}{publishable_key}{m.group(3)}", original, count=1
    )
    path.write_text(updated, encoding="utf-8")
    return True


def configure_frontend(source: Path, publishable_key: str) -> list[Path]:
    """Inject the publishable key into all HTML files under ``source``."""
    updated_files: list[Path] = []
    for path in source.rglob("*.html"):
        if update_meta_tag(path, publishable_key):
            updated_files.append(path)
    return updated_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inject Clerk configuration into the frontend2 static bundle",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "frontend2-static",
        help="Path to the frontend2 static directory (defaults to repository copy)",
    )
    parser.add_argument(
        "--publishable-key",
        dest="publishable_key",
        default=None,
        help="Explicit Clerk publishable key (defaults to environment)",
    )
    args = parser.parse_args(argv)

    publishable_key = (
        args.publishable_key
        or os.getenv("VITE_CLERK_PUBLISHABLE_KEY")
        or os.getenv("CLERK_PUBLISHABLE_KEY")
    )

    if not publishable_key:
        print(
            "[configure_frontend2_static] No Clerk publishable key provided; "
            "skipping injection.",
            file=sys.stderr,
        )
        return 0

    source = args.source
    if not source.exists():
        parser.error(f"Source directory '{source}' does not exist")

    updated = configure_frontend(source, publishable_key)
    if not updated:
        print(
            "[configure_frontend2_static] No Clerk meta tags found to update.",
            file=sys.stderr,
        )
        return 0

    for path in updated:
        print(f"[configure_frontend2_static] Updated {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
