import argparse
import json
import os
import pathlib
import urllib.request


PROMPT = (
    "Review the following SQL upgrade script for safety and backwards compatibility. "
    "Provide a short confirmation or highlight blocking issues."
)


def load_sql(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def call_gemini(api_key: str, upgrade_sql: str, downgrade_sql: str) -> dict:
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": PROMPT},
                    {"text": upgrade_sql},
                    {"text": "Also review the downgrade script."},
                    {"text": downgrade_sql},
                ]
            }
        ]
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-flash:generateContent?key="
        f"{api_key}"
    )

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(request) as response:
        return json.load(response)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Gemini review for SQL migrations")
    parser.add_argument("--upgrade", type=pathlib.Path, required=True, help="Path to upgrade SQL file")
    parser.add_argument("--downgrade", type=pathlib.Path, required=True, help="Path to downgrade SQL file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("GEMINI_API_KEY environment variable is required")

    upgrade_sql = load_sql(args.upgrade)
    downgrade_sql = load_sql(args.downgrade)

    result = call_gemini(api_key, upgrade_sql, downgrade_sql)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
