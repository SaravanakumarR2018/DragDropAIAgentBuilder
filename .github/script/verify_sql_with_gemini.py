import logging
import os
import sys
from pathlib import Path

from google import genai

EXPECTED_ARG_COUNT = 2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    if len(sys.argv) != EXPECTED_ARG_COUNT:
        logger.error(
            "Usage: python verify_upgrade_forward_with_gemini.py <upgrade_sql_path>"
        )
        sys.exit(1)

    upgrade_sql_path = Path(sys.argv[1])

    try:
        upgrade_sql = upgrade_sql_path.open(encoding="utf-8").read()
    except OSError:
        logger.exception("Error reading upgrade SQL file")
        sys.exit(1)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "PUT_YOUR_API_KEY_HERE":
        logger.error("Gemini API key is not configured.")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    prompt = f"""
You are a senior database migration reviewer.

We are validating ONLY forward compatibility.

Definitions:

UPGRADE FORWARD COMPATIBLE:
- After applying upgrade.sql
- The current version of the webapp which uses the schema before applying upgrade.sql and
  the new version of the webapp which uses the schema after applying upgrade.sql must work
- Both the versions of the webapp must work after applying upgrade.sql
- Against the SAME database

Analyze STRICTLY.

upgrade.sql:
{upgrade_sql}

Respond EXACTLY as:

UPGRADE_FORWARD: YES or NO

Explain each NO clearly and precisely.
"""
    model = os.getenv("GEMINI_MODEL")
    if not model:
        logger.error("GEMINI_MODEL is not configured.")
        sys.exit(1)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
    )

    output = response.text.strip()
    logger.info("Gemini response:\n%s", output)

    if "UPGRADE_FORWARD: YES" not in output.upper():
        logger.error("Upgrade forward compatibility check FAILED.")
        sys.exit(1)

    logger.info("Upgrade forward compatibility check PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
