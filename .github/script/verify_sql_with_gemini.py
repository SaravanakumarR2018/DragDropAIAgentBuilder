import os
import sys
import google.generativeai as genai


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python verify_sql_with_gemini.py "
            "<upgrade_sql_path> <downgrade_sql_path>"
        )
        sys.exit(1)

    upgrade_sql_path = sys.argv[1]
    downgrade_sql_path = sys.argv[2]

    # Read SQL files
    try:
        with open(upgrade_sql_path, "r", encoding="utf-8") as f:
            upgrade_sql = f.read()
        with open(downgrade_sql_path, "r", encoding="utf-8") as f:
            downgrade_sql = f.read()
    except Exception as e:
        print(f"Error reading SQL files: {e}")
        sys.exit(1)

    # Resolve API key
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "PUT_YOUR_API_KEY_HERE":
        print("Gemini API key is not configured.")
        sys.exit(1)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""
You are a senior database migration reviewer.

We are validating ONLY forward compatibility.

Definitions:

UPGRADE FORWARD COMPATIBLE:
- After applying upgrade.sql
- BOTH version 1 (old app) and version 2 (new app) must work
- Against the SAME database
- Assume the old app may read or write ANY existing column

DOWNGRADE FORWARD COMPATIBLE:
- After applying downgrade.sql
- BOTH version 2 (new app) and version 1 (old app) must work
- Against the SAME database
- Assume the new app may read or write ANY existing column

Analyze STRICTLY.

upgrade.sql:
{upgrade_sql}

downgrade.sql:
{downgrade_sql}

Respond EXACTLY as:

UPGRADE_FORWARD: YES or NO
DOWNGRADE_FORWARD: YES or NO

Explain each NO clearly and precisely.
"""

    response = model.generate_content(prompt)
    output = response.text.strip()
    output_upper = output.upper()

    print(output)

    if (
        "UPGRADE_FORWARD: YES" not in output_upper
        or "DOWNGRADE_FORWARD: YES" not in output_upper
    ):
        print("\nForward compatibility check FAILED.")
        sys.exit(1)

    print("\nForward compatibility check PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
