import os
import sys
from google import genai



def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python verify_upgrade_forward_with_gemini.py "
            "<upgrade_sql_path>"
        )
        sys.exit(1)

    upgrade_sql_path = sys.argv[1]

    # Read upgrade SQL file
    try:
        with open(upgrade_sql_path, encoding="utf-8") as f:
            upgrade_sql = f.read()
    except Exception as e:
        print(f"Error reading upgrade SQL file: {e}")
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

Analyze STRICTLY.

upgrade.sql:
{upgrade_sql}

Respond EXACTLY as:

UPGRADE_FORWARD: YES or NO

Explain each NO clearly and precisely.
"""

    response = model.generate_content(prompt)
    output = response.text.strip()
    output_upper = output.upper()

    print(output)

    if "UPGRADE_FORWARD: YES" not in output_upper:
        print("\nUpgrade forward compatibility check FAILED.")
        sys.exit(1)

    print("\nUpgrade forward compatibility check PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
