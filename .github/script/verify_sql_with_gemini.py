import os
import sys
import google.generativeai as genai

# ===== MANUAL API KEY (LOCAL TESTING ONLY) =====
# DO NOT COMMIT A REAL KEY TO SOURCE CONTROL
MANUAL_GEMINI_API_KEY = "AIzaSyBJeffmuYafp45iKeLNMFXkmx74TNeA6w8"
# ==============================================

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

    # Resolve API key: ENV first, manual fallback second
    api_key = os.getenv("GEMINI_API_KEY") or MANUAL_GEMINI_API_KEY

    if not api_key or api_key == "PUT_YOUR_API_KEY_HERE":
        print("Gemini API key is not configured.")
        sys.exit(1)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-pro")

    prompt = f"""
You are a senior database migration reviewer.

Definitions:
- Upgrade forward compatible: does not break previous app versions
- Upgrade backward compatible: fully reversible via downgrade
- Downgrade forward compatible: can run immediately after upgrade
- Downgrade backward compatible: restores previous app compatibility

Analyze strictly.

upgrade.sql:
{upgrade_sql}

downgrade.sql:
{downgrade_sql}

Respond EXACTLY as:

UPGRADE_FORWARD: YES or NO
UPGRADE_BACKWARD: YES or NO
DOWNGRADE_FORWARD: YES or NO
DOWNGRADE_BACKWARD: YES or NO

Explain each NO.
"""

    response = model.generate_content(prompt)
    result = response.text.upper()

    print(response.text)

    required = [
        "UPGRADE_FORWARD: YES",
        "UPGRADE_BACKWARD: YES",
        "DOWNGRADE_FORWARD: YES",
        "DOWNGRADE_BACKWARD: YES",
    ]

    if not all(r in result for r in required):
        print("\nMigration compatibility check FAILED.")
        sys.exit(1)

    print("\nMigration compatibility check PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
