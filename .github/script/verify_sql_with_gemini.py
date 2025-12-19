import os
import sys
import google.generativeai as genai


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python verify_forward_compatible_migration.py "
            "<upgrade_sql_path>"
        )
        sys.exit(1)

    upgrade_sql_path = sys.argv[1]

    # Read upgrade SQL file
    try:
        with open(upgrade_sql_path, "r", encoding="utf-8") as f:
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

Definition:
Forward compatible migration means:
- BOTH the OLD and NEW versions of the application must work
- Against the SAME database schema
- Without coordinated application upgrades
- Without requiring downgrade or rollback
- Assume the old application may read or write ANY existing column

Analyze STRICTLY.

upgrade.sql:
{upgrade_sql}

Respond EXACTLY as:

FORWARD_COMPATIBLE: YES or NO

If NO, explain precisely why the old application would break.
"""

    response = model.generate_content(prompt)
    result_text = response.text.strip()
    result_upper = result_text.upper()

    print(result_text)

    if "FORWARD_COMPATIBLE: YES" not in result_upper:
        print("\nForward compatibility check FAILED.")
        sys.exit(1)

    print("\nForward compatibility check PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
