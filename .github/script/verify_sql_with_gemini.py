import os
import sys
import google.generativeai as genai

def main():
    if len(sys.argv) != 3:
        print("Usage: python verify_sql_with_gemini.py <upgrade_sql_path> <downgrade_sql_path>")
        sys.exit(1)

    upgrade_sql_path = sys.argv[1]
    downgrade_sql_path = sys.argv[2]

    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    model = genai.GenerativeModel('gemini-pro')

    with open(upgrade_sql_path, 'r') as f:
        upgrade_sql = f.read()
    with open(downgrade_sql_path, 'r') as f:
        downgrade_sql = f.read()

    prompt = f"""
    Please review the following SQL migration scripts for any potential issues.
    The upgrade script is:
    {upgrade_sql}

    The downgrade script is:
    {downgrade_sql}

    Respond ONLY with the word SAFE or UNSAFE on the first line, followed by your explanation.
    """
    response = model.generate_content(prompt)

    if "UNSAFE" in response.text:
        print("Gemini AI has identified potential issues with the SQL scripts.")
        print(response.text)
        sys.exit(1)
    elif "SAFE" in response.text:
        print("Gemini AI has determined the SQL scripts are safe.")
    else:
        print("Gemini AI response was inconclusive.")
        print(response.text)
        sys.exit(1)

if __name__ == "__main__":
    main()