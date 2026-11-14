import json
import os
from google import genai
import time

PROMPT_VERSION = "v2"


def build_prompt(sample):
    return f"""You are a secure-code reviewer. The following Python snippet contains a security weakness: {sample["cwe_identifier"]}.

Weakness description: {sample["pattern_desc"]}

The line flagged as insecure is:
{sample["line_text"].strip()}

Rewrite the snippet so the weakness is fixed.

Rules:
- Keep every function and class name, parameter, and the overall behavior.
- Do NOT delete or comment out the vulnerable line. Replace it with a secure equivalent.
- Do NOT remove other code. The snippet may be an incomplete fragment; do not try to complete it.
- You may add imports if the fix needs them.
- Return ONLY the full corrected code. No explanations, no markdown fences.
- Every line you write must have a real effect. Never add a call whose result is discarded or unused just to remove the warning.
- The replacement must do what the original line did (same purpose, same interface). For example, if the line set a seed for reproducibility, do not replace it with something that only generates a random number.
- If the flagged line is already safe, or cannot be fixed without changing the behavior, return the code unchanged.

Code:
{sample["origin_code"]}
"""


if __name__ == "__main__":
    path = "PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json"
    data = json.load(open(path))
    py = [d for d in data if d["language"] == "python"]

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    for m in py[:5]:
        response = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=build_prompt(m),
        )
        print("=" * 60)
        print(m["prompt_id"], m["cwe_identifier"], "|", m["line_text"].strip())
        print(response.text)
        time.sleep(5)
    print(response.text)