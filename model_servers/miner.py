import os
import json
from fastapi import FastAPI, HTTPException
from starlette.requests import Request
import anthropic

app = FastAPI()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

PROMPT = """
You are an elite Solidity smart contract auditor.
Analyze the following contract and identify all security vulnerabilities
Use only these exact vulnerabilityClass values:
- Known compiler bugs
- Reentrancy
- Gas griefing
- Oracle manipulation
- Bad randomness
- Unexpected privilege grants
- Forced reception
- Integer overflow/underflow
- Race condition
- Unguarded function
- Inefficient storage key
- Front-running potential
- Miner manipulation
- Storage collision
- Signature replay
- Unsafe operation
- Invalid code

Output format:
[
    {
        "fromLine": <integer>, starting line number of the vulnerable code
        "toLine": <integer>, ending line number of the vulnerable code,
        "vulnerabilityClass": exact type of the vulnerability (e.g. Reentrancy, Integer Overflow, Invalid code),
        "testCase": an example of how the vulnerability can be exploited,
        "description": a detailed description of the issue,
        "priorArt": array of real-world incidents (e.g., ["The DAO Hack"]),
        "fixedLines": a corrected version of the affected code (if applicable),
    },
]

If no vulnerabilities are present, return exactly [] with no whitespace or comments
If the code is not valid Solidity or cannot be analyzed, return exactly:
[
    {
        "fromLine": 1, 
        "toLine": Total number of lines in the code,
        "vulnerabilityClass": "Invalid Code",
        "description": "The entire code is considered invalid for audit processing.",
    }
]

Return only this JSON. No extra text, comments, or explanation.
""".strip()


REQUIRED_KEYS = {
    "fromLine",
    "toLine",
    "vulnerabilityClass",
    "description",
}
INT_KEYS = ("fromLine", "toLine")


def try_prepare_result(result) -> list[dict] | None:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return None
    if isinstance(result, dict):
        if (
            len(result) == 1
            and isinstance(list(result.values())[0], list)
            and all(isinstance(item, dict) for item in list(result.values())[0])
        ):
            result = list(result.values())[0]
        else:
            result = [result]
    prepared = []
    for item in result:
        for key in REQUIRED_KEYS:
            if key not in item:
                return None
        cleared = {k: item[k] for k in REQUIRED_KEYS}
        if (
            "priorArt" in item
            and isinstance(item["priorArt"], list)
            and all(isinstance(x, str) for x in item["priorArt"])
        ):
            cleared["priorArt"] = item["priorArt"]
        if "fixedLines" in item and isinstance(item["fixedLines"], str):
            cleared["fixedLines"] = item["fixedLines"]
        if "testCase" in item and isinstance(item["testCase"], str):
            cleared["testCase"] = item["testCase"]
        for k in INT_KEYS:
            if isinstance(cleared[k], int) or (
                isinstance(item[k], str) and item[k].isdigit()
            ):
                cleared[k] = int(item[k])
            else:
                return None
        prepared.append(cleared)
    return prepared


def generate_audit(source: str):
    response = client.messages.create(
        model="claude-3-7-sonnet-latest",
        max_tokens=4096,
        temperature=0,
        system=PROMPT,
        messages=[{"role": "user", "content": source}],
    )
    return response.content[0].text


@app.post("/submit")
async def submit(request: Request):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    contract_code = (await request.body()).decode("utf-8")
    while tries > 0:
        result = generate_audit(contract_code)
        result = try_prepare_result(result)
        if result is not None:
            is_valid = True
            break
        tries -= 1
    if not is_valid:
        raise HTTPException(status_code=400, detail="Unable to prepare audit")
    return result

@app.get("/healthcheck")
async def healthchecker():
    return {"status": "OK"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("SERVER_PORT", "5001")))
