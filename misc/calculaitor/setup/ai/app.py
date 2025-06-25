#!/usr/bin/env python3
import re
import os
import random
import uvicorn
from openai import OpenAI
from fastapi import FastAPI, Request
from pydantic import BaseModel

# Configure client to connect to the AI server
ai_base_url = os.getenv('AI_SERVER_URL', 'https://generativelanguage.googleapis.com/v1beta/openai/')
ai_api_keys = os.getenv('AI_SERVER_API_KEY').split(',')
ai_model_to_use = os.getenv('AI_SERVER_MODEL', 'models/gemini-2.0-flash')

system_prompt = """
Convert the given math formula to valid Python code that will print the result using `print(result)`.
Don't provide an explanation, just the Python code and nothing else.
Only accept valid equations, nothing else. If the equation is invalid, return `print("Error")`.
Wrap the code in 3 backticks.
"""

app = FastAPI()

class EvalRequest(BaseModel):
    expression: str

def extractCode(text):
    match = re.search(r"```(?:python)?\n(.*?)\n```", text, re.DOTALL)
    if match:
        return match.group(1)
    return None

@app.post("/eval")
def evaluate(req: EvalRequest):
    expression = req.expression
    print('[AI] Expression:', expression)
    
    client = OpenAI(
        base_url = ai_base_url,
        api_key = random.choice(ai_api_keys)
    )
    query = client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": expression}
        ],
        model=ai_model_to_use
    )

    response = query.choices[0].message.content
    code = extractCode(response)
    print('[AI] Python Code:', code)
    return {"code": code}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
