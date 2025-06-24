#!/usr/bin/env python3
import io
import aiohttp
import asyncio
import textwrap
import contextlib
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

AI_APP_URL = 'http://localhost:8080'

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

async def expressionToCode(expr: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.post(AI_APP_URL + '/eval', json={"expression": expr}) as resp:
            data = await resp.json()
            return data.get("code", "")

def executeCode(code: str) -> str:
    print('[APP] Executing:\n', code)
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            exec(textwrap.dedent(code), {})
    except Exception as e:
        return f"Execution error: {e}"
    return buffer.getvalue().strip()

async def evaluateExpression(expr: str) -> str:
    code = await expressionToCode(expr)
    if not code:
        return "Failed to translate expression to code."
    return executeCode(code)

class Equation(BaseModel):
    equation: str

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/calculate")
async def calculate(eq: Equation):
    if eq.equation and len(eq.equation) < 512:
        result = await evaluateExpression(eq.equation)
        return {"result": result}
    else:
        return {"result": "TLDR"}
