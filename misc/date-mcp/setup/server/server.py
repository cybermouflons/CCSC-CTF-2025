#!/usr/bin/env python3
import re
import uvicorn
import platform
import subprocess
from typing import Any

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route

# Initialize FastMCP server
mcp = FastMCP("weather")


# Implement get_current_time
@mcp.tool()
async def get_current_time(tz: str) -> str:
    """Get current time in a specific timezone

    Args:
            timezone: IANA timezone (e.g. 'Europe/Athens', 'America/New_York')
    """
    # Easy if tz is valid using regex
    if not re.fullmatch(r"\S+/\S+", tz):
        return "Invalid timezone format"

    sysname = platform.system()
    x = True

    tz_lookup = {"NY": "America/New_York"}
    # print("Debug: timezone is", tz)

    # support 4 windows
    if sysname == "Windows":
        cmd = f"powershell -Command \"[System.TimeZoneInfo]::ConvertTime([datetime]::UtcNow, [System.TimeZoneInfo]::FindSystemTimeZoneById('{tz}')).ToString('yyyy-MM-ddTHH:mm:ss')\""
        # cmd = f'powershell -Command "Get-Date"'

    # support 4 mac/linux
    else:
        cmd = f'env TZ="{tz}" date "+%Y-%m-%dT%H:%M:%S"'
        # cmd = "date"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        out = result.stdout.strip()
    except Exception as e:
        print(e)
        return "error getting time"

    # AI will know what was the error based on the result
    # if result.returncode != 0:
    # 	return f"bad timezone? {tz}"

    # print("Got time:", out)
    return out if out else "unkown error"


# Create server app
def create_app(debug: bool = False) -> Starlette:
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await mcp._mcp_server.run(
                read_stream,
                write_stream,
                mcp._mcp_server.create_initialization_options(),
            )

    return Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )


app = create_app(debug=True)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=1337)
