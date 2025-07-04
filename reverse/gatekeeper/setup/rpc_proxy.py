#!/usr/bin/env python3
import os, json, requests
from flask import Flask, request, abort, Response

ANVIL = f"http://127.0.0.1:{os.getenv('RPC_PORT_INTERNAL','8545')}"
ALLOWED = ("eth_", "net_", "web3_")

app = Flask(__name__)


@app.route("/", methods=["POST"])
def proxy():
    j = request.get_json(silent=True)
    if not j or "method" not in j:
        abort(400)
    if not j["method"].startswith(ALLOWED):
        return Response(
            json.dumps({"error": "method blocked"}),
            status=403,
            content_type="application/json",
        )
    resp = requests.post(ANVIL, json=j).content
    return Response(resp, content_type="application/json")
