#!/usr/bin/env python3
import os, sys, json
from web3 import Web3

BANNER = """

 ▗▄▄▖▗▞▀▜▌   ■  ▗▞▀▚▖█  ▄ ▗▞▀▚▖▗▞▀▚▖▄▄▄▄  ▗▞▀▚▖ ▄▄▄
▐▌   ▝▚▄▟▌▗▄▟▙▄▖▐▛▀▀▘█▄▀  ▐▛▀▀▘▐▛▀▀▘█   █ ▐▛▀▀▘█
▐▌▝▜▌       ▐▌  ▝▚▄▄▖█ ▀▄ ▝▚▄▄▖▝▚▄▄▖█▄▄▄▀ ▝▚▄▄▖█
▝▚▄▞▘       ▐▌       █  █           █
            ▐▌                      ▀

Welcome to Gatekeeper!

Use the information below to solve the challenge

Contract Address: {0}
Pre-funded Private Key : {1}

Note: The RPC endpoint is provided in the challenge description.

Beyond these gates lie secrets veiled in silence. Only the worthy may pass and uncover what dwells within.
If you believe yourself chosen, type `flag` and perhaps the truth shall unveil itself to you.

The winning condition is making the contract function `success()` to return `true`.

"""
RPC = f"http://127.0.0.1:{os.getenv('RPC_PORT','8545')}"
PK = os.getenv("PLAYER_PK")
FLAG = os.getenv("FLAG")

with open("./proxy.addr") as f:
    PROXY = Web3.to_checksum_address(f.read().strip())

w3 = Web3(Web3.HTTPProvider(RPC))
sig_success = w3.keccak(text="success()")[:4]


def success() -> bool:
    data = w3.eth.call({"to": PROXY, "data": sig_success})
    return bool(int.from_bytes(data, "big"))


def handle(cmd: str):
    cmd = cmd.strip().lower()
    if cmd == "exit":
        exit(0)
    if cmd == "flag":
        return (FLAG if success() else "You shall not pass...") + "\n"
    return "commands: flag | exit\n"


sys.stdout.write(BANNER.format(PROXY, PK))
sys.stdout.write(">>> ")
sys.stdout.flush()
for line in sys.stdin:
    try:
        sys.stdout.write(handle(line))
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write(f"error!\n")
        sys.stdout.flush()
    finally:
        sys.stdout.write(">>> ")
        sys.stdout.flush()
