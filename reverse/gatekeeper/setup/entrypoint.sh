#!/usr/bin/env sh
set -e


echo "[*] Generating mnemonic and accounts …"
MNEMONIC_JSON=$(cast wallet new-mnemonic --accounts 2 --json)

MNEMONIC=$(echo "$MNEMONIC_JSON" | jq -r '.mnemonic')
PLAYER_PK=$(echo "$MNEMONIC_JSON" | jq -r '.accounts[0].private_key')
DEPLOYER_KEY=$(echo "$MNEMONIC_JSON" | jq -r '.accounts[1].private_key')

export PLAYER_PK
export DEPLOYER_KEY
export PRIVATE_KEY=$DEPLOYER_KEY

echo "[*] Launching Anvil …"
anvil \
    --host 0.0.0.0                   \
    --port ${RPC_PORT}               \
    --mnemonic "$MNEMONIC"          \
    --accounts 2                     \
    --chain-id ${CHAIN_ID}                 \
    --block-time 10                  \
    > /tmp/anvil.log 2>&1 &

ANVIL_PID=$!

RPC_URL="http://127.0.0.1:${RPC_PORT}"
export ETH_RPC_URL=${RPC_URL}

echo "[*] Waiting for Anvil JSON-RPC at ${RPC_URL} …"
for i in $(seq 1 20); do
    if curl -s -X POST --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        -H "Content-Type: application/json" "${RPC_URL}" > /dev/null; then
        echo "[✓] Anvil is up!"
        break
    fi
    sleep 0.5
done

# Final fallback if not ready
if ! curl -s -X POST --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    -H "Content-Type: application/json" "${RPC_URL}" > /dev/null; then
    echo "[!] Failed to connect to Anvil at ${RPC_URL}"
    exit 1
fi

echo "[*] Deploying Gatekeeper …"
cd gatekeeper-foundry && \
    git init && \
    forge install foundry-rs/forge-std && \
    forge script script/Deploy.s.sol:Deploy --broadcast --rpc-url ${RPC_URL} --silent


PROXY_ADDR=$(jq -r '.transactions[] | select(.contractName == "Proxy") | .contractAddress' ~/gatekeeper-foundry/broadcast/Deploy.s.sol/${CHAIN_ID}/run-latest.json)
if [ -z "$PROXY_ADDR" ]; then
    echo "[!] Could not find Proxy contract address in $DEPLOY_JSON"
    exit 1
fi
echo "$PROXY_ADDR" > ./proxy.addr
echo "[✓] Proxy deployed at $PROXY_ADDR"

echo "[*] Starting checker on ${CHECK_PORT}"
exec socat TCP-LISTEN:${CHECK_PORT},reuseaddr,fork EXEC:"/home/ctf/checker.py",stderr
