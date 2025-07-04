FROM debian:bookworm-slim AS foundry-build

RUN apt-get update && apt-get install -y curl bash git ca-certificates \
    && curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y python3 python3-pip socat curl jq git

COPY --from=foundry-build /root/.foundry/bin /usr/local/bin

RUN pip3 install --no-cache-dir gunicorn flask web3 requests --break-system-packages

RUN useradd -m ctf
WORKDIR /home/ctf

# # --- helper scripts ---
COPY entrypoint.sh checker.py rpc_proxy.py ./
COPY ./gatekeeper-foundry ./gatekeeper-foundry

RUN chmod +x entrypoint.sh checker.py rpc_proxy.py && \
    chown -R ctf:ctf /home/ctf

USER ctf

EXPOSE 8545 1337
ENTRYPOINT ["/home/ctf/entrypoint.sh"]
