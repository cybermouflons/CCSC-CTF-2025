FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    && apt-get purge -y build-essential libjpeg-dev zlib1g-dev libfreetype6-dev \
    && apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /opt/pyjail
COPY . ./
RUN chmod 600 flag.txt && chown root:root flag.txt
RUN chmod +x /opt/pyjail/start.sh

EXPOSE 1337
CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork,su=root", "EXEC:/opt/pyjail/start.sh"]