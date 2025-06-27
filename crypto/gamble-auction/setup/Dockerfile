FROM python:slim

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Update package lists and install dependencies
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install socat && \
    apt-get -y install python3 && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install pycryptodome
RUN mkdir -p /opt/app
WORKDIR /opt/app

COPY app/ /opt/app/

RUN useradd -m ctf && \
    chown -R root:root /opt/app && \
    chmod -R 755 /opt/app && \
    chmod +x /opt/app/serve.sh

EXPOSE 1337
CMD ["/bin/sh", "/opt/app/serve.sh"]
