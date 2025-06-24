# Use official Python base image
FROM python:3.11-slim

# Prepare system dependencies
RUN apt-get update && \
    apt-get install -y supervisor && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
RUN pip install --no-cache-dir fastapi uvicorn jinja2 aiohttp openai

# Add user
RUN useradd -m -s /bin/bash www

# Prapare files
COPY app /app
COPY ai /ai
COPY supervisord.conf /etc/supervisord.conf

# Fix permissions
RUN chown -R www:www /app

WORKDIR /app
EXPOSE 8000
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
