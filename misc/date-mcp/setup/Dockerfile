FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y tzdata && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uvicorn starlette mcp
RUN useradd -r www

# Copy your project files
COPY server /server
#RUN chmod -R 744 /server

USER www
EXPOSE 1337
WORKDIR /server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "1337"]
