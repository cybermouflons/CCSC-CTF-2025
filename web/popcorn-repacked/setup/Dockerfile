# Stage 1: Build the backend (Bun) application
FROM oven/bun:1.1-slim AS backend_build

RUN mkdir -p /temp/prod
COPY ./backend /temp/prod
RUN cd /temp/prod && bun install

# Stage 2: Prepare the bot application (Node.js packages only)
FROM node:20-slim AS bot_app_build

WORKDIR /temp/bot
COPY ./bot/package*.json ./
RUN npm install
COPY ./bot/admin-bot.js ./


# Stage 3: Final image combining all services with Supervisor
FROM ubuntu:latest

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install Supervisor, Nginx, Python, Node.js/npm, Bun, and Chromium dependencies
# Chromium and its dependencies are now installed ONLY in this final stage
RUN apt-get update && \
    apt-get install -y \
    supervisor \
    nginx \
    python3 \
    nodejs \
    npm \
    wget \
    unzip \
    gnupg2 \
    ca-certificates \
    fonts-liberation \
    libappindicator3-1 \
    libasound2t64 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgdk-pixbuf2.0-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    curl && \
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    apt-get install -y ./google-chrome-stable_current_amd64.deb && \
    rm ./google-chrome-stable_current_amd64.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Manually install Bun and symlink it to a common PATH location
RUN curl -fsSL https://bun.sh/install | bash \
    && ln -s /root/.bun/bin/bun /usr/local/bin/bun

# Set up Nginx for the cache service
COPY ./cache/app.conf /etc/nginx/sites-available/default
COPY ./cache/nginx.conf /etc/nginx/nginx.conf
RUN ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default \
    && rm -f /etc/nginx/sites-enabled/default.old

# Copy backend application
RUN mkdir -p /app/backend
COPY --from=backend_build /temp/prod /app/backend

# Copy bot application (only the Node.js app, Chromium is already installed in this stage)
RUN mkdir -p /app/bot
COPY --from=bot_app_build /temp/bot /app/bot
WORKDIR /app/bot
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV CHROME_BIN=/usr/bin/chromium

# Copy Supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports
EXPOSE 80
#EXPOSE 8080

# Set working directory for common files (if any) or where supervisor will run from
WORKDIR /app

# Command to start Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
