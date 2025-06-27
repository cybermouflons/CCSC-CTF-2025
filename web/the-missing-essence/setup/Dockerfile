FROM node:alpine

# set environment variables
ENV APP_PORT 4242

# Install packages
RUN apk add --update --no-cache supervisor

# Setup challenge files
RUN mkdir -p /opt/app
COPY ./app/package.json /opt/app/package.json
WORKDIR /opt/app
# Install dependencies
RUN npm install

# Copy challenge files
COPY app/ /opt/app/
COPY flag.txt /flag.txt

# Setup superivsord
COPY supervisord.conf /etc/supervisord.conf

# Expose port and run services
EXPOSE 4242
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
