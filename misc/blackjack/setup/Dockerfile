FROM node:buster-slim
LABEL maintainer="gramthanos@gmail.com"

ENV PATH "$PATH:/usr/local/bin"
ENV NODE_OPTIONS --openssl-legacy-provider

# Copy challenge files
COPY app/ /opt/app/
WORKDIR /opt/app

# Install node requirements
RUN npm install && npm cache clean --force

# Execute
EXPOSE 4242
CMD npm start
