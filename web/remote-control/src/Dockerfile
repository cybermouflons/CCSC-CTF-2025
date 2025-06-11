FROM node:23-alpine

WORKDIR /app

COPY ./app/package.json /app/package.json
RUN npm install
COPY ./app /app/
COPY ./flag.txt /flag.txt

EXPOSE 1337
CMD [ "/bin/ash", "init.sh" ]
