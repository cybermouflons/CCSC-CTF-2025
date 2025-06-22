#!/bin/sh
docker build --tag=pwnbot .
docker run -it -p 4242:4242 --rm --name=pwnbot pwnbot