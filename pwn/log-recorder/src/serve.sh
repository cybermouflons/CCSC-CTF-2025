#!/bin/sh
docker build --tag=log .
docker run -it -p 4242:4242 --rm --name=log log