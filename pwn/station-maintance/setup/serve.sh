#!/bin/sh
docker build --tag=station-maintenance .
docker run -it -p 4242:4242 --rm --name=station-maintenance station-maintenance