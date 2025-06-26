#!/bin/bash
docker rm -f hardware_pot_pouri
docker build --tag=hardware_pot_pouri . && \
docker run -p 1337:1337 --rm --name=hardware_pot_pouri --detach hardware_pot_pouri
