#!/usr/bin/env ash
mv /flag.txt /flag_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32).txt
node app.js
