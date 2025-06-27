#!/bin/bash

if [ -f ./flag.sh ]; then
	chmod +x ./flag.sh
	. ./flag.sh
	rm ./flag.sh
fi

chmod -R 555 /opt/app

# Serve application
socat TCP4-LISTEN:1337,reuseaddr,fork EXEC:"python3 server.py",stderr,pty,iexten=0,echo=0
