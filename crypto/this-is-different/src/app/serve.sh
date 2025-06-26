#!/bin/bash

if [ -f ./flag.sh ]; then
	chmod +x ./flag.sh
	. ./flag.sh
	rm ./flag.sh
fi

chmod -R 555 /opt/app

# Serve application
#su -l ctf -c "cd /opt/app && socat -dd TCP4-LISTEN:4242,reuseaddr,fork EXEC:python3 chall.py,pty,echo=0,raw,iexten=0"
socat TCP4-LISTEN:1337,reuseaddr,fork EXEC:"python3 chall.py",stderr,pty,iexten=0,echo=0