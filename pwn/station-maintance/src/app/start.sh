#!/bin/bash
su -l ctflib -c "cd /opt/app && socat -dd TCP4-LISTEN:4242,reuseaddr,fork EXEC:./log-recorder,pty,echo=0,raw,iexten=0"
