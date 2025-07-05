#!/bin/ash

mv $WINEPREFIX/drive_c/app/flag.txt "$WINEPREFIX/drive_c/app/flag_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8).txt"
socat TCP4-LISTEN:1337,reuseaddr,fork EXEC:"wine64 ${WINEPREFIX}/drive_c/python/python.exe game.py",stderr,pty,iexten=0,echo=0,crnl
