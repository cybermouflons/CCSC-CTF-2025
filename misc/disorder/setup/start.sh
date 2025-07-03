#!/bin/bash
TEMP_FLAG=$(mktemp /tmp/flag_XXXXXX.txt)
cp /opt/pyjail/flag.txt "$TEMP_FLAG"
chown ctf:ctf "$TEMP_FLAG"
chmod 644 "$TEMP_FLAG"
export FLAG_PATH="$TEMP_FLAG"
exec su ctf -c "cd /opt/pyjail && python3 jail.py"