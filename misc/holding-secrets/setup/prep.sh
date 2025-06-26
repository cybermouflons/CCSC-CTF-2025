#!/bin/bash
echo "flag.st" > /root/OpenPLC_v3/webserver/active_program
sed -i 's/blank_program.st/flag.st/g' /root/OpenPLC_v3/background_installer.sh