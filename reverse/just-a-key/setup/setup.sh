#!/bin/bash

# Check if chall exists
if [ -f "chall" ]; then
    read -p "The challenge is already generated, do you want to regenerate it? This will reset the random values (y/N): " answer
    case "$answer" in
        [yY][eE][sS]|[yY])
            echo "Regenerating..."
            ;;
        *)
            echo "Aborting."
            exit 0
            ;;
    esac
fi

python3 ./generate_code.py
gcc -O1 -o chall chall.c
strip chall
chmod +x chall
echo "[+] Binary generated successfully."
