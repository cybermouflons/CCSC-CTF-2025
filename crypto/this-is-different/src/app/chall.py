import des
import os
import random
import signal
import subprocess
import socketserver
from Crypto.Util.number import bytes_to_long
import traceback
des.core.ROTATES = (
    1, 1, 2, 2, 2, 2,
)

ORACLE_TRIES = 50

def encrypt(pt, key):
    cipher = des.DesKey(key)
    return cipher.encrypt(pt).hex()

if __name__ == "__main__":
    flag = open("flag.txt", "rb").read()
    oracle_counter = 0
    print('Welcome to our encryption oracle.\n' +
        '1. Encrypt\n' + '2. Get the flag\n')
    key = os.urandom(8)
    while True:
        try:
            option = input('> ').strip()
            if option == '1' and oracle_counter < 50:
                pt = bytes.fromhex(input('Provide message to encrypt > '))                
                if b'flag' in pt or len(pt) != 8:
                    print('No, I am not encrypting this.\n')
                    continue
                else:
                    ct = encrypt(pt, key)
                    
                    print(ct)
                    oracle_counter += 1
            elif oracle_counter > 50:
                print('You cannot request more than 50 ciphertexts. Bye!\n')
                break
            elif option == '2':
                ct = input('Provide the magic phrase > ')
                magic_ct = encrypt(b'Give me the flag', key)
                print(magic_ct)
                if magic_ct == ct:
                    print('Approved! Here is your flag:\n')
                    print(flag.decode() +'\n')
                    break
        except Exception as e:
            traceback.print_exc()