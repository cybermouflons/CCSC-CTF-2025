from Crypto.Util.number import *
import os

p = getPrime(1024)
q = getPrime(1024)
n = p * q

e = getPrime(22)
d = pow(e, -1, (p-1)*(q-1))

msg = open('flag.txt', 'rb').read()
msg += os.urandom(n.bit_length()//8 - 1 - len(msg))
m = bytes_to_long(msg)

ct = pow(m, e, n)

hint = d**2*p + q*e**2

open('output.txt', 'w').write(f'''\
{n = }
{e = }
{ct = }
{hint = }
''')