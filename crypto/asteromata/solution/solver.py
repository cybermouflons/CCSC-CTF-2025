from sage.all import *
from tqdm import tqdm

R = PolynomialRing(QQ, names='p,q,n,k,e,d,hint')
p,q,n,k,e,d,hint = R.gens()

I = Ideal([
    e*d - 1 - k * (p-1) * (q-1),
    n - p*q,
    hint - (d**2*p + q*e**2)
])

exec(open('output.txt').read())

PR = PolynomialRing(ZZ, names='q,k')
q,k = PR.gens()

ff = eval(str(I.elimination_ideal([d, p]).gens()[0]).replace('^', '**'))

for k in tqdm(range(e)):
    f = ff(k=k).univariate_polynomial()
    r = f.roots()
    if len(r) > 0:
        if r[0][0] != 0:
            q = r[0][0]
            p = n // q
            assert n == p * q
            break
else:
    print('oops')
    exit()

print(f'{p = }')
print(f'{q = }')

d = pow(e, -1, (p-1)*(q-1))

m = int(pow(ct, d, n))

msg = int.to_bytes(m, length=(m.bit_length()+7)//8, byteorder='big')

import re

print(re.search(rb'ECSC{[A-Za-z0-9_?!]+}', msg)[0])

'''
einv = pow(e, -1, (p-1)*(q-1))

pari.addprimes(p)
pari.addprimes(q)

m_einv = Zmod(n)(pow(ct, d, n))

m = int(m_einv.nth_root(einv))

msg = int.to_bytes(m, length=(m.bit_length()+7)//8, byteorder='big')

import re

print(re.search(rb'ECSC{.*}', msg)[0])
'''