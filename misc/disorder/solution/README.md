## Write up
The goal of this challenge is to somehow leak the ciphertext and key from the running python script and hence uncover the flag by decrypting it.
Players must use the LOAD_FAST instruction of the Python VM which allows for OOB reads in order to get a reference to the objects of interest. Context -> `aes` and `ct`.

See solution script [here](./solve.py)

## References:
- https://juliapoo.github.io/security/2021/05/29/load_fast-py3-vm.html