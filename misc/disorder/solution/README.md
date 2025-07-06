## Write up
The goal of this challenge is to somehow leak the ciphertext and key from the running python script and hence uncover the flag by decrypting it.
Players must use the LOAD_FAST instruction of the Python VM which allows for OOB reads in order to get a reference to the objects of interest. Context -> `aes` and `ct`.

See solution script [here](./solve.py)

## References:
- https://juliapoo.github.io/security/2021/05/29/load_fast-py3-vm.html
- https://doar-e.github.io/blog/2014/04/17/deep-dive-into-pythons-vm-story-of-load_const-bug/
- https://github.com/x-vespiary/writeup/blob/a53d757a223c8dec53099934b5e0553b7f3c385b/2023/11-tsg/pwn-bypy.md?plain=1#L2
- https://docs.python.org/3/library/dis.html#opcode-CACHE