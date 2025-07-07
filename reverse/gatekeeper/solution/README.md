# Writeup

### TL;DR;
See here for a full solution script. It can be run like this `PROXY=<proxy_addr> PRIVATE_KEY=<private_key> forge script script/Solve.s.sol:Solve --broadcast --rpc-url http://<rpc_endpoint_host>:<port>-vvvv`

---

Given that is is a reverse challenge the first step should be to extract the code of the contract provided.

One can do that using the `cast` foundry utility :
```
cast code --rpc-url http://<rpc_endpoint_host>:<port> <contract_address> --disassemble
```

This will give the following low-level disassembled EVM code:
```
00000001: PUSH1 0x80
00000003: PUSH1 0x40
00000005: MSTORE
00000006: CALLDATASIZE
00000007: PUSH1 0x48
00000009: JUMPI
0000000a: PUSH32 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
0000002b: SLOAD
0000002c: CALLDATASIZE
0000002d: PUSH0
0000002e: DUP1
0000002f: CALLDATACOPY
00000030: PUSH0
00000031: DUP1
00000032: CALLDATASIZE
00000033: PUSH0
....
```

PLayers accustomed to blockchain development practices can recognise the `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` hash as this is the storage slot for implementing proxies (EIP-1967 i.e. `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)`). In other words the code retrieved is the code of the proxy contract which delegates calls to the contract that holds the actual logic. Otherwise, this can be discovered through reversing or googling.

That being said, players can retrieve the address of the contract behind the proxy by fetching the vlaue of the storage slot `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` using cast again:

```
cast storage --rpc-url --rpc-url http://<rpc_endpoint_host>:<port> <proxy_contract_addr> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
```

In my case I got something like this:
```
0x0000000000000000000000009488cf41a7790af62356ea3fe70c606164d4ae54
```

Therefore that the address of the contract holding the logic is `0x9488cf41a7790af62356ea3fe70c606164d4ae54` (Note that it's padded)

The next step is to retrieve the bytecode of the contract:
```
cast code --rpc-url http://<rpc_endpoint_host>:<port> 0x9488cf41a7790af62356ea3fe70c606164d4ae54 > bytecode.hex
```

You can also optionally get the disassembled code with the `--disassemble` flag

A good way moving forward is extracting the function signatures of the contract:
```
cast code --rpc-url  http://<rpc_endpoint_host>:<port>  0x9488cf41a7790af62356ea3fe70c606164d4ae54  --disassemble | grep -Eo 'PUSH4 0x[0-9a-fA-F]{8}' |  awk '{print $2}' | sort -u
```

This extracs all the PUSH4 arguments from the bytecode which usually corresponds to the function signature. In this case we get:
```
0x0b93381b
0x48c89491
0xcafebabe
```

The last one seems like an intentional value so probably not a function but the first two can be checked against https://www.4byte.directory/

The [first one](https://www.4byte.directory/signatures/?bytes4_signature=0x0b93381b) is the `success()` function which is also mentioned in the welcome message of the challenge.
The [second one](https://www.4byte.directory/signatures/?bytes4_signature=0x48c89491) is a function called `unlock(bytes)` which looks like a great entry point for reversing.

With the bytecode at hand participants can use EVM reversing tools like Ghidra EVM plugin, or heimdall to understand what the unlock function does. i.e.
```
heimdall decompile main.hex --include-yul  --include-sol
```

By reversing players must realise that the functions checks 4 conditions:
1. The call is to the unlock function made by a contract
2. The contract's address must end with `EC5C` (vanity address)
3. The bytes passed as an arguments have length of 21
4. These bytes are then used by a tiny stack-based VM to perform some operations (XOR/SHIFTS) of which the result is compared agaist 0xCAFEBABE.

If all of the above are true then the success flag is toggled to true and participants can request the flag from the interactive endpoint provided in the challenge by just typing `flag`

---
