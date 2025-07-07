# Writeup

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


