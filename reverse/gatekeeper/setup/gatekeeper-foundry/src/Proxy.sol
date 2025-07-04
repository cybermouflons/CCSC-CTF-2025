// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

/// @dev Minimal (≈42‑byte runtime) EIP‑1967 proxy, via‑IR‑compiled.
contract Proxy {
    /// EIP‑1967 implementation slot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) ‑ 1)
    bytes32 internal constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) payable {
        assembly {
            sstore(SLOT, impl)
        }
    }

    fallback() external payable virtual {
        assembly {
            let impl := sload(SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    receive() external payable virtual {
        assembly {
            let impl := sload(SLOT)
            // forward exact ETH
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}