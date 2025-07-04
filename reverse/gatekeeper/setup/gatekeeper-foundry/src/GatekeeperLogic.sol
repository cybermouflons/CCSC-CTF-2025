// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;

contract GatekeeperLogic {
    uint256 private constant VM_MAGIC = 0xCAFEBABE;

    bool public success;
    mapping(address => bool) private _callerUsed;

    event GateCleared(uint8 indexed gate, address indexed player);
    event Unlocked(address indexed player);

    error Fail(uint8 gate);

    function unlock(bytes calldata vmCode) external payable {
        /* Gate 1 */
        if (address(msg.sender).code.length == 0) revert Fail(1);
        emit GateCleared(1, msg.sender);

        /* Gate 2 */
        assembly {
            if iszero(eq(and(caller(), 0xffff), 0xEC5C)) {
                mstore(0, 3)
                revert(0, 1)
            }
        }
        if (_callerUsed[msg.sender]) revert Fail(2);
        _callerUsed[msg.sender] = true;
        emit GateCleared(2, msg.sender);

        /* Gate 3 */
        if (vmCode.length != 21) revert Fail(3);
        emit GateCleared(3, msg.sender);

        /* Gate 4 */
        if (_runVm(vmCode) != VM_MAGIC) revert Fail(4);
        emit GateCleared(4, msg.sender);

        success = true;
        emit Unlocked(msg.sender);
    }

    function _runVm(bytes calldata code) private pure returns (uint256 out) {
        uint256[32] memory stack;
        uint256 sp = 0;
        uint256 pc = 0;
        while (pc < code.length) {
            uint8 op = uint8(code[pc++]);
            if (op == 0x00) {
                require(sp > 0, "empty");
                return stack[sp - 1];
            } else if (op == 0x01) {
                require(pc < code.length, "EOF");
                stack[sp++] = uint8(code[pc++]);
            } else if (op == 0x02) {
                require(sp >= 2, "UF");
                stack[sp - 2] += stack[--sp];
            } else if (op == 0x03) {
                require(sp >= 2, "UF");
                stack[sp - 2] ^= stack[sp - 1];
                sp--;
            } else if (op == 0x04) {
                require(sp >= 1, "UF");
                stack[sp - 1] = ~stack[sp - 1];
            } else if (op == 0x05) {
                require(sp >= 1, "UF");
                stack[sp - 1] <<= 8;
            } else {
                revert("bad op");
            }
        }
        revert("no STOP");
    }
}
