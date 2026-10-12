// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

address constant ENTRY_POINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
address constant BYPASS = 0x000000000000000000000000000000000000dEaD;

struct PackedUserOperation {
    address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits;
    uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature;
}

/// Account: only the EntryPoint may validate or execute; execution needs the paymaster to have
/// run first, as the unwrap after a Railgun unshield does.
contract MockAccount {
    function validateUserOp(PackedUserOperation calldata, bytes32, uint256) external view returns (uint256) {
        require(msg.sender == ENTRY_POINT, "account: not from EntryPoint");
        uint256 x; unchecked { for (uint256 i = 0; i < 50; i++) { x += uint256(keccak256(abi.encode(i))); } }
        return x == 0 ? 1 : 0;
    }
    function run(address paymaster, address payable to) external {
        require(msg.sender == ENTRY_POINT, "account: not from EntryPoint");
        require(MockPaymaster(paymaster).paid(), "account: nothing unshielded yet");
        // Like the last step of a native unshield: native currency to the recipient. Towards a
        // new account the CALL must have 34000 gas at hand, most of which it does not consume.
        if (to != address(0)) {
            (bool ok, ) = to.call{value: 1}("");
            require(ok, "account: transfer failed");
        }
    }
    receive() external payable {}
}

/// Paymaster: accepts only from the EntryPoint and, like the Railgun verifier, only takes a
/// dummy proof when tx.origin is the bypass address.
contract MockPaymaster {
    bool public paid;
    uint256 public postOps;
    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256 maxCost)
        external returns (bytes memory context, uint256 validationData)
    {
        require(msg.sender == ENTRY_POINT, "paymaster: not from EntryPoint");
        require(tx.origin == BYPASS, "paymaster: proof rejected");
        require(maxCost != 666, "paymaster: insufficient fee");
        uint256 x; unchecked { for (uint256 i = 0; i < 400; i++) { x += uint256(keccak256(abi.encode(i))); } }
        paid = true;
        return (maxCost == 1 ? bytes("") : abi.encode(x), 0);
    }
    function postOp(uint8, bytes calldata, uint256, uint256) external {
        require(msg.sender == ENTRY_POINT, "paymaster: not from EntryPoint");
        postOps += 1;
    }
}
