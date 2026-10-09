// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Stand-in for the ERC-4337 EntryPoint during an eth_call: a state override puts this code at
/// the EntryPoint address, so accounts and paymasters see their expected caller, while the call
/// itself comes from an origin of the simulator's choosing. It runs the phases of one
/// UserOperation in EntryPoint order and reports the gas each one used. It holds no state and
/// has no constructor, which is what makes it usable as overridden code.
contract ValidationProbe {
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    struct Result {
        uint256 accountValidationGas;
        uint256 paymasterValidationGas;
        uint256 callGas;
        uint256 postOpGas;
        bool accountValidated;
        bool paymasterValidated;
        bool callSucceeded;
        bool postOpCalled;
        bytes paymasterError;
        bytes callError;
        // Smallest gas limit with which the execution call succeeds, found by search. The gas
        // used is not a limit: a value transfer must have 9000 gas at hand (34000 towards a new
        // account) that it then hands back, and each nested call keeps 1/64 in reserve.
        uint256 callGasLimit;
    }

    uint256 private constant SEARCH_START = 30_000;
    uint256 private constant SEARCH_CEILING = 8_000_000;
    uint256 private constant SEARCH_PRECISION = 1_000;

    /// One trial of the execution call under `gasLimit`. Always reverts, so that the state is
    /// the same for every trial and for the real call; the outcome travels in the revert data.
    function attempt(address sender, bytes calldata callData, uint256 gasLimit) external {
        require(msg.sender == address(this), "probe: internal");
        (bool ok, ) = sender.call{gas: gasLimit}(callData);
        bytes memory out = abi.encode(ok);
        assembly { revert(add(out, 32), mload(out)) }
    }

    function _succeedsWith(address sender, bytes calldata callData, uint256 gasLimit) private returns (bool) {
        // The trial must really be able to forward `gasLimit`.
        if (gasleft() < gasLimit + gasLimit / 32 + 50_000) return false;
        try this.attempt(sender, callData, gasLimit) {
            return false;
        } catch (bytes memory data) {
            return data.length == 32 && abi.decode(data, (bool));
        }
    }

    function _minimalCallGas(address sender, bytes calldata callData) private returns (uint256) {
        uint256 high = SEARCH_START;
        while (!_succeedsWith(sender, callData, high)) {
            if (high >= SEARCH_CEILING) return 0;
            high *= 2;
        }
        uint256 low = high == SEARCH_START ? 0 : high / 2;
        while (high - low > SEARCH_PRECISION) {
            uint256 mid = (low + high) / 2;
            if (_succeedsWith(sender, callData, mid)) high = mid; else low = mid;
        }
        return high;
    }

    function probe(PackedUserOperation calldata op, bytes32 userOpHash, uint256 maxCost)
        external
        returns (Result memory r)
    {
        uint256 g = gasleft();
        (bool ok, ) = op.sender.call(
            abi.encodeWithSignature(
                "validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32,uint256)",
                op, userOpHash, uint256(0)
            )
        );
        r.accountValidationGas = g - gasleft();
        r.accountValidated = ok;

        bytes memory context;
        if (op.paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(op.paymasterAndData[:20]));
            g = gasleft();
            bytes memory ret;
            (ok, ret) = paymaster.call(
                abi.encodeWithSignature(
                    "validatePaymasterUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32,uint256)",
                    op, userOpHash, maxCost
                )
            );
            r.paymasterValidationGas = g - gasleft();
            r.paymasterValidated = ok;
            if (ok) {
                (context, ) = abi.decode(ret, (bytes, uint256));
            } else {
                r.paymasterError = ret;
            }

            if (op.callData.length > 0) {
                // Before the real call, while the state is what the paymaster left.
                if (ok) r.callGasLimit = _minimalCallGas(op.sender, op.callData);
                g = gasleft();
                (r.callSucceeded, ret) = op.sender.call(op.callData);
                r.callGas = g - gasleft();
                if (!r.callSucceeded) r.callError = ret;
            } else {
                r.callSucceeded = true;
            }

            if (context.length > 0) {
                r.postOpCalled = true;
                g = gasleft();
                // opSucceeded = 0, actual cost = the maximum: the most a refund path can do.
                (ok, ) = paymaster.call(
                    abi.encodeWithSignature(
                        "postOp(uint8,bytes,uint256,uint256)", uint8(0), context, maxCost, uint256(1)
                    )
                );
                r.postOpGas = g - gasleft();
            }
        }
    }
}
