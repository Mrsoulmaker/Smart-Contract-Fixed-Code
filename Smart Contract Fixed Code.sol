// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS
    }

    error ECDSAInvalidSignature();
    error ECDSAInvalidSignatureLength(uint256 length);
    error ECDSAInvalidSignatureS(bytes32 s);

    function tryRecover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly ("memory-safe") {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}

contract UserManagement {
    using ECDSA for bytes32;

    mapping(address => bool) public isAdmin;
    mapping(address => bool) public isRegularUser;

    event UsersAdded(address[] admins, address[] regularUsers);

    constructor() {
        isAdmin[msg.sender] = true; 
    }

    function addUsers(
        address[] calldata admins,
        address[] calldata regularUsers,
        bytes calldata signature
    ) external {
        if (!isAdmin[msg.sender]) {
            bytes32 hash = keccak256(abi.encodePacked(admins, regularUsers));
            bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

            address signer = ethSignedHash.recover(signature);
            require(isAdmin[signer], "Only admins can add users.");
        }
        require(admins.length > 0 || regularUsers.length > 0, "No users to add.");
        
        for (uint256 i = 0; i < admins.length; i++) {
            require(!isAdmin[admins[i]], "Admin already exists.");
            isAdmin[admins[i]] = true;
        }

        for (uint256 i = 0; i < regularUsers.length; i++) {
            require(!isRegularUser[regularUsers[i]], "User already exists.");
            isRegularUser[regularUsers[i]] = true;
        }
        emit UsersAdded(admins, regularUsers);
    }
}
