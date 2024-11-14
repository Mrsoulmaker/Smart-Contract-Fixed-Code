## Introdution
 
In Solidity, you can use the abi.encodePacked() function to create a tightly packed byte array that can then be hashed using keccak256().

However, using this function with multiple variable length arguments is dangerous because it can result in hash collisions. These collisions can be exploited in scenarios such as signature verification, allowing attackers to bypass authentication mechanisms.
**Hash Collision** is a situation where two different sets of inputs produce the same hash output. In this context, using abi.encodePacked() with multiple arguments of variable length can result in hash collisions, allowing an attacker to create different inputs that produce the same hash.

## Understanding the vulnerability

When abi.encodePacked() is used with multiple variable length arguments (such as arrays or strings), the packed encoding does not contain any information about the boundaries between the different arguments, which can lead to situations where different combinations of arguments result in the same encoded output, resulting in hash collisions.

For example, consider the following two calls to `abi.encodePacked()`:

```solidity
abi.encodePacked(["a", "b"], ["c", "d"])
```

```solidity
abi.encodePacked(["a"], ["b", "c", "d"])
```

Both calls could potentially produce the same packed encoding because `abi.encodePacked()` simply concatenates the elements without any delimiters!

Consider the below example for strings:

```solidity
abi.encodePacked("foo", "bar") == abi.encodePacked("fo", "obar")
```

Strings in Solidity are dynamic types and when they are concatenated using `abi.encodePacked()`, there is no delimiter between them to mark their boundaries, which can lead to hash collisions.

```solidity
/// INSECURE
function addUsers(address[] calldata admins, address[] calldata regularUsers, bytes calldata signature) external {
    if (!isAdmin[msg.sender]) {
        bytes32 hash = keccak256(abi.encodePacked(admins, regularUsers));
        address signer = hash.toEthSignedMessageHash().recover(signature);
        require(isAdmin[signer], "Only admins can add users.");
    }
    for (uint256 i = 0; i < admins.length; i++) {
        isAdmin[admins[i]] = true;
    }
    for (uint256 i = 0; i < regularUsers.length; i++) {
        isRegularUser[regularUsers[i]] = true;
    }
}

In the provided sample code above, the `addUsers` function uses `abi.encodePacked(admins, regularUsers)` to generate a hash. An attacker could exploit this by rearranging elements between the `admins` and `regularUsers` arrays, resulting in the same hash and thereby bypassing authorization checks.

```solidity

/// INSECURE
function verifyMessage(string calldata message1, string calldata message2, bytes calldata signature) external {
    bytes32 hash = keccak256(abi.encodePacked(message1, message2));
    address signer = hash.toEthSignedMessageHash().recover(signature);
    require(isAuthorized[signer], "Unauthorized signer");
}
```

The above function `verifyMessage()` could easily be exploited as below:-

```solidity
verifyMessage("hello", "world", signature);
```
or

```solidity
verifyMessage("hell", "oworld", signature);
```

or a variation of the string `hello` `world`

All variations of the string `hello` `world` passed to `verifyMessage()` would produce the same hash, potentially allowing an attacker to bypass the authorization check if they can provide a valid signature for their manipulated inputs.

**Fixed Code Using Single User:**

```solidity
function addUser(address user, bool admin, bytes calldata signature) external {
    if (!isAdmin[msg.sender]) {
        bytes32 hash = keccak256(abi.encodePacked(user));
        address signer = hash.toEthSignedMessageHash().recover(signature);
        require(isAdmin[signer], "Only admins can add users.");
    }
    if (admin) {
        isAdmin[user] = true;
    } else {
        isRegularUser[user] = true;
    }
}
```

This approach eliminates the use of variable-length arrays, thus avoiding the hash collision issue entirely by dealing with a single user at a time.

**Fixed Code Using Fixed-Length Arrays:**

```solidity
function addUsers(address[3] calldata admins, address[3] calldata regularUsers, bytes calldata signature) external {
    if (!isAdmin[msg.sender]) {
        bytes32 hash = keccak256(abi.encodePacked(admins, regularUsers));
        address signer = hash.toEthSignedMessageHash().recover(signature);
        require(isAdmin[signer], "Only admins can add users.");
    }
    for (uint256 i = 0; i < admins.length; i++) {
        isAdmin[admins[i]] = true;
    }
    for (uint256 i = 0; i < regularUsers.length; i++) {
        isRegularUser[regularUsers[i]] = true;
    }
}
```

In this version, fixed-length arrays are used, which mitigates the risk of hash collisions since the encoding is unambiguous.

## Excution 

![Screenshot (8)](https://github.com/user-attachments/assets/3b90afaf-e327-4fa3-810a-9e9e171021c6)

![Screenshot (9)](https://github.com/user-attachments/assets/f423c9f2-10e1-453d-875b-33cd0c467264)




## Remediation Strategies

To prevent this type of hash collision, the below remediation strategies can be employed:

1. **Avoid Variable-Length Arguments**: Avoid using `abi.encodePacked()` with variable-length arguments such as arrays and strings. Instead, use fixed-length arrays to ensure the encoding is unique and unambiguous.

2. **Use `abi.encode()` Instead**: Unlike `abi.encodePacked()`, `abi.encode()` includes additional type information and length prefixes in the encoding, making it much less prone to hash collisions. Switching from `abi.encodePacked()` to `abi.encode()` is a simple yet effective fix.
   
> [!IMPORTANT]
> Replay Protection does not protect against possible hash collisions!
> 
> It is listed here as a defense in depth strategy and SHOULD NOT be solely relied upon to protect against said vulnerability

3. **Replay Protection**: Implement replay protection mechanisms to prevent attackers from reusing valid signatures. This can involve including nonces or timestamps in the signed data. However, this does not completely eliminate the risk of hash collisions but adds an additional layer of security.


## Sources
- [Smart Contract Weakness Classification #133](https://swcregistry.io/docs/SWC-133/)
- [Solidity Non-standard Packed Mode](https://docs.soliditylang.org/en/latest/abi-spec.html#non-standard-packed-mode)
