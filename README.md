[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/HKDF.NET/blob/main/LICENSE)
[![CodeQL](https://github.com/samuel-lucas6/HKDF.NET/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/samuel-lucas6/HKDF.NET/actions)

# HKDF.NET
A .NET implementation of [HKDF](https://tools.ietf.org/html/rfc5869), with support for [SHA256](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256?view=net-5.0), [SHA384](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384?view=net-5.0), and [SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512?view=net-5.0).

## Usage
### ⚠️Warnings
1. HKDF is **NOT** suitable for passwords. You **MUST** use a password hashing/password-based KDF algorithm, such as [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) or [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), for such purposes. Both algorithms are available in the [libsodium](https://doc.libsodium.org/password_hashing) library.
2. The info **SHOULD** be independent of the input keying material (IKM). Moreover, although this parameter is optional, it **SHOULD** almost always be used to bind derived keys to application- and context-specific information. Inadequate context information **CAN** lead to subtle vulnerabilities.
3. The salt **SHOULD** be independent of the input keying material (IKM). Furthermore, despite the salt parameter being optional, you **SHOULD** use a random 128-bit or 256-bit salt when possible because it improves the strength of HKDF. A secret salt (e.g. derived from a pre-shared key) provides an even stronger security guarantee.

### Functions
HKDF consists of three different functions:
1. `DeriveKey()`: if the input keying material (IKM) is **not** distributed uniformly (e.g. a shared secret from a key exchange) and you want to derive one or more keys using the **same** context information for all of those keys, then you should use this function. This calls the `Extract()` and `Expand()` functions internally.
2. `Extract()`: if the input keying material (IKM) is **not** distributed uniformly (e.g. a shared secret from a key exchange) and you want to derive one or more keys using **different** context information for different keys, then you should call this function **once** to derive a pseudorandom key. Then you can call `Expand()` on the output to derive multiple subkeys, as explained below.
3. `Expand()`: if the input keying material (IKM) **is** distributed uniformly (e.g. the output of `Extract()` or randomly generated using a cryptographically secure random number generator), then you can call this function **multiple** times to derive separate subkeys using **different** context information.

### Parameters
Here are my recommendations:
- Hash algorithm: use SHA512 in all cases.
- Input keying material: at least 256-bits long and **MUST** be high-entropy (e.g. a shared secret, **NOT** a password).
- Output length: at least 256-bits, which is equivalent to 32 bytes. If deriving multiple keys using one call to `DeriveKey()`, then use an output length as long as the required key lengths added together (e.g. a 256-bit encryption key and a 512-bit MAC key means a 96 byte output length).
- Salt: randomly generated and 128-bits or 256-bits long. Alternatively, it may be possible to use a secret salt in rare cases (e.g. derived from a secret nonce or a pre-shared key).
- Info: a hardcoded, globally unique, application-specific string converted into a byte array using UTF8 encoding. The default format should be `[application] [date and time] [purpose]`. However, info may contain things that do not fit this format, such as protocol/version numbers, algorithm identifiers, and user identities. Multiple pieces of context information can be concatenated together using [Array.Copy()](https://github.com/samuel-lucas6/Kryptor/blob/090f4034674e9da668287dc627b1e38d96d81a86/src/KryptorCLI/GeneralPurpose/Arrays.cs#L31).

### Example
Here is a code example to derive a 256-bit key for an AEAD, followed by how to derive two separate keys for Encrypt-then-MAC, using an [X25519](https://datatracker.ietf.org/doc/html/rfc7748) shared secret as the input keying material (IKM), a random 128-bit salt, and hardcoded info/context strings:

```c#
const int outputLength = 32;
const int saltLength = 16;
const string context = "HKDF Demo 15/11/2021 21:52 Deriving an encryption key for ChaCha20-Poly1305";

// The high-entropy input keying material (not a password) that you want to derive subkeys from
byte[] inputKeyingMaterial = GetSharedSecret(senderPrivateKey, recipientPublicKey);

// The optional, typically non-secret salt. A random 128-bit or 256-bit salt is recommended
byte[] salt = SecureRandom.GetBytes(saltLength);

// The optional, hardcoded, globally unique, and application-specific context information
byte[] info = Encoding.UTF8.GetBytes(context);

// Derive a single subkey (e.g. for encryption with an AEAD, like ChaCha20-Poly1305 or AES-GCM)
byte[] subkey = Hkdf.DeriveKey(HashAlgorithmName.SHA512, inputKeyingMaterial, outputLength, salt, info);

// Or derive multiple subkeys (e.g. for Encrypt-then-MAC)
byte[] pseudorandomKey = Hkdf.Extract(HashAlgorithmName.SHA512, inputKeyingMaterial, salt);

byte[] encryptionInfo = Encoding.UTF8.GetBytes("HKDF Demo 15/11/2021 21:54 ChaCha20 encryption key");
byte[] encryptionKey = Hkdf.Expand(HashAlgorithmName.SHA512, pseudorandomKey, outputLength, encryptionInfo);

byte[] macInfo = Encoding.UTF8.GetBytes("HKDF Demo 15/11/2021 21:55 BLAKE2b MAC key");
byte[] macKey = Hkdf.Expand(HashAlgorithmName.SHA512, pseudorandomKey, outputLength * 2, macInfo);
```
