[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/HKDF.NET/blob/main/LICENSE)
[![CodeQL](https://github.com/samuel-lucas6/HKDF.NET/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/samuel-lucas6/HKDF.NET/actions)

# HKDF.NET
A .NET implementation of [HKDF](https://tools.ietf.org/html/rfc5869), with support for [SHA256](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256?view=net-6.0), [SHA384](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384?view=net-6.0), and [SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512?view=net-6.0).

## Installation
### NuGet
You can find the NuGet package [here](https://www.nuget.org/packages/HkdfDotNet).

The easiest way to install this is via the NuGet Package Manager in [Visual Studio](https://visualstudio.microsoft.com/vs/), as explained [here](https://docs.microsoft.com/en-us/nuget/quickstart/install-and-use-a-package-in-visual-studio). [JetBrains Rider](https://www.jetbrains.com/rider/) also has a package manager, and instructions can be found [here](https://www.jetbrains.com/help/rider/Using_NuGet.html).

### Manual
1. Download the latest [release](https://github.com/samuel-lucas6/HKDF.NET/releases/latest).
2. Move the downloaded `.dll` file into your project folder.
3. Click on the `Project` tab and `Add Project Reference...` in Visual Studio.
4. Go to `Browse`, click the `Browse` button, and select the downloaded `.dll` file.
5. Add `using HkdfDotNet;` to the top of each code file that needs the library.

## Usage
### ⚠️Warnings
1. HKDF is **NOT** suitable for passwords. You **MUST** use a password-based KDF algorithm, such as [Argon2](https://www.rfc-editor.org/rfc/rfc9106.html) or [scrypt](https://datatracker.ietf.org/doc/html/rfc7914), for such purposes. Both algorithms are available in the [libsodium](https://doc.libsodium.org/password_hashing) library.
2. Although the `info` parameter is optional according to the specification, it **SHOULD** always be used to insert some randomness into HKDF and to bind derived keys to application- and context-specific information. Inadequate context information **CAN** lead to subtle vulnerabilities. The info **SHOULD** be independent of the input keying material (IKM).
3. The `salt` parameter **SHOULD NOT** be used. You **SHOULD** randomly generate one 128-bit or 256-bit salt that gets used for all derived subkeys but placed into the `info` parameter alongside other context information using [concatenation](https://github.com/samuel-lucas6/Kryptor/blob/5a2dc250ac801b3da701464cdc12b041a1d0e201/src/KryptorCLI/GeneralPurpose/Arrays.cs#L30). Make sure you **AVOID** [canonicalization attacks](https://github.com/samuel-lucas6/Cryptography-Guidelines#notes-2) when doing this.

### Functions
HKDF consists of three different functions:
1. `DeriveKey()`: if the input keying material (IKM) is **not** distributed uniformly (e.g. a shared secret from a key exchange) and you want to derive one or more keys using the **same** context information for all of those keys, then you should use this function. This calls the `Extract()` and `Expand()` functions internally.
2. `Extract()`: if the input keying material (IKM) is **not** distributed uniformly (e.g. a shared secret from a key exchange) and you want to derive one or more keys using **different** context information for different keys, then you should call this function **once** to derive a pseudorandom key. Then you can call `Expand()` on the output to derive multiple subkeys, as explained below.
3. `Expand()`: if the input keying material (IKM) **is** distributed uniformly (e.g. the output of `Extract()` or randomly generated using a cryptographically secure random number generator), then you can call this function **multiple** times to derive separate subkeys using **different** context information but the **same** randomly generated salt.

### Parameters
Here are my recommendations:
- `HashAlgorithmName`: use SHA512 in all cases.
- `inputKeyingMaterial`: at least 256-bits long and **MUST** be high-entropy (e.g. a shared secret, **NOT** a password).
- `outputLength`: at least 256-bits, which is equivalent to 32 bytes. If deriving multiple keys using one call to `DeriveKey()`, then use an output length as long as the required key lengths added together (e.g. a 256-bit encryption key and a 512-bit MAC key means a 96 byte output length).
- `salt`: [leave this null](https://soatok.blog/2021/11/17/understanding-hkdf/) to get the [standard security definition](https://github.com/paseto-standard/paseto-spec/blob/dfd1115170724b056b3c1ac722239cf7084755a8/docs/Rationale-V3-V4.md#better-use-of-hkdf-salts-change) for HKDF. Randomly generate **one** 128-bit or 256-bit salt for **all** subkeys and concatenate it to the `info` parameter instead, as explained below.
- `info`: **one** randomly generated 128-bit or 256-bit salt used for **all** subkeys, followed by a **different** hardcoded, globally unique, application-specific string for **each** subkey converted into a byte array using UTF8 encoding. The default context string format should be `"[application] [date and time] [purpose]"`. You can also include things like protocol/version numbers, algorithm identifiers, and user identities. The salt and context information should be concatenated together using [Array.Copy()](https://github.com/samuel-lucas6/Kryptor/blob/5a2dc250ac801b3da701464cdc12b041a1d0e201/src/KryptorCLI/GeneralPurpose/Arrays.cs#L30) in a way that is resistant to [canonicalization attacks](https://github.com/samuel-lucas6/Cryptography-Guidelines#notes-2) (please see that link and the code example below).

### Example
Here is an example of how to derive a 256-bit key for an AEAD, followed by how to derive two separate keys for Encrypt-then-MAC, using an [X25519](https://datatracker.ietf.org/doc/html/rfc7748) shared secret as the input keying material (IKM), a random 128-bit salt, and hardcoded context strings:

```c#
const int saltLength = 16;
const string context = "HKDF Demo 15/11/2021 21:52 Deriving an encryption key for ChaCha20-Poly1305";
const int outputLength = 32;

// The high-entropy input keying material (NOT a password) that you want to derive subkeys from
byte[] inputKeyingMaterial = GetSharedSecret(senderPrivateKey, recipientPublicKey);

// A random 128-bit or 256-bit salt to feed into info
byte[] salt = SecureRandom.GetBytes(saltLength);

// The hardcoded, globally unique, and application-specific context information
byte[] info = Encoding.UTF8.GetBytes(context);

// Convert the length of each parameter to concatenate in info into bytes
byte[] saltLength = BitConversion.GetBytes(salt.Length);
byte[] infoLength = BitConversion.GetBytes(info.Length);

// Concatenate the salt, info, and lengths
info = Arrays.Concat(salt, info, saltLength, infoLength);

// Derive a single subkey (e.g. for encryption with an AEAD, like ChaCha20-Poly1305 or AES-GCM)
byte[] subkey = Hkdf.DeriveKey(HashAlgorithmName.SHA512, inputKeyingMaterial, outputLength, info);

// Or derive multiple subkeys (e.g. for Encrypt-then-MAC)
byte[] pseudorandomKey = Hkdf.Extract(HashAlgorithmName.SHA512, inputKeyingMaterial);

byte[] encryptionInfo = Encoding.UTF8.GetBytes("HKDF Demo 15/11/2021 21:54 ChaCha20 encryption key");
byte[] encryptionInfoLength = BitConversion.GetBytes(encryptionInfo.Length);
encryptionInfo = Arrays.Concat(salt, encryptionInfo, saltLength, encryptionInfoLength);
byte[] encryptionKey = Hkdf.Expand(HashAlgorithmName.SHA512, pseudorandomKey, outputLength, encryptionInfo);

byte[] macInfo = Encoding.UTF8.GetBytes("HKDF Demo 15/11/2021 21:55 BLAKE2b MAC key");
byte[] macInfoLength = BitConversion.GetBytes(macInfo.Length);
macInfo = Arrays.Concat(salt, macInfo, saltLength, macInfoLength);
byte[] macKey = Hkdf.Expand(HashAlgorithmName.SHA512, pseudorandomKey, outputLength * 2, macInfo);
```

Note that the `Arrays.Concat()` function looks like [this](https://github.com/samuel-lucas6/Kryptor/blob/5a2dc250ac801b3da701464cdc12b041a1d0e201/src/KryptorCLI/GeneralPurpose/Arrays.cs#L30), and the `BitConversion.GetBytes()` function looks like [this](https://github.com/samuel-lucas6/Kryptor/blob/5a2dc250ac801b3da701464cdc12b041a1d0e201/src/KryptorCLI/GeneralPurpose/BitConversion.cs#L27).
