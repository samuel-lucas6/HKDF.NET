[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/Geralt/blob/main/LICENSE)

# HKDF.NET
A .NET implementation of [HKDF](https://tools.ietf.org/html/rfc5869) with support for [SHA256](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256?view=net-5.0), [SHA384](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384?view=net-5.0), and [SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512?view=net-5.0).

## Usage
```c#
const int masterKeyLength = 32;
const int outputLength = 32;
const string context = "MyApplicationName";

// The master key that you want to derive subkeys from
byte[] inputKeyingMaterial = SodiumCore.GetRandomBytes(masterKeyLength);

// The optional, non-secret salt. A random salt as long as the hash output length is recommended
byte[] salt = SodiumCore.GetRandomBytes(outputLength);

// The optional context and application specific information
byte[] info = Encoding.UTF8.GetBytes(context);

// Perform HKDF Expand and Extract to derive a subkey
byte[] subkey = HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyingMaterial, outputLength, salt, info);
```
