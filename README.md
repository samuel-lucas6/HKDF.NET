[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/HKDF.NET/blob/main/LICENSE)
[![CodeQL](https://github.com/samuel-lucas6/HKDF.NET/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/samuel-lucas6/HKDF.NET/actions)

# HKDF.NET
A .NET implementation of [HKDF](https://tools.ietf.org/html/rfc5869) with support for [SHA256](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256?view=net-5.0), [SHA384](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha384?view=net-5.0), and [SHA512](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512?view=net-5.0).

## Usage
For information about the different functions (DeriveKey, Expand, and Extract), please see the [.NET documentation](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hkdf?view=net-5.0) and [RFC](https://datatracker.ietf.org/doc/html/rfc5869).

```c#
const int masterKeyLength = 32;
const int saltLength = 16;
const int outputLength = 32;
const string context = "[application] [date and time] [purpose]";

// The high-entropy master key (not a password) that you want to derive subkeys from
byte[] inputKeyingMaterial = SecureRandom.GetBytes(masterKeyLength);

// The optional, typically non-secret salt. A random 128-bit or 256-bit salt is recommended
byte[] salt = SecureRandom.GetBytes(saltLength);

// The optional, hardcoded, globally unique, and application specific context information
byte[] info = Encoding.UTF8.GetBytes(context);

// Perform HKDF Expand and Extract to derive a subkey
byte[] subkey = HKDF.DeriveKey(HashAlgorithmName.SHA512, inputKeyingMaterial, outputLength, salt, info);
```
