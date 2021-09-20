using System;
using System.Security.Cryptography;

/*
    HKDF.NET: A .NET implementation of HKDF.
    Copyright (c) 2021 Samuel Lucas

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace HkdfDotNet
{
    public static class Hkdf
    {
        public static byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] inputKeyingMaterial, int outputLength, byte[] salt = null, byte[] info = null)
        {
            byte[] key = Extract(hashAlgorithmName, inputKeyingMaterial, salt);
            return Expand(hashAlgorithmName, key, outputLength, info);
        }

        public static byte[] Extract(HashAlgorithmName hashAlgorithmName, byte[] inputKeyingMaterial, byte[] salt = null)
        {
            if (salt == null) { salt = Array.Empty<byte>(); }
            using (var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, salt))
            {
                hmac.AppendData(inputKeyingMaterial);
                return hmac.GetHashAndReset();
            }
        }

        public static byte[] Expand(HashAlgorithmName hashAlgorithmName, byte[] key, int outputLength, byte[] info = null)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Key cannot be null."); }
            if (info == null) { info = Array.Empty<byte>(); }
            int hashLength = GetHashLength(hashAlgorithmName);
            if (hashLength == 0) { throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName), "Please specify a SHA2 algorithm."); }
            if (outputLength == 0 || outputLength > 255 * hashLength) { throw new ArgumentOutOfRangeException(nameof(outputLength), $"Output length must be greater than 0 and less than 255 * {hashLength}."); }
            int iterations = (int)Math.Ceiling((double)outputLength / hashLength);
            var counter = new byte[1];
            var previousHash = Array.Empty<byte>();
            var outputKeyingMaterial = new byte[outputLength];
            int bytesWritten = 0;
            using (var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, key))
            {
                for (int i = 1; i <= iterations; i++)
                {
                    counter[0] = (byte)i;
                    hmac.AppendData(previousHash);
                    hmac.AppendData(info);
                    hmac.AppendData(counter);
                    previousHash = hmac.GetHashAndReset();
                    Array.Copy(previousHash, sourceIndex: 0, outputKeyingMaterial, bytesWritten, (i != iterations) ? previousHash.Length : outputLength - bytesWritten);
                    bytesWritten += hashLength;
                }
            }
            return outputKeyingMaterial;
        }

        private static int GetHashLength(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA256) { return 32; }
            if (hashAlgorithmName == HashAlgorithmName.SHA384) { return 48; }
            if (hashAlgorithmName == HashAlgorithmName.SHA512) { return 64; }
            return 0;
        }
    }
}
