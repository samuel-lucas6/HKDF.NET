using System;
using System.Security.Cryptography;
using Sodium;
using HkdfDotNet;

/*
    HKDF.NET: A .NET implementation of HKDF.
    Copyright (c) 2021-2022 Samuel Lucas

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

namespace HkdfTest
{
    class Program
    {
        private const string Success = "Success";
        private const string Fail = "Fail";

        static void Main(string[] _)
        {
            // https://tools.ietf.org/html/rfc5869 - Appendix A. Test Vectors (SHA-256)
            TestCase1();
            TestCase2();
            TestCase3();
            Console.ReadLine();
        }

        private static void TestCase1()
        {
            byte[] inputKeyingMaterial = Utilities.HexToBinary("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] salt = Utilities.HexToBinary("000102030405060708090a0b0c");
            byte[] info = Utilities.HexToBinary("f0f1f2f3f4f5f6f7f8f9");
            int outputLength = 42;

            string expectedPrk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
            string expectedOkm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
            string actualPrk = Utilities.BinaryToHex(Hkdf.Extract(HashAlgorithmName.SHA256, inputKeyingMaterial, salt));
            string actualOkm = Utilities.BinaryToHex(Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyingMaterial, outputLength, info, salt));

            Console.WriteLine($"Test 1.1: {(expectedPrk == actualPrk ? Success : Fail)}");
            Console.WriteLine($"Test 1.2: {(expectedOkm == actualOkm ? Success : Fail)}");
        }

        private static void TestCase2()
        {
            byte[] inputKeyingMaterial = Utilities.HexToBinary("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
            byte[] salt = Utilities.HexToBinary("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            byte[] info = Utilities.HexToBinary("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            int outputLength = 82;

            string expectedPrk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
            string expectedOkm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";
            string actualPrk = Utilities.BinaryToHex(Hkdf.Extract(HashAlgorithmName.SHA256, inputKeyingMaterial, salt));
            string actualOkm = Utilities.BinaryToHex(Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyingMaterial, outputLength, info, salt));

            Console.WriteLine($"Test 2.1: {(expectedPrk == actualPrk ? Success : Fail)}");
            Console.WriteLine($"Test 2.2: {(expectedOkm == actualOkm ? Success : Fail)}");
        }

        private static void TestCase3()
        {
            byte[] inputKeyingMaterial = Utilities.HexToBinary("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var salt = Array.Empty<byte>();
            var info = Array.Empty<byte>();
            int outputLength = 42;

            string expectedPrk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";
            string expectedOkm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";
            string actualPrk = Utilities.BinaryToHex(Hkdf.Extract(HashAlgorithmName.SHA256, inputKeyingMaterial, salt));
            string actualOkm = Utilities.BinaryToHex(Hkdf.DeriveKey(HashAlgorithmName.SHA256, inputKeyingMaterial, outputLength, info, salt));

            Console.WriteLine($"Test 3.1: {(expectedPrk == actualPrk ? Success : Fail)}");
            Console.WriteLine($"Test 3.2: {(expectedOkm == actualOkm ? Success : Fail)}");
        }
    }
}
