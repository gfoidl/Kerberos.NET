using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal sealed class Sha256 : IHashAlgorithm
    {
        private const int HashSize = 256;

        public int HashSizeInBytes
        {
            get
            {
#if DEBUG
                using (var hash = SHA256.Create())
                {
                    Debug.Assert(hash.HashSize == HashSize);
                }
#endif

                return HashSize / 8;
            }
        }

        public bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            using var alogithm = SHA256.Create();

            return alogithm.TryComputeHash(data, hash, out bytesWritten);
        }

        public void Dispose() { }
    }
}
