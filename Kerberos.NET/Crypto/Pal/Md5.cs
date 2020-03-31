using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal sealed class Md5 : IHashAlgorithm
    {
        private const int HashSize = 128;

        public int HashSizeInBytes
        {
            get
            {
#if DEBUG
                using (var hash = MD5.Create())
                {
                    Debug.Assert(hash.HashSize == HashSize);
                }
#endif

                return HashSize / 8;
            }
        }

        public bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            using var alogithm = MD5.Create();

            return alogithm.TryComputeHash(data, hash, out bytesWritten);
        }

        public void Dispose() { }
    }
#endif
}
