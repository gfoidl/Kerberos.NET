using System.Security.Cryptography;

#if NETSTANDARD2_1
using System;
#endif

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : IHmacAlgorithm
    {
        public int HashSizeInBytes => 20;

#if NETSTANDARD2_1
        public bool TryComputeHash(byte[] key, ReadOnlySpan<byte> data, Span<byte> dest, out int bytesWritten)
        {
            using var hmac = new HMACSHA1(key);

            return hmac.TryComputeHash(data, dest, out bytesWritten);
        }
#elif NETSTANDARD2_0
        public byte[] ComputeHash(byte[] key, byte[] data)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(data);
        }
#else
#warning Update Tfms
#endif
    }
}
