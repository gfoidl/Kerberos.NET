#if NETSTANDARD2_1
using System;
using System.Diagnostics;
using System.Security.Cryptography;
#endif

namespace Kerberos.NET.Crypto
{
    public interface IHmacAlgorithm
    {
        int HashSizeInBytes { get; }

#if NETSTANDARD2_1
        bool TryComputeHash(byte[] key, ReadOnlySpan<byte> data, Span<byte> dest, out int bytesWritten);

        byte[] ComputeHash(byte[] key, ReadOnlySpan<byte> data)
        {
            var hash = new byte[HashSizeInBytes];

            if (TryComputeHash(key, data, hash, out int written))
            {
                Debug.Assert(written == hash.Length);
                return hash;
            }

            throw new CryptographicException();
        }
#elif NETSTANDARD2_0
        byte[] ComputeHash(byte[] key, byte[] data);
#else
#warning Update Tfms
#endif
    }
}
