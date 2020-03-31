using System;

#if NETSTANDARD2_1
using System.Diagnostics;
using System.Security.Cryptography;
#endif

namespace Kerberos.NET.Crypto
{
    public interface IHashAlgorithm : IDisposable
    {
        int HashSizeInBytes { get; }

        bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten);

#if NETSTANDARD2_1
        byte[] ComputeHash(ReadOnlySpan<byte> data)
        {
            var hash = new byte[HashSizeInBytes];

            if (TryComputeHash(data, hash, out int written))
            {
                Debug.Assert(written == hash.Length);
                return hash;
            }

            throw new CryptographicException();
        }
#elif NETSTANDARD2_0
        byte[] ComputeHash(byte[] data);
#else
#warning Update Tfms
#endif
    }
}
