using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public interface IHashAlgorithm : IDisposable
    {
        int HashSizeInBytes { get; }

        bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten);

        ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            byte[] hash = new byte[HashSizeInBytes];

            if (TryComputeHash(data, hash, out int written))
            {
                Debug.Assert(written == hash.Length);
                return hash;
            }

            throw new CryptographicException();
        }
    }
}
