using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public abstract class PalHashAlgorithm : IHashAlgorithm
    {
        protected readonly HashAlgorithm _algorithm;

        protected PalHashAlgorithm(HashAlgorithm algorithm)
        {
            _algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        }

        public int HashSizeInBytes => _algorithm.HashSize / 8;

        public bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
            => _algorithm.TryComputeHash(data, hash, out bytesWritten);

        public void Dispose() => Dispose(true);

        protected virtual void Dispose(bool disposing) => _algorithm.Dispose();
    }
}
