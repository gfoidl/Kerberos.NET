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

#if NETSTANDARD2_1
        public bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
            => _algorithm.TryComputeHash(data, hash, out bytesWritten);
#elif NETSTANDARD2_0
        public virtual bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
            => throw new PlatformNotSupportedException();

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data)
            => _algorithm.ComputeHash(data.TryGetArrayFast());
#else
#warning Update Tfms
#endif

        public void Dispose() => Dispose(true);

        protected virtual void Dispose(bool disposing) => _algorithm.Dispose();
    }
}
