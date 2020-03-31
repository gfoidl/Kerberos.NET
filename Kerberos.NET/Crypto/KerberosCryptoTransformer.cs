using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public enum KeyDerivationMode : byte
    {
        Kc = 0x99,
        Ke = 0xAA,
        Ki = 0x55
    }

    public abstract class KerberosCryptoTransformer
    {
        private static readonly RandomNumberGenerator s_rng = RandomNumberGenerator.Create();

        public abstract int ChecksumSize { get; }

        public abstract int BlockSize { get; }

        public abstract int KeySize { get; }

#if NETSTANDARD2_1
        public virtual void GenerateKey(Span<byte> dest) => GenerateRandomBytes(KeySize, dest);
#elif NETSTANDARD2_0
        public virtual byte[] GenerateKey() => GenerateRandomBytes(KeySize);
#else
#warning Update Tfms
#endif

        public abstract byte[] String2Key(KerberosKey key);
        public abstract byte[] Encrypt(byte[] data, KerberosKey key, KeyUsage usage);
        public abstract byte[] Decrypt(byte[] cipher, KerberosKey key, KeyUsage usage);


#if NETSTANDARD2_1
        public virtual void GenerateRandomBytes(int size, Span<byte> dest) => s_rng.GetBytes(dest.Slice(0, size));
#elif NETSTANDARD2_0
        public virtual byte[] GenerateRandomBytes(int size)
        {
            var arr = new byte[size];

            s_rng.GetBytes(arr);

            return arr;
        }
#else
#warning Update Tfms
#endif

        public virtual byte[] MakeChecksum(byte[] data, KerberosKey key, KeyUsage usage, KeyDerivationMode kdf, int hashSize)
        {
            throw new NotImplementedException();
        }

        public virtual void MakeChecksum(byte[] key, ReadOnlySpan<byte> data, KeyUsage keyUsage, Span<byte> dest, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool AreEqualSlow(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            var diff = left.Length ^ right.Length;

            for (var i = 0; i < left.Length; i++)
            {
                diff |= (left[i] ^ right[i]);
            }

            return diff == 0;
        }
    }
}
