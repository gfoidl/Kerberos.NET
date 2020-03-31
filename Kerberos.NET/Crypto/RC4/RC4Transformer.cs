using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    public class RC4Transformer : KerberosCryptoTransformer
    {
        public const int HashSize = 16;
        private const int ConfounderSize = 8;

        public override int ChecksumSize => HashSize;

        public override int BlockSize => HashSize;

        public override int KeySize => HashSize;

        public override byte[] String2Key(KerberosKey key)
        {
            return MD4(key.PasswordBytes);
        }

        public override byte[] Encrypt(byte[] data, KerberosKey key, KeyUsage usage)
        {
            byte[] k1 = key.GetKey(this);
#if NETSTANDARD2_1
            Span<byte> salt = stackalloc byte[sizeof(int)];
            GetSalt((int)usage, salt);

            var k2 = new byte[HashSize];
            bool success = HMACMD5(k1, salt, k2, out int bytesWritten);
            Debug.Assert(success && bytesWritten == k2.Length);

            Span<byte> confounder = stackalloc byte[ConfounderSize];
            GenerateRandomBytes(ConfounderSize, confounder);

            byte[] plaintextBuffer = null;
            Span<byte> plaintext = data.Length + ConfounderSize <= 256
                ? stackalloc byte[256]
                : plaintextBuffer = CryptoPool.Rent(data.Length + ConfounderSize);

            try
            {
                confounder.CopyTo(plaintext);
                data.CopyTo(plaintext.Slice(ConfounderSize));

                Span<byte> checksum = stackalloc byte[HashSize];
                success = HMACMD5(k2, plaintext, checksum, out bytesWritten);
                Debug.Assert(success && bytesWritten == checksum.Length);

                Span<byte> k3 = stackalloc byte[HashSize];
                success = HMACMD5(k2, checksum, k3, out bytesWritten);
                Debug.Assert(success && bytesWritten == k3.Length);

                var ciphertext = new byte[checksum.Length + plaintext.Length];
                checksum.CopyTo(ciphertext);
                RC4.Transform(k3, plaintext, ciphertext.AsSpan(checksum.Length));

                return ciphertext;
            }
            finally
            {
                CryptoPool.Return(plaintextBuffer);
            }
#elif NETSTANDARD2_0
            byte[] salt = GetSalt((int)usage);

            byte[] k2 = HMACMD5(k1, salt);

            byte[] confounder = GenerateRandomBytes(ConfounderSize);

            var plaintext = new byte[data.Length + confounder.Length];

            confounder.CopyTo(plaintext.AsSpan());
            data.CopyTo(plaintext.AsSpan(confounder.Length));

            byte[] checksum = HMACMD5(k2, plaintext);

            byte[] k3 = HMACMD5(k2, checksum);

            var ciphertext = new byte[plaintext.Length + checksum.Length];
            checksum.CopyTo(ciphertext.AsSpan());
            RC4.Transform(k3, plaintext, ciphertext.AsSpan(checksum.Length));

            return ciphertext;
#else
#warning Update Tfms
#endif
        }

        public override byte[] Decrypt(byte[] ciphertext, KerberosKey key, KeyUsage usage)
        {
            byte[] k1 = key.GetKey(this);
#if NETSTANDARD2_1
            Span<byte> salt = stackalloc byte[sizeof(int)];
            GetSalt((int)usage, salt);

            var k2 = new byte[HashSize];
            bool success = HMACMD5(k1, salt, k2, out int bytesWritten);
            Debug.Assert(success && bytesWritten == k2.Length);

            ReadOnlySpan<byte> incomingChecksum = ciphertext.AsSpan(0, HashSize);
            ReadOnlySpan<byte> ciphertextOffset = ciphertext.AsSpan(HashSize);

            Span<byte> k3 = stackalloc byte[HashSize];
            success = HMACMD5(k2, incomingChecksum, k3, out bytesWritten);
            Debug.Assert(success && bytesWritten == k3.Length);

            var plaintext = new byte[ciphertextOffset.Length];
            RC4.Transform(k3, ciphertextOffset, plaintext);

            Span<byte> actualChecksum = stackalloc byte[HashSize];
            success = HMACMD5(k2, plaintext, actualChecksum, out bytesWritten);
            Debug.Assert(success && bytesWritten == actualChecksum.Length);

            if (!AreEqualSlow(incomingChecksum, actualChecksum))
            {
                throw new SecurityException("Invalid Checksum");
            }

            return plaintext.AsSpan(ConfounderSize).ToArray();
#elif NETSTANDARD2_0
            byte[] salt = GetSalt((int)usage);

            byte[] k2 = HMACMD5(k1, salt);

            Span<byte> incomingChecksum = ciphertext.AsSpan(0, HashSize);
            Span<byte> ciphertextOffset = ciphertext.AsSpan(HashSize);

            byte[] k3 = HMACMD5(k2, incomingChecksum.ToArray());

            var plaintext = new byte[ciphertextOffset.Length];

            RC4.Transform(k3, ciphertextOffset, plaintext);

            var actualChecksum = HMACMD5(k2, plaintext);

            if (!AreEqualSlow(incomingChecksum, actualChecksum))
            {
                throw new SecurityException("Invalid Checksum");
            }

            return plaintext.AsSpan(ConfounderSize).ToArray();
#else
#warning Update Tfms
#endif
        }

        // TODO: use ROS static data optimization
        private static readonly byte[] s_checksumSignatureKey = Encoding.ASCII.GetBytes("signaturekey\0");

        public override void MakeChecksum(byte[] key, ReadOnlySpan<byte> data, KeyUsage keyUsage, Span<byte> dest, out int bytesWritten)
        {
#if NETSTANDARD2_1
            byte[] ksign = new byte[HashSize];
            bool success = HMACMD5(key, s_checksumSignatureKey, ksign, out int written);
            Debug.Assert(success && written == ksign.Length);

            byte[] arrayToReturnToPool = null;
            Span<byte> span = 4 + data.Length <= 256
                ? stackalloc byte[256]
                : arrayToReturnToPool = CryptoPool.Rent(4 + data.Length);

            try
            {
                BinaryPrimitives.WriteInt32LittleEndian(span, (int)keyUsage);
                data.CopyTo(span.Slice(4));

                Span<byte> tmp = stackalloc byte[HashSize];
                success = MD5(span, tmp, out written);
                Debug.Assert(success && written == HashSize);

                success = HMACMD5(ksign, tmp, dest, out bytesWritten);
                Debug.Assert(success && bytesWritten == HashSize);
            }
            finally
            {
                CryptoPool.Return(arrayToReturnToPool);
            }
#elif NETSTANDARD2_0
            byte[] ksign = HMACMD5(key, s_checksumSignatureKey);

            Span<byte> span = new byte[4 + data.Length];
            BinaryPrimitives.WriteInt32LittleEndian(span, (int)keyUsage);
            data.CopyTo(span.Slice(4));

            Span<byte> tmp = stackalloc byte[HashSize];
            bool success= MD5(span, tmp, out int written);
            Debug.Assert(success && written == tmp.Length);

            byte[] res = HMACMD5(ksign, tmp.ToArray());

            res.CopyTo(dest);
            bytesWritten = res.Length;
#else
#warning Update Tfms
#endif
        }

        private static bool MD5(ReadOnlySpan<byte> key, Span<byte> hash, out int bytesWritten)
        {
            using var md5 = CryptoPal.Platform.Md5();

            return md5.TryComputeHash(key, hash, out bytesWritten);
        }

#if NETSTANDARD2_1
        private static void GetSalt(int usage, Span<byte> dest)
        {
            Debug.Assert(dest.Length >= sizeof(int));

            switch (usage)
            {
                case 3:
                    usage = 8;
                    break;
                case 23:
                    usage = 13;
                    break;
            }

            BinaryPrimitives.WriteInt32LittleEndian(dest, usage);
        }

        private static bool HMACMD5(byte[] key, ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            var hmac = CryptoPal.Platform.HmacMd5();

            return hmac.TryComputeHash(key, data, hash, out bytesWritten);
        }

        private static bool MD4(ReadOnlySpan<byte> key, Span<byte> hash, out int bytesWritten)
        {
            using var md4 = CryptoPal.Platform.Md4();

            return md4.TryComputeHash(key, hash, out bytesWritten);
        }

        private static byte[] MD4(ReadOnlySpan<byte> key)
        {
            using var md4 = CryptoPal.Platform.Md4();
            var hash = new byte[md4.HashSizeInBytes];

            bool success = md4.TryComputeHash(key, hash, out int bytesWritten);

            Debug.Assert(success && bytesWritten == hash.Length);

            return hash;
        }
#elif NETSTANDARD2_0
        private static byte[] GetSalt(int usage)
        {
            switch (usage)
            {
                case 3:
                    usage = 8;
                    break;
                case 23:
                    usage = 13;
                    break;
            }

            var salt = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(salt, usage);

            return salt;
        }

        private static byte[] HMACMD5(byte[] key, byte[] data)
        {
            var hmac = CryptoPal.Platform.HmacMd5();

            return hmac.ComputeHash(key, data);
        }

        private static byte[] MD4(ReadOnlySpan<byte> key)
        {
            using var md4 = CryptoPal.Platform.Md4();
            var hash = new byte[md4.HashSizeInBytes];

            bool success = md4.TryComputeHash(key, hash, out int bytesWritten);

            Debug.Assert(success && bytesWritten == hash.Length);

            return hash;
        }
#else
#warning Update Tfms
#endif
    }
#endif
}
