using System;
using System.Security;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosChecksum
    {
        public KeyUsage Usage { get; set; } = KeyUsage.PaForUserChecksum;

        public byte[] Signature { get; private set; }

        protected byte[] Data { get; }

        protected KerberosChecksum(byte[] signature, byte[] data)
        {
            Signature = signature;
            Data = data;
        }

        public void Validate(KerberosKey key)
        {
            if (!ValidateInternal(key))
            {
                throw new SecurityException("Invalid checksum");
            }
        }

        public void Sign(KerberosKey key)
        {
#if NETSTANDARD2_1

#elif NETSTANDARD2_0
            Signature = SignInternal(key);
#else
#warning Update Tfms
#endif
        }

#if NETSTANDARD2_1
        protected abstract void SignInternal(KerberosKey key, Span<byte> dest, out int written);
#elif NETSTANDARD2_0
        protected abstract byte[] SignInternal(KerberosKey key);
#else
#warning Update Tfms
#endif

        protected abstract bool ValidateInternal(KerberosKey key);
    }

    public class HmacAes256KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes256KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES256_CTS_HMAC_SHA1_96), signature, data)
        {
        }
    }

    public class HmacAes128KerberosChecksum : AesKerberosChecksum
    {
        public HmacAes128KerberosChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
            : base(CryptoService.CreateTransform(EncryptionType.AES128_CTS_HMAC_SHA1_96), signature, data)
        {
        }
    }

    public abstract class AesKerberosChecksum : KerberosChecksum
    {
        private readonly KerberosCryptoTransformer decryptor;

        protected AesKerberosChecksum(KerberosCryptoTransformer decryptor, byte[] signature, byte[] data)
            : base(signature, data)
        {
            this.decryptor = decryptor;
        }


        protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
        {
            return decryptor.MakeChecksum(
                Data,
                key,
                Usage,
                KeyDerivationMode.Kc,
                decryptor.ChecksumSize
            );
        }

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum.Span, Signature);
        }
    }
#if WEAKCRYPTO
    public class HmacMd5KerberosChecksum : KerberosChecksum
    {
        public HmacMd5KerberosChecksum(byte[] signature, byte[] data)
            : base(signature, data)
        {
        }

#if NETSTANDARD2_1

#elif NETSTANDARD2_0
        protected override byte[] SignInternal(KerberosKey key)
        {
            var crypto = CryptoService.CreateTransform(EncryptionType.RC4_HMAC_NT);

            return crypto.MakeChecksum(key.GetKey(crypto), Data, Usage);

            return crypto.MakeChecksum(key.GetKey(crypto), Data, Usage, )
        }
#else
#warning Update Tfms
#endif

        protected override bool ValidateInternal(KerberosKey key)
        {
            var actualChecksum = SignInternal(key);

            return KerberosCryptoTransformer.AreEqualSlow(actualChecksum, Signature);
        }
    }
#endif
    }
