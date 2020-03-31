using System;
using System.Diagnostics;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{EType} {Usage} [{KeyValue.Length}]")]
    public partial class KrbEncryptionKey
    {
        public KerberosKey AsKey(KeyUsage? usage = null)
        {
            return new KerberosKey(this) { Usage = usage };
        }

        public KeyUsage Usage { get; set; }

        public static KrbEncryptionKey Generate(EncryptionType type)
        {
            var crypto = CryptoService.CreateTransform(type);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {type}");
            }

#if NETSTANDARD2_1
            var keyValue = new byte[crypto.KeySize];
            crypto.GenerateKey(keyValue);
#elif NETSTANDARD2_0
            byte[] keyValue = crypto.GenerateKey();
#else
#warning Update Tfms
#endif
            return new KrbEncryptionKey
            {
                EType = type,
                KeyValue = keyValue
            };
        }
    }
}
