﻿using System;
using Kerberos.NET.Crypto;

namespace KerbDump
{
    public class NoopTransform : KerberosCryptoTransformer
    {
        public override int ChecksumSize => throw new NotImplementedException();

        public override int BlockSize => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();

        public override byte[] Encrypt(byte[] data, KerberosKey key, KeyUsage usage)
        {
            return data;
        }

        public override byte[] Decrypt(byte[] cipher, KerberosKey key, KeyUsage usage)
        {
            return cipher;
        }

        public override byte[] String2Key(KerberosKey key)
        {
            return key.PasswordBytes;
        }
    }
}
