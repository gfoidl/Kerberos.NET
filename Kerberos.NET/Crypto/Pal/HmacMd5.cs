using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal class HmacMd5 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var keyArray = key.TryGetArrayFast();
            var dataArray = data.TryGetArrayFast();

            using (HMACMD5 hmac = new HMACMD5(keyArray))
            {
                return hmac.ComputeHash(dataArray);
            }
        }
    }
#endif
}
