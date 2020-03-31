using System;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    internal class HmacSha1 : IHmacAlgorithm
    {
        public ReadOnlyMemory<byte> ComputeHash(
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> data
        )
        {
            var keyArray = key.TryGetArrayFast();
            var dataArray = data.TryGetArrayFast();

            using (var hmac = new HMACSHA1(keyArray))
            {
                return hmac.ComputeHash(dataArray, 0, data.Length);
            }
        }
    }
}
