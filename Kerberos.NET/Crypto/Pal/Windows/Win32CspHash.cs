using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal unsafe abstract class Win32CspHash : IHashAlgorithm
    {
        protected Win32CspHash(string algorithm, int calg, int hashSize)
        {
            Algorithm = algorithm;
            CAlg = calg;
            HashSize = hashSize;

            if (!Native.CryptAcquireContext(ref _hProvider, algorithm, null, Native.PROV_RSA_AES, 0)
             && !Native.CryptAcquireContext(ref _hProvider, algorithm, null, Native.PROV_RSA_AES, Native.CRYPT_NEWKEYSET))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!Native.CryptCreateHash(_hProvider, calg, IntPtr.Zero, 0, ref _hHash))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        private readonly IntPtr _hProvider;
        private readonly IntPtr _hHash;

        public string Algorithm { get; }

        public int CAlg { get; }

        public int HashSize { get; }

        public int HashSizeInBytes => HashSize;

        public bool TryComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            Debug.Assert(!data.IsEmpty);
            Debug.Assert(hash.Length >= HashSizeInBytes);

            fixed (byte* pData = &MemoryMarshal.GetReference(data))
            {
                if (!Native.CryptHashData(_hHash, pData, data.Length, 0))
                {
                    bytesWritten = 0;
                    return false;
                }
            }

            fixed (byte* pHash = &MemoryMarshal.GetReference(hash))
            {
                int len = hash.Length;

                if (Native.CryptGetHashParam(_hHash, Native.HP_HASHVAL, pHash, ref len, 0))
                {
                    Debug.Assert(len == HashSizeInBytes);
                    bytesWritten = len;
                    return true;
                }

                bytesWritten = 0;
                return false;
            }
        }

#if NETSTANDARD2_0
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data)
        {
            byte[] hash = new byte[HashSizeInBytes];

            if (TryComputeHash(data.Span, hash, out int written))
            {
                Debug.Assert(written == hash.Length);
                return hash;
            }

            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
#endif

        public void Dispose()
        {
            if (_hHash != IntPtr.Zero)
            {
                Native.CryptDestroyHash(_hHash);
            }

            if (_hProvider != IntPtr.Zero)
            {
                Native.CryptReleaseContext(_hProvider, 0);
            }
        }

        private static class Native
        {
            private const string ADVAPI32 = "advapi32.dll";

            public const int PROV_RSA_AES = 24;
            public const int CRYPT_NEWKEYSET = 0x00000008;
            public const int HP_HASHVAL = 0x0002;

            [DllImport(ADVAPI32, CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CryptAcquireContext(
                ref IntPtr hProv,
                string pszContainer,
                string pszProvider,
                int dwProvType,
                int dwFlags
            );

            [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptCreateHash(
                IntPtr hProv,
                int algId,
                IntPtr hKey,
                int dwFlags,
                ref IntPtr phHash
            );

            [DllImport(ADVAPI32, SetLastError = true)]
            public static extern bool CryptHashData(
                IntPtr hHash,
                byte* pbData,
                int dataLen,
                int flags
            );

            [DllImport(ADVAPI32, SetLastError = true)]
            public static extern bool CryptGetHashParam(
                IntPtr hHash,
                int dwParam,
                byte* pbData,
                ref int pdwDataLen,
                int dwFlags
            );

            [DllImport(ADVAPI32)]
            public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

            [DllImport(ADVAPI32, SetLastError = true)]
            public static extern bool CryptDestroyHash(IntPtr hHash);
        }
    }
}
