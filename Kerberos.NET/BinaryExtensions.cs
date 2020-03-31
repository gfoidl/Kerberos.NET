using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Kerberos.NET
{
    public static class BinaryExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] TryGetArrayFast(this ReadOnlyMemory<byte> bytes)
        {
            if (MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment) && segment.Array.Length == bytes.Length)
            {
                return segment.Array;
            }
            else
            {
                return GetArraySlow(bytes);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static byte[] GetArraySlow(ReadOnlyMemory<byte> bytes)
        {
            return bytes.ToArray();
        }
    }
}
