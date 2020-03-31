using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal class BinaryContent : HttpContent
    {
        private readonly ReadOnlyMemory<byte> _data;

        public BinaryContent(ReadOnlyMemory<byte> data)
        {
            _data = data;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
#if NETSTANDARD2_1
            await stream.WriteAsync(_data).ConfigureAwait(false);
#elif NETSTANDARD2_0
            byte[] bytes = _data.TryGetArrayFast();
            await stream.WriteAsync(bytes, 0, bytes.Length);
#else
#warning Update Tfms
#endif
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _data.Length;

            return true;
        }
    }
}
