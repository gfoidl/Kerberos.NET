using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal class BinaryContent : HttpContent
    {
        private readonly ReadOnlyMemory<byte> data;

        public BinaryContent(ReadOnlyMemory<byte> data)
        {
            this.data = data;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            await stream.WriteAsync(data).ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = data.Length;

            return true;
        }
    }
}
