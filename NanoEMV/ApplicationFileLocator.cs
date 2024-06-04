using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NanoEMV
{
    public class ApplicationFileLocator
    {
        private readonly byte[] data = new byte[4];

        public ApplicationFileLocator(byte[] data)
        {
            if (data == null || data.Length < 4)
            {
                throw new ArgumentException("Provided data should have at least 4 bytes.");
            }
            Buffer.BlockCopy(data, 0, this.data, 0, 4);
        }

        public byte SFI => (byte)(data[0] >> 3);

        public byte FirstRecord => data[1];

        public byte LastRecord => data[2];

        public byte OfflineRecords => data[3];
    }
}
