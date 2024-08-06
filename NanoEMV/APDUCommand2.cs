namespace NanoEMV
{
    public class APDUCommand2
    {
        private const int APDU_MIN_LENGTH = 4;

        private byte cla;
        private byte ins;
        private byte p1;
        private byte p2;
        private byte[] data;
        private byte? le;

        // Constructor with Le byte
        public APDUCommand2(byte cla, byte ins, byte p1, byte p2, byte[] data, byte? le)
        {
            this.cla = cla;
            this.ins = ins;
            this.p1 = p1;
            this.p2 = p2;
            this.data = data;
            this.le = le;
        }

        // Constructor without Le byte
        public APDUCommand2(byte cla, byte ins, byte p1, byte p2, byte[] data)
        {
            this.cla = cla;
            this.ins = ins;
            this.p1 = p1;
            this.p2 = p2;
            this.data = data;
            this.le = null; // Indicating no Le byte
        }

        public byte[] ToArray()
        {
            int commandLength = APDU_MIN_LENGTH + (data != null ? (1 + data.Length) : 0) + (le.HasValue ? 1 : 0);
            byte[] buffer = new byte[commandLength];

            buffer[0] = cla;
            buffer[1] = ins;
            buffer[2] = p1;
            buffer[3] = p2;

            if (data != null)
            {
                buffer[4] = (byte)data.Length;
                Array.Copy(data, 0, buffer, 5, data.Length);
            }

            if (le.HasValue)
            {
                buffer[commandLength - 1] = le.Value;
            }

            return buffer;
        }

        public byte[] CommandData => ToArray();
    }
}
