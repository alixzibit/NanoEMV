using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NanoEMV
{
    /// <summary>
    /// This class represents a command APDU
    /// </summary>
    public class APDUCommand
    {
        /// <summary>
        /// Minimun size in bytes of an APDU command
        /// </summary>
        private const int APDU_MIN_LENGTH = 4;

        private byte cla;
        private byte ins;
        private byte p1;
        private byte p2;
        private byte[] data;
        private byte le;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bCla">Class byte</param>
        /// <param name="bIns">Instruction byte</param>
        /// <param name="bP1">Parameter P1 byte</param>
        /// <param name="bP2">Parameter P2 byte</param>
        /// <param name="baData">Data to send to the card if any, null if no data to send</param>
        /// <param name="bLe">Number of data expected, 0 if none</param>
        public APDUCommand(byte cla, byte ins, byte p1, byte p2, byte[] data, byte le)
        {
            this.cla = cla;
            this.ins = ins;
            this.p1 = p1;
            this.p2 = p2;
            this.data = data;
            this.le = le;
        }

        #region Accessors
        /// <summary>
        /// Class get property
        /// </summary>
        public byte Class
        {
            get
            {
                return cla;
            }
        }


        /// <summary>
        /// Instruction get property
        /// </summary>
        public byte Ins
        {
            get
            {
                return ins;
            }
        }


        /// <summary>
        /// Parameter P1 get property
        /// </summary>
        public byte P1
        {
            get
            {
                return p1;
            }
        }


        /// <summary>
        /// Parameter P2 get property
        /// </summary>
        public byte P2
        {
            get
            {
                return p2;
            }
        }


        /// <summary>
        /// Data get property
        /// </summary>
        public byte[] Data
        {
            get
            {
                return data;
            }
        }


        /// <summary>
        /// Length expected get property
        /// </summary>
        public byte Le
        {
            get
            {
                return le;
            }
        }
        #endregion
        public byte[] CommandData
        {
            get
            {
                return ToArray();  // Since ToArray() already returns the full APDU as a byte array.
            }
        }


        //public override string ToString()
        //{
        //    string strData = null;

        //    if (data != null)
        //    {
        //        StringBuilder sb = new StringBuilder(data.Length * 2);

        //        for (int i = 0; i < data.Length; i++)
        //        {
        //            sb.AppendFormat("{0:X02}", data[i]);
        //        }

        //        strData = "Data: " + sb.ToString();
        //        le = (byte)data.Length;
        //    }

        public override string ToString()
        {
            string strData = null;
            byte dataLength = 0;
            if (data != null)
            {
                StringBuilder sb = new StringBuilder(data.Length * 2);

                for (int i = 0; i < data.Length; i++)
                {
                    sb.AppendFormat("{0:X02}", data[i]);
                }

                strData = "Data: " + sb.ToString();
                dataLength = (byte)data.Length;
            }
            StringBuilder sbApdu = new StringBuilder();
            sbApdu.AppendFormat("Cla: {0:X02} Ins: {1:X02} P1: {2:X02} P2: {3:X02} Le: {4:X02} ", cla, ins, p1, p2, le);

            if (data != null)
            {
                sbApdu.Append(strData);
            }

            return sbApdu.ToString();
        }

        public byte[] ToArray()
        {
            int commandLength = APDU_MIN_LENGTH + ((this.Data != null) ? (1 + this.Data.Length) : 0) + 1; // +1 for Le
            byte[] buffer = new byte[commandLength];

            buffer[0] = this.Class;
            buffer[1] = this.Ins;
            buffer[2] = this.P1;
            buffer[3] = this.P2;

            if (this.Data != null)
            {
                buffer[4] = (byte)this.Data.Length;
                Array.Copy(this.Data, 0, buffer, 5, this.Data.Length);
            }

            buffer[commandLength - 1] = this.Le; // Always include Le

            return buffer;
        }

    }
}