using NanoEMV;
using System.Collections.Generic;
using System;
using System.IO;

namespace NanoEMV
{
    public class RecordReader
    {
        private PCSCReader _cardReader;

        public RecordReader(PCSCReader cardReader)
        {
            _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
        }
        //string logPath = @"C:\EMV_CB_log\emvcard_log.txt";
        //voidlogger.WriteLog(string message)
        //{
        //    using (StreamWriter writer = new StreamWriter(logPath, true))
        //    {
        //        writer.WriteLine($"{DateTime.Now:G}: {message}");
        //    }
        //}
        // For simplicity, this example assumes reading of record numbers from 1 to the maximum possible (SFI up to 30 and record up to 16).
        // You might want to adjust this based on the AID or other transaction specifics.
       
        public List<APDUResponse> ReadAllRecords()
        {
            List<APDUResponse> responses = new List<APDUResponse>();
            var logger = new Logger();

            for (byte sfi = 1; sfi <= 8; sfi++)
            {
                for (byte record = 1; record <= 14; record++)
                {
                    APDUResponse response = ReadRecord(sfi, record);

                    // Log the record attempt
                   logger.WriteLog($"Attempted to read record: SFI: {sfi}, Record: {record}, SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                    // Check if the response indicates "record not found" or "wrong parameters", then break the inner loop.
                    if (response.SW1 == 0x6A && response.SW2 == 0x82)
                    {
                       logger.WriteLog($"Record not found for SFI: {sfi}, Record: {record}. Breaking inner loop.");
                        break;
                    }

                    // If the response is successful, add it to the list.
                    if (response.SW1 == 0x90 && response.SW2 == 0x00)
                    {
                        responses.Add(response);
                       logger.WriteLog($"Successfully read record for SFI: {sfi}, Record: {record}. Added to list.");
                    }
                }
            }

            return responses;
        }

        public APDUResponse ReadRecord(byte sfi, byte record)
        {
            var logger = new Logger();
            byte p2 = (byte)((sfi << 3) | 4); // construct P2 value from SFI. It's commonly (SFI << 3) | 4
            APDUCommand apdu = new APDUCommand(0x00, 0xB2, record, p2, null, 0x00);

            APDUResponse response = _cardReader.Transmit(apdu);

            // Check for 0x6C status word
            if (response.SW1 == 0x6C)
            {
               logger.WriteLog($"Received 0x6C status. Adjusting Le and reissuing command - 00 B2 {record} {p2} {response.SW2}.");
                apdu = new APDUCommand(0x00, 0xB2, record, p2, null, response.SW2); // adjust Le with SW2
                response = _cardReader.Transmit(apdu);
            }

            return response;
        }

    }
}