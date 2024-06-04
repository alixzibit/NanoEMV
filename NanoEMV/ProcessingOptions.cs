using NanoEMV;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NanoEMV
{
    public class ProcessingOptions
    {
        private PCSCReader _cardReader;
        private RecordReader _recordReader;

        public ProcessingOptions(PCSCReader cardReader)
        {
            _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
            _recordReader = new RecordReader(_cardReader);
        }

        public List<APDUResponse> ReadRecords { get; private set; } = new List<APDUResponse>();


        public APDUResponse GetProcessingOptions()
        {
            var logger = new Logger();

            byte[] commandData = new byte[] { 0x83, 0x00 };
            logger.WriteLog("Preparing APDU command with Empty PDOL.");

            APDUCommand apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, commandData, 0x00);
            logger.WriteLog($"APDU Command prepared: {BitConverter.ToString(apdu.CommandData)}.");

            APDUResponse response = _cardReader.Transmit(apdu);
            logger.WriteLog($"Received APDU Response with SW1 = {response.SW1}, SW2 = {response.SW2}.");

            if (response.SW1 == 0x61)
            {
                logger.WriteLog("Status indicates more data is available. Fetching...");
                apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
                response = _cardReader.Transmit(apdu);
            }
            else if (response.SW1 == 0x69 && response.SW2 == 0x85)
            {
                logger.WriteLog("Received 6985 in response, conditions of use not satisfied.");

                // Directly using 8300 as the new command data
                byte[] newCommandData = new byte[] { 0x83, 0x00 };

                apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, newCommandData, 0x00);
                response = _cardReader.Transmit(apdu);
                logger.WriteLog($"Rebuilt APDU Command: {BitConverter.ToString(apdu.CommandData)}.");
                logger.WriteLog(
                    $"Received APDU Response after rebuilding: SW1 = {response.SW1}, SW2 = {response.SW2}.");
            }

            else
            {
                logger.WriteLog("No valid data received from initial GPO command to rebuild APDU.");
            }
        

            List<byte> fullData = new List<byte>(response.Data);

            // Checking for Template Format
            if (fullData[0] == 0x80) // Template Format 1
            {
               logger.WriteLog("Detected Template Format 1.");

                byte[] aip = fullData.Skip(2).Take(2).ToArray();
                byte[] aflData = fullData.Skip(4).ToArray();

               logger.WriteLog($"AIP: {BitConverter.ToString(aip)}");
               logger.WriteLog($"AFL Data: {BitConverter.ToString(aflData)}");

                List<ApplicationFileLocator> afls = new List<ApplicationFileLocator>();
                for (int i = 0; i < aflData.Length; i += 4)
                {
                    if (i + 4 <= aflData.Length)
                    {
                        byte[] aflEntry = aflData.Skip(i).Take(4).ToArray();
                        afls.Add(new ApplicationFileLocator(aflEntry));
                       logger.WriteLog($"Added AFL Entry: {BitConverter.ToString(aflEntry)}");
                    }
                }
            }
            else if (fullData[0] == 0x77) // Template Format 2
            {
               logger.WriteLog("Detected Template Format 2.");

                byte[] aip = fullData.Skip(4).Take(2).ToArray(); // Find the AIP (0x82 tag)
                byte[] aflData = fullData.Skip(7).ToArray();     // Skip the 0x94 tag and its length

               logger.WriteLog($"AIP: {BitConverter.ToString(aip)}");
               logger.WriteLog($"AFL Data: {BitConverter.ToString(aflData)}");

                List<ApplicationFileLocator> afls = new List<ApplicationFileLocator>();
                for (int i = 0; i < aflData.Length; i += 4)
                {
                    if (i + 4 <= aflData.Length)
                    {
                        byte[] aflEntry = aflData.Skip(i).Take(4).ToArray();
                        afls.Add(new ApplicationFileLocator(aflEntry));
                       logger.WriteLog($"Added AFL Entry: {BitConverter.ToString(aflEntry)}");
                    }
                }

                foreach (var locator in afls)
                {
                    for (byte recordNum = locator.FirstRecord; recordNum <= locator.LastRecord; recordNum++)
                    {
                        var recordResponse = _recordReader.ReadRecord(locator.SFI, recordNum);
                        ReadRecords.Add(recordResponse); // Now process the recordResponse as needed
                    }
                }
            }

            else
            {
               logger.WriteLog("No fullData available to process.");
            }


            return response;
        }

        // A helper function to determine if the GPO was successful.
        public bool IsGPOResponseSuccessful(APDUResponse response)
        {
            // Based on ISO/IEC 7816 standards, '90 00' indicates success
            return response.SW1 == 0x90 && response.SW2 == 0x00;
        }
    }
}
    