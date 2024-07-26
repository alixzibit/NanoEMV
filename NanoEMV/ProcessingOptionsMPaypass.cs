using System;
using System.Collections.Generic;
using System.Linq;

namespace NanoEMV
{
    public class ProcessingOptionsMPaypass
    {
        private PCSCReader _cardReader;
        private RecordReader _recordReader;

        public ProcessingOptionsMPaypass(PCSCReader cardReader)
        {
            _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
            _recordReader = new RecordReader(_cardReader);
        }

        public List<APDUResponse> ReadRecords { get; private set; } = new List<APDUResponse>();
        public byte[] AIP { get; private set; }
        public byte[] AFL { get; private set; }
        //public string PAN { get; private set; }
        //public byte[] AC { get; private set; }
        //public byte[] PANSEQ { get; private set; }
        //public byte[] IAD { get; private set; }
        //public byte[] ATC { get; private set; }

        public APDUResponse GetProcessingOptions()
        {
            var logger = new Logger();
            byte[] commandData = new byte[] { 0x83, 0x00 };
            logger.WriteLog("Preparing APDU command with Empty PDOL.");

            APDUCommand apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, commandData, 0x00);
            logger.WriteLog($"APDU Command prepared: {BitConverter.ToString(apdu.CommandData)}.");

            APDUResponse response = _cardReader.Transmit(apdu);
            logger.WriteLog($"Received APDU Response with SW1 = {response.SW1:X2}, SW2 = {response.SW2:X2}.");

            if (response.SW1 == 0x61)
            {
                logger.WriteLog("Status indicates more data is available. Fetching...");
                apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
                response = _cardReader.Transmit(apdu);
            }
            else if (response.SW1 == 0x69 && response.SW2 == 0x85)
            {
                logger.WriteLog("Received 6985 in response, conditions of use not satisfied.");
                byte[] newCommandData = new byte[] { 0x83, 0x00 };
                apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, newCommandData, 0x00);
                response = _cardReader.Transmit(apdu);
                logger.WriteLog($"Rebuilt APDU Command: {BitConverter.ToString(apdu.CommandData)}.");
                logger.WriteLog($"Received APDU Response after rebuilding: SW1 = {response.SW1:X2}, SW2 = {response.SW2:X2}.");
            }
            else
            {
                logger.WriteLog("No valid data received from initial GPO command to rebuild APDU.");
            }

            if (response.SW1 != 0x90)
            {
                return response;
            }

            List<byte> fullData = new List<byte>(response.Data);
            ASN1 aip = null;
            ASN1 afl = null;

            if (fullData[0] == 0x80) // Template Format 1
            {
                logger.WriteLog("Detected Template Format 1.");

                AIP = fullData.Skip(2).Take(2).ToArray();
                AFL = fullData.Skip(4).ToArray();

                aip = new ASN1(0x82, AIP);
                afl = new ASN1(0x94, AFL);

                //logger.WriteLog($"AIP: {BitConverter.ToString(AIP)}");
                logger.WriteLog($"AFL: {BitConverter.ToString(AFL).Replace("-", "")}");
            }
            else if (fullData[0] == 0x77) // Template Format 2
            {
                logger.WriteLog("Detected Template Format 2.");
                ASN1 template = new ASN1(response.Data);
                aip = template.Find(0x82);
                afl = template.Find(0x94);

                if (aip != null) AIP = aip.Value;
                if (afl != null) AFL = afl.Value;

                //logger.WriteLog($"AIP: {BitConverter.ToString(AIP)}");
                logger.WriteLog($"AFL: {BitConverter.ToString(AFL).Replace("-", "")}");
                //ASN1 applicationCryptogram = template.Find(new byte[] { 0x9F, 0x26 });
                //if (applicationCryptogram != null)
                //{
                //    AC = applicationCryptogram.Value;
                //    logger.WriteLog($"Application Cryptogram: {BitConverter.ToString(AC)}");
                //}
                //ASN1 panseq = template.Find(new byte[] { 0x5F, 0x34 });
                //if (panseq != null)
                //{
                //    PANSEQ = panseq.Value;
                //    logger.WriteLog($"PAN Sequence: {BitConverter.ToString(PANSEQ)}");
                //}
                //ASN1 iad = template.Find(new byte[] { 0x9F, 0x10 });
                //if (iad != null)
                //{
                //    IAD = iad.Value;
                //    logger.WriteLog($"Issuer Application Data: {BitConverter.ToString(IAD)}");
                //}
                //ASN1 atc = template.Find(new byte[] { 0x9F, 0x36 });
                //if (atc != null)
                //{
                //    {
                //        ATC = atc.Value;
                //        logger.WriteLog($"Application Transaction Counter: {BitConverter.ToString(ATC)}");
                //    }
                //}
            }
            else
            {
                logger.WriteLog("No valid data format detected.");
                return response;
            }

            List<ApplicationFileLocator> afls = new List<ApplicationFileLocator>();
            for (int i = 0; i < AFL.Length; i += 4)
            {
                byte[] aflEntry = AFL.Skip(i).Take(4).ToArray();
                afls.Add(new ApplicationFileLocator(aflEntry));
                logger.WriteLog($"Added AFL Entry: {BitConverter.ToString(aflEntry)}");
            }

            ReadAFLRecords(afls);

            return response;
        }

        private void ReadAFLRecords(List<ApplicationFileLocator> afls)
        {
            foreach (var locator in afls)
            {
                for (byte recordNum = locator.FirstRecord; recordNum <= locator.LastRecord; recordNum++)
                {
                    var recordResponse = _recordReader.ReadRecord(locator.SFI, recordNum);
                    if (recordResponse.SW1 == 0x90 && recordResponse.SW2 == 0x00)
                    {
                        ReadRecords.Add(recordResponse);
                    }
                }
            }
        }

        public bool IsGPOResponseSuccessful(APDUResponse response)
        {
            return response.SW1 == 0x90 && response.SW2 == 0x00;
        }
    }
}
