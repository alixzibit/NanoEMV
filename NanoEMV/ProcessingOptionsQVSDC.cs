using System;
using System.Collections.Generic;
using System.Linq;

namespace NanoEMV;

public class ProcessingOptionsQVSDC
{
    private readonly PCSCReader _cardReader;
    private readonly RecordReader _recordReader;


    //public class ProcessingOptionsQVSDC
    //{
    //    private readonly PCSCReader _cardReader;
    //    private readonly RecordReader _recordReader;

        public ProcessingOptionsQVSDC(PCSCReader cardReader)
        {
            _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
            _recordReader = new RecordReader(_cardReader);
        }
    public List<APDUResponse> ReadRecords { get; } = new();
    public byte[] AIP { get; private set; }
    public byte[] AFL { get; private set; }
    public string PAN { get; private set; }
    public byte[] AC { get; private set; }
    public byte[] PANSEQ { get; private set; }
    public byte[] IAD { get; private set; }
    public byte[] ATC {  get; private set; }    

    private byte[] ConstructPDOLRelatedData(bool useAlternate = false)
    {
        if (useAlternate)
            // Alternate PDOL structure
            return new byte[]
            {
                0x26, 0x80, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x01, 0x02, 0x03, 0x04, // Custom data as per your requirement
                0x03, 0x92, 
                0x03, 0x92,
            };
        // Default PDOL structure
        return new byte[]
        {
            0x26, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x92,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x92,
            0x01, 0x01, 0x01,
            0x00,
            0x01, 0x02, 0x03, 0x04
        };
    }

    public APDUResponse GetProcessingOptionsQVSDC()
    {
        var logger = new Logger();
        var pdolRelatedData = ConstructPDOLRelatedData();
        var response = SendGPOCommand(pdolRelatedData);

        if (response.SW1 == 0x69 && response.SW2 == 0x85)
        {
            logger.WriteLog("Received 6985 in response, trying with alternate PDOL data.");
            pdolRelatedData = ConstructPDOLRelatedData(true);
            response = SendGPOCommand(pdolRelatedData);
        }

        if (response.SW1 == 0x67 && response.SW2 == 0x00)
        {
            logger.WriteLog("Received 6700 in response, trying with alternate PDOL data.");
            pdolRelatedData = ConstructPDOLRelatedData(true);
            response = SendGPOCommand(pdolRelatedData);
        }

        if (response.SW1 == 0x61)
        {
            logger.WriteLog("Status indicates more data is available. Fetching...");
            var apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
            response = _cardReader.Transmit(apdu);
        }
        else if (response.SW1 == 0x69 && response.SW2 == 0x85)
        {
            logger.WriteLog("Received 6985 in response, conditions of use not satisfied.");
            // Handle the specific condition or terminate the transaction
        }
        else
        //{
        //    logger.WriteLog("No valid data received from the GPO command.");
        //}

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

            // Search and parse the PAN from track data (tag 0x57)
            ASN1 track2Data = template.Find(0x57);
            if (track2Data != null)
            {
                string track2 = BitConverter.ToString(track2Data.Value).Replace("-", "");
                int separatorIndex = track2.IndexOf('D');
                if (separatorIndex > 0)
                {
                    PAN = track2.Substring(0, separatorIndex);
                    //logger.WriteLog($"PAN: {PAN}");
                }
            }

            ASN1 applicationCryptogram = template.Find(new byte[] { 0x9F, 0x26 });
            if (applicationCryptogram != null)
            {
                AC = applicationCryptogram.Value;
                logger.WriteLog($"Application Cryptogram: {BitConverter.ToString(AC)}");
            }
            ASN1 panseq = template.Find(new byte[] { 0x5F, 0x34 });
            if ( panseq != null )
            {
                PANSEQ = panseq.Value;
                /*logger.WriteLog($"PAN Sequence: {BitConverter.ToString(PANSEQ)}")*/;
            }
            ASN1 iad = template.Find(new byte[] { 0x9F, 0x10 });
            if ( iad != null )
            {
                IAD = iad.Value;
                logger.WriteLog($"Issuer Application Data: {BitConverter.ToString(IAD)}");
            }
            ASN1 atc = template.Find(new byte[] { 0x9F, 0x36 });
            if ( atc != null )
            {
                {
                   ATC = atc.Value;
                    //logger.WriteLog($"Application Transaction Counter: {BitConverter.ToString(ATC).Replace("-", "")}");
                }
            }
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

        //    private APDUResponse SendGPOCommand(byte[] pdolRelatedData)
        //    {
        //        var logger = new Logger();
        //        logger.WriteLog("Preparing APDU command with PDOL data.");

        //        APDUCommand apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, pdolRelatedData, 0x00);
        //        logger.WriteLog($"APDU Command prepared: {BitConverter.ToString(apdu.CommandData)}.");

        //        APDUResponse response = _cardReader.Transmit(apdu);
        //        logger.WriteLog($"Received APDU Response with SW1 = {response.SW1}, SW2 = {response.SW2}.");

        //        if (response.SW1 == 0x61)
        //        {
        //            logger.WriteLog("Status indicates more data is available. Fetching...");
        //            apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
        //            response = _cardReader.Transmit(apdu);
        //        }

        //        return response;
        //    }
        //}



        private APDUResponse SendGPOCommand(byte[] pdolRelatedData)
        {
            var commandData = new byte[pdolRelatedData.Length + 2];
            commandData[0] = 0x83;
            commandData[1] = (byte)pdolRelatedData.Length;
            Array.Copy(pdolRelatedData, 0, commandData, 2, pdolRelatedData.Length);

            var logger = new Logger();
            logger.WriteLog($"Preparing APDU command with PDOL data: {BitConverter.ToString(commandData)}.");

            var apdu = new APDUCommand(0x80, 0xA8, 0x00, 0x00, commandData, 0x00);
            return _cardReader.Transmit(apdu);
        }

        // A helper function to determine if the GPO was successful.
        public bool IsGPOResponseSuccessful(APDUResponse response)
        {
            // Based on ISO/IEC 7816 standards, '90 00' indicates success
            return response.SW1 == 0x90 && response.SW2 == 0x00;
        }
    }


// MANUAL AFL - 
//byte[] manualAfl = new byte[] { 0x08, 0x02, 0x02, 0x00, 0x10, 0x01, 0x02, 0x00, 0x10, 0x04, 0x05, 0x00, 0x18, 0x01, 0x02, 0x01 };

//logger.WriteLog("Using manual AFL: " + BitConverter.ToString(manualAfl));

//List<ApplicationFileLocator> afls = new List<ApplicationFileLocator>();
//for (int i = 0; i < manualAfl.Length; i += 4)
//{
//    if (i + 4 <= manualAfl.Length)
//    {
//        byte[] aflEntry = manualAfl.Skip(i).Take(4).ToArray();
//        afls.Add(new ApplicationFileLocator(aflEntry));
//        logger.WriteLog("Added manual AFL Entry: " + BitConverter.ToString(aflEntry));
//    }
//}

//foreach (var locator in afls)
//{
//    for (byte recordNum = locator.FirstRecord; recordNum <= locator.LastRecord; recordNum++)
//    {
//        var recordResponse = _recordReader.ReadRecord(locator.SFI, recordNum);
//        ReadRecords.Add(recordResponse); // Now process the recordResponse as needed
//    }
//} //end of manual afl mod