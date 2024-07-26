using NanoEMV;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public class EMVTransactionSimulator
{
    private PCSCReader _cardReader;

    public EMVTransactionSimulator(PCSCReader cardReader)
    {
        _cardReader = cardReader;
    }

    public byte[] GetATC()
    {
        // Step 1: Construct CDOL Data
        byte[] cdolData = ConstructCDOLData();

        // Step 2: Send Generate AC Command
        APDUResponse response = GenerateAC(0x80, cdolData); // 0x80 indicates ARQC

        if (response.SW1 == 0x90 && response.Data != null)
        {
            // Step 3: Parse the Response to Extract ATC
            return ExtractATCFromResponse(response.Data);
        }

        throw new Exception("Failed to generate AC and retrieve ATC.");
    }

    public byte[] ConstructCDOLData()
    {
        List<byte> cdolData = new List<byte>
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Tag 9F 02: Transaction Amount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Tag 9F 03: Cashback Amount
            0x03, 0x92, // Tag 9F 1A: Terminal Country Code
            0x00, 0x00, 0x00, 0x00, 0x00, // Tag 95: Terminal Verification Results (TVR)
            0x03, 0x92, // Tag 5F 2A: Transaction Currency Code
            0x01, 0x01, 0x01, // Tag 9A: Transaction Date
            0x00, // Tag 9C: Transaction Type
            0x01, 0x02, 0x03, 0x04 // Tag 9F 37: Unpredictable Number
        };

        Debug.WriteLine($"Constructed CDOL Data: {BitConverter.ToString(cdolData.ToArray()).Replace("-", "")}");
        return cdolData.ToArray();
    }


    public byte[] ConstructCDOL2Data(byte[] arpc, byte[] arc)
    {
        List<byte> cdol2Data = new List<byte>();

        cdol2Data.AddRange(arc); // Tag 8A: Authorization Response Code (00 = Approved)
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }); // Tag 9F 02: Transaction Amount
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 9F 03: Cashback Amount
        cdol2Data.AddRange(new byte[] { 0x03, 0x92 });                         // Tag 9F 1A: Terminal Country Code
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 });       // Tag 95: Terminal Verification Results (TVR)
        cdol2Data.AddRange(new byte[] { 0x03, 0x92 });                         // Tag 5F 2A: Transaction Currency Code
        cdol2Data.AddRange(new byte[] { 0x01, 0x01, 0x01 });                   // Tag 9A: Transaction Date
        cdol2Data.AddRange(new byte[] { 0x00 });                               // Tag 9C: Transaction Type
        cdol2Data.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04 });             // Tag 9F 37: Unpredictable Number
        cdol2Data.AddRange(arpc);
        cdol2Data.AddRange(arc);

        // Add debug line to print constructed CDOL2 data
        Debug.WriteLine($"Constructed CDOL2 Data: {BitConverter.ToString(cdol2Data.ToArray()).Replace("-", "")}");

        return cdol2Data.ToArray();
    }


    public byte[] ConstructCDOL2Data2(byte[] arpc, byte[] arc)
    {
        List<byte> cdol2Data = new List<byte>();

        cdol2Data.AddRange(arc); // Tag 8A: Authorization Response Code (00 = Approved)
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }); // Tag 9F 02: Transaction Amount
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 9F 03: Cashback Amount
        cdol2Data.AddRange(new byte[] { 0x03, 0x92 });                         // Tag 9F 1A: Terminal Country Code
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 });       // Tag 95: Terminal Verification Results (TVR)
        cdol2Data.AddRange(new byte[] { 0x03, 0x92 });                         // Tag 5F 2A: Transaction Currency Code
        cdol2Data.AddRange(new byte[] { 0x01, 0x01, 0x01 });                   // Tag 9A: Transaction Date
        cdol2Data.AddRange(new byte[] { 0x00 });                               // Tag 9C: Transaction Type
        cdol2Data.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04 });             // Tag 9F 37: Unpredictable Number
        cdol2Data.AddRange(arpc.Take(4));                                      // Only add the first 4 bytes of ARPC
        cdol2Data.AddRange(new byte[] { 0x03, 0x92, 0x00, 0x00 });             // Card Status Update

        // Add debug line to print constructed CDOL2 data
        Debug.WriteLine($"Constructed ARPC Method 2 CDOL2 Data for VISA CVN18: {BitConverter.ToString(cdol2Data.ToArray()).Replace("-", "")}");

        return cdol2Data.ToArray();
    }


    //public byte[] ConstructCDOLDataMchip()
    //{
    //    List<byte> cdolData = new List<byte>
    //{
    //    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Tag 9F 02: Transaction Amount
    //    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Tag 9F 03: Cashback Amount
    //    0x03, 0x92, // Tag 9F 1A: Terminal Country Code
    //    0x00, 0x00, 0x00, 0x00, 0x00, // Tag 95: Terminal Verification Results (TVR)
    //    0x03, 0x92, // Tag 5F 2A: Transaction Currency Code
    //    0x01, 0x01, 0x01, // Tag 9A: Transaction Date
    //    0x00, // Tag 9C: Transaction Type
    //    0x01, 0x02, 0x03, 0x04, // Tag 9F 37: Unpredictable Number
    //    0x12, // Tag 9F 35: Terminal Type
    //    0x01, 0x02, // Tag 9F 45: Data Authentication Code
    //    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Tag 9F 4C: ICC Dynamic Number
    //    0x00, 0x01, 0x02 // Tag 9F 34: Cardholder Verification Method (CVM) Results
    //};

    //    Debug.WriteLine($"Constructed CDOL Data for Mchip: {BitConverter.ToString(cdolData.ToArray()).Replace("-", "")}");
    //    return cdolData.ToArray();
    //}

    public byte[] ConstructCDOLDataMchip(int length8C)
    {
        List<byte> cdolData = new List<byte>();

        cdolData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }); // Tag 9F 02: Transaction Amount
        cdolData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 9F 03: Cashback Amount
        cdolData.AddRange(new byte[] { 0x03, 0x92 }); // Tag 9F 1A: Terminal Country Code
        cdolData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 95: Terminal Verification Results (TVR)
        cdolData.AddRange(new byte[] { 0x03, 0x92 }); // Tag 5F 2A: Transaction Currency Code
        cdolData.AddRange(new byte[] { 0x01, 0x01, 0x01 }); // Tag 9A: Transaction Date
        cdolData.AddRange(new byte[] { 0x00 }); // Tag 9C: Transaction Type
        cdolData.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04 }); // Tag 9F 37: Unpredictable Number
        cdolData.AddRange(new byte[] { 0x12 }); // Tag 9F 35: Terminal Type
        cdolData.AddRange(new byte[] { 0x01, 0x02 }); // Tag 9F 45: Data Authentication Code
        cdolData.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }); // Tag 9F 4C: ICC Dynamic Number
        cdolData.AddRange(new byte[] { 0x00, 0x01, 0x02 }); // Tag 9F 34: Cardholder Verification Method (CVM) Results

        bool cdol1withTTMCD = false;

        if (length8C > 66)
        {
            cdol1withTTMCD = true;
            cdolData.AddRange(new byte[] { 0x12, 0x04, 0x33 }); // Tag 9F 21: Transaction Time
            cdolData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 9F 7C: Merchant Custom Data
        }

        Debug.WriteLine($"Constructed CDOL Data for Mchip: {BitConverter.ToString(cdolData.ToArray()).Replace("-", "")}");
        return cdolData.ToArray();
    }


    public byte[] ConstructCDOL2DataMchip(byte[] arpc, byte[] arc)
    {
        List<byte> cdol2Data = new List<byte>();

        cdol2Data.AddRange(arpc); // Tag 91: Issuer Authentication Data (ARPC + ARPC Response Code)
        cdol2Data.AddRange(arc); // Tag 8A: Authorization Response Code (e.g., 30 30 for Approved)
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }); // Tag 9F 02: Transaction Amount
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // Tag 9F 03: Cashback Amount
        cdol2Data.AddRange(new byte[] { 0x03, 0x92 });                         // Tag 9F 1A: Terminal Country Code
        cdol2Data.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 });       // Tag 95: Terminal Verification Results (TVR)
        cdol2Data.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04 });             // Tag 9F 37: Unpredictable Number
        cdol2Data.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }); // Tag 9F 4C: ICC Dynamic Number

        // Add debug line to print constructed CDOL2 data
        Debug.WriteLine($"Constructed CDOL2 Data for Mchip: {BitConverter.ToString(cdol2Data.ToArray()).Replace("-", "")}");

        return cdol2Data.ToArray();
    }

    public byte[] ConstructCDOLMchipARPC(byte[] arpc, byte[] arc)
    {
        List<byte> cdolMCarpcData = new List<byte>();

        cdolMCarpcData.AddRange(arpc); // Tag 91: Issuer Authentication Data
        cdolMCarpcData.AddRange(arc); // Additional ARC
        cdolMCarpcData.AddRange(new byte[] { 0x30, 0x30 }); //  Tag 8A: Authorization Response Code
        cdolMCarpcData.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 });       // Tag 95: Terminal Verification Results (TVR)
        cdolMCarpcData.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04 });             // Tag 9F 37: Unpredictable Number
        cdolMCarpcData.AddRange(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }); // Tag 9F 4C: ICC Dynamic Number
       

        // Add debug line to print constructed CDOL data
        Debug.WriteLine($"Constructed ARPC Method 1 CDOL Data for Mchip: {BitConverter.ToString(cdolMCarpcData.ToArray()).Replace("-", "")}");

        return cdolMCarpcData.ToArray();
    }



    public APDUResponse GenerateAC(byte p1, byte[] data)
    {
        APDUCommand apdu = new APDUCommand(0x80, 0xAE, p1, 0x00, data, 0x00);
        return _cardReader.Transmit(apdu);
    }

    public APDUResponse GetUnpredictableNumber()
    {
        APDUCommand apdu = new APDUCommand(0x00, 0x84, 0x00, 0x00, null, 0x08);
        APDUResponse response = _cardReader.Transmit(apdu);

        if (response.SW1 == 0x90 && response.SW2 == 0x00)
        {
            // Trim the trailing 9000
            byte[] unpredictableNumber = new byte[response.Data.Length - 2];
            Array.Copy(response.Data, 0, unpredictableNumber, 0, unpredictableNumber.Length);
            return new APDUResponse(unpredictableNumber, response.SW1, response.SW2);
        }
        return response;
    }





    public APDUResponse ExternalAuthenticate(byte[] issuerAuthenticationData)
    {
        // CLA: 0x00 (indicates no secure messaging)
        // INS: 0x82 (External Authenticate command)
        // P1: 0x00
        // P2: 0x00
        // Lc: Length of issuerAuthenticationData
        // Data: issuerAuthenticationData
        // Le: 0x00 (to receive the maximum length allowed by the card)

        APDUCommand externalAuthenticateCommand = new APDUCommand(0x00, 0x82, 0x00, 0x00, issuerAuthenticationData, 0x00);
        APDUResponse response = _cardReader.Transmit(externalAuthenticateCommand);

        Debug.WriteLine($"External Authenticate APDU: {BitConverter.ToString(externalAuthenticateCommand.ToArray()).Replace("-", "")}");
        Debug.WriteLine($"External Authenticate Response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}, Data: {BitConverter.ToString(response.Data).Replace("-", "")}");

        return response;
    }

    private byte[] ExtractATCFromResponse(byte[] responseData)
    {
        // Assuming the response data follows the format in the provided log
        // Tag 9F 36: Application Transaction Counter (ATC) is 2 bytes long and follows Tag 9F 27 in the response
        for (int i = 0; i < responseData.Length - 1; i++)
        {
            if (responseData[i] == 0x9F && responseData[i + 1] == 0x36)
            {
                // Found the ATC tag, the next byte is the length (should be 2), followed by the ATC value
                byte length = responseData[i + 2];
                if (length == 2)
                {
                    return new byte[] { responseData[i + 3], responseData[i + 4] };
                }
            }
        }

        throw new Exception("ATC not found in the response.");
    }

    public byte[] GenerateARPC2(byte[] arqc, byte[] arc, byte[] sessionKey)
    {
        // ARPC Method 2 requires concatenating ARQC, CSU, and Proprietary Authentication Data
        byte[] csu = new byte[] { 0x03, 0x92, 0x00, 0x00 }; // Example CSU (Card Status Update)
        byte[] y = new byte[arqc.Length + csu.Length + 0]; // Proprietary Authentication Data is empty here

        // Concatenate ARQC, CSU, and Proprietary Authentication Data
        Buffer.BlockCopy(arqc, 0, y, 0, arqc.Length);
        Buffer.BlockCopy(csu, 0, y, arqc.Length, csu.Length);

        // Compute MAC over the data
        byte[] arpc = ComputeMAC(sessionKey, y);

        // Return ARPC concatenated with CSU (Issuer Authentication Data)
        return arpc.Concat(csu).ToArray();
    }



    private static byte[] ComputeMAC(byte[] key, byte[] data)
    {
        using (var des = TripleDES.Create())
        {
            des.Key = key;
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.None;
            des.IV = new byte[8];  // Initialize IV to zero

            using (var encryptor = des.CreateEncryptor())
            {
                byte[] mac = new byte[8];
                for (int i = 0; i < data.Length; i += 8)
                {
                    encryptor.TransformBlock(data, i, 8, mac, 0);
                }
                return mac;
            }
        }

    }
}
