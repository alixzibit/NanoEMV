using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using static NanoEMV.Services.CardReaderService2;

namespace NanoEMV.Services
{
    public class OnlineTxnSimCTL
    {
        private readonly ICardReaderService2 _cardReaderService;
        private readonly byte[] _masterKey;
        private readonly bool _arpcEnabled;
        private CardData _cardData;
        private List<string> _transactionLogs;
        private Logger _logger = new Logger();


        public OnlineTxnSimCTL(ICardReaderService2 cardReaderService, string masterKeyHex, bool arpcEnabled)
        {
            _cardReaderService = cardReaderService;
            _masterKey = HexStringToByteArray(masterKeyHex);
            _arpcEnabled = arpcEnabled;
            _transactionLogs = new List<string>();
        }


        public CardData SimulateTransaction(string readerName)
        {
            try
            {
                _transactionLogs.Clear();
                _transactionLogs.Add("Starting Contactless transaction simulation...");
                _logger.WriteLog("=========================== Starting Contactless transaction simulation ===========================");

                // Step 1: Read all card data
                _cardData = _cardReaderService.ReadCardContactless(readerName);

                _transactionLogs.Add("Card data read successfully.");

                // Step 2: Generate and Authenticate ARQC
                GenerateAndAuthenticateARQC(_arpcEnabled);
                _transactionLogs.Add("Contactless Transaction Simulated successfully.");
                _logger.WriteLog("=========================== Contactless Transaction Simulated successfully =========================");
            }
            catch (Exception ex)
            {
                _transactionLogs.Add($"Error: {ex.Message}");
                _logger.WriteLog($"Error: {ex.Message}");
            }

            return _cardData; // Return the updated CardData instance
        }

        //PARENT ARQC METHODS for VISA AND MCHIP
        public void GenerateAndAuthenticateARQC(bool arpcEnabled)
        {
            try
            {
                // Get PAN
                string pan = _cardData.GetTagValue("5A"); // PAN
                if (string.IsNullOrEmpty(pan))
                {
                    throw new Exception("PAN not found.");
                }

                string maskedPan = $"{pan.Substring(0, 6)}XXXXXX{pan.Substring(pan.Length - 4)}";
                _transactionLogs.Add($"PAN: {maskedPan}");
                _logger.WriteLog($"PAN: {maskedPan}");

                // Get PAN Sequence Number
                string panSequenceNumber = _cardData.GetTagValue("5F34"); // Default sequence number
                _transactionLogs.Add($"PAN Sequence Number: {panSequenceNumber}");
                _logger.WriteLog($"PAN Sequence Number: {panSequenceNumber}");

                // Check if the card is MChip based on the PAN starting digit
                if (pan.StartsWith("5") || pan.StartsWith("6"))
                {
                    GenAuthARQCMchip(pan, panSequenceNumber, arpcEnabled);
                    return; // MChip-specific logic here if needed
                }

                // PROCESS AS VISA-----------------

                // Retrieve AIP
                _transactionLogs.Add($"Processing as qVSDC Online Transaction...");
                _logger.WriteLog($"Processing as qVSDC Online Transaction...");
                string extractedAip = _cardData.GetTagValue("82");
                if (string.IsNullOrEmpty(extractedAip))
                {
                    throw new Exception("AIP (Tag 82) not found");
                }

                byte[] aip = HexStringToByteArray(extractedAip);
                _transactionLogs.Add($"AIP: {BitConverter.ToString(aip).Replace("-", "")}");
                _logger.WriteLog($"AIP: {BitConverter.ToString(aip).Replace("-", "")}");

                byte[] udk = SessionKeyDerivation.DeriveUDK(_masterKey, pan, panSequenceNumber);
                _transactionLogs.Add($"Derived UDK: {BitConverter.ToString(udk).Replace("-", "")}");
                _logger.WriteLog($"Session Key Derivation - Derived UDK: {BitConverter.ToString(udk).Replace("-", "")}");

                // Retrieve AC
                string extractedAC = _cardData.GetTagValue("9F26");
                if (string.IsNullOrEmpty(extractedAC))
                {
                    throw new Exception("AC (Tag 9F26) not found");
                }
                byte[] ac = HexStringToByteArray(extractedAC);

                // Retrieve ATC
                string extractedATC = _cardData.GetTagValue("9F36");
                if (string.IsNullOrEmpty(extractedATC))
                {
                    throw new Exception("ATC (Tag 9F36) not found");
                }
                byte[] atc = HexStringToByteArray(extractedATC);

                // Retrieve IAD
                string extractedIAD = _cardData.GetTagValue("9F10");
                if (string.IsNullOrEmpty(extractedIAD))
                {
                    throw new Exception("IAD (Tag 9F10) not found");
                }
                byte[] iad = HexStringToByteArray(extractedIAD);

                byte cvn = iad.Length > 0 ? iad[2] : (byte)0x00;
                _transactionLogs.Add($"Detected CVN (hex): {cvn:X2}");
                _logger.WriteLog($"Detected CVN (hex): {cvn:X2}");

                byte[] cvr = iad.Skip(3).Take(4).ToArray(); // Adjusting the CVR extraction
                byte[] cvrAlt = iad.Skip(4).Take(1).ToArray();

                byte[] arqc;
                EMVTransactionSimulatorCTL simulator = new EMVTransactionSimulatorCTL(_cardReaderService.GetCardReader());
                byte[] cdol1Data = simulator.ConstructCDOLData();
                byte[] cdolDataAlt = simulator.ConstructCDOLalt();
                if (cvn == 0x0A)
                {
                    // CVN 10
                    byte[] transactionData = cdol1Data.Concat(aip).Concat(atc).Concat(cvr).ToArray();
                    _transactionLogs.Add($"Constructed CVN10 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    _logger.WriteLog($"Constructed CVN10 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    arqc = CalculateApplicationCryptogram(transactionData, udk);

                    if (arpcEnabled)
                    {
                        GenerateARPCForVisaCVN10(ac, udk, aip);
                    }
                }
                if (cvn == 0x11)
                {
                    //CVN 17
                    byte[] transactionData = cdolDataAlt.Concat(atc).Concat(cvrAlt).ToArray(); 
                    _transactionLogs.Add($"Constructed CVN17 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    _logger.WriteLog($"Constructed CVN17 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    arqc = CalculateApplicationCryptogram(transactionData, udk);

                    if (arpcEnabled)
                    {
                        GenerateARPCForVisaCVN10(ac, udk, aip);
                    }
                }
                else if (cvn >= 0x12)
                {
                    // CVN 18 or higher
                    byte[] transactionData = cdol1Data.Concat(aip).Concat(atc).Concat(iad).ToArray();
                    _transactionLogs.Add($"Constructed CVN18 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    _logger.WriteLog($"Constructed CVN18 Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    byte[] skac = SessionKeyDerivation.DeriveSessionKeyEMVCSK(udk, atc);
                    _transactionLogs.Add($"Derived SKAC: {BitConverter.ToString(skac).Replace("-", "")}");
                    _logger.WriteLog($"Session Key Derivation - Derived SKAC: {BitConverter.ToString(skac).Replace("-", "")}");
                    arqc = CalculateApplicationCryptogramCVN18(transactionData, skac);

                    if (arpcEnabled)
                    {
                        GenerateARPCForVisaCVN18(ac, skac, aip);
                    }
                }
                else
                {
                    _logger.WriteLog("Unsupported CVN");
                    throw new Exception("Unsupported CVN.");
                }

                _transactionLogs.Add($"Calculated ARQC: {BitConverter.ToString(arqc).Replace("-", "")}\nReceived ARQC: {BitConverter.ToString(ac).Replace("-", "")}");
                _logger.WriteLog($"Calculated ARQC: {BitConverter.ToString(arqc).Replace("-", "")}");
                _logger.WriteLog($"Received ARQC: {BitConverter.ToString(ac).Replace("-", "")}");


                if (!ac.SequenceEqual(arqc))
                {
                    _logger.WriteLog($"ARQC verification failed.");

                    throw new Exception("ARQC verification failed.");
                }
                else
                {
                    _logger.WriteLog($"ARQC verification succeeded.");
                    _transactionLogs.Add("ARQC verification succeeded.");
                }

                _transactionLogs.Add("Transaction Simulation succeeded.");
                _logger.WriteLog($"Transaction Simulation succeeded.");
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"Error during transaction simulation: {ex.Message}");
                _transactionLogs.Add($"Error during transaction simulation: {ex.Message}");
                throw;
            }
        }



        private void GenerateARPCForVisaCVN18(byte[] ac, byte[] skac, byte[] aip)
        {
            byte[] arc = new byte[] { 0x30, 0x30 }; // Example ARC
            byte[] arpc = GenerateARPC2(ac, arc, skac);
            EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());
            byte[] cdol1Data = simulator.ConstructCDOLData();

            byte[] cdol2Data = simulator.ConstructCDOL2Data2(arpc, arc);
            APDUResponse tcResponse = simulator.GenerateAC(0x40, cdol2Data); // 0x40 indicates TC
            tcResponse = ProcessResponse(tcResponse); // Process the response to handle additional data

            if (tcResponse.SW1 != 0x90)
            {
                throw new Exception("Failed to generate TC with Issuer Authentication Data.");
            }

            // Parse the GAC response for TC
            var (tcCid, tcAtc, tcAc, tcIad) = ParseGACResponse(tcResponse.Data);

            // Concatenate CDOL1 Data, AIP, ATC, IAD for TC verification
            byte[] tcTransactionData = cdol1Data.Concat(aip).Concat(tcAtc).Concat(tcIad).ToArray();
            _transactionLogs.Add($"Constructed Txn Cert Data: {BitConverter.ToString(tcTransactionData).Replace("-", "")}");

            // Verify TC
            if (!VerifyApplicationCryptogramCVN18(tcAc, tcTransactionData, skac))
            {
                throw new Exception("ARPC verification failed.");
            }
            else
            {
                _transactionLogs.Add("ARPC verification succeeded.");
            }

        }

        private void GenerateARPCForVisaCVN10(byte[] ac, byte[] udk, byte[] aip)
        {
            byte[] arc = new byte[] { 0x30, 0x30 }; // Example ARC
            byte[] arpc = GenerateARPC(ac, arc, udk);
            EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());
            byte[] cdol1Data = simulator.ConstructCDOLData();

            byte[] cdol2Data = simulator.ConstructCDOL2Data(arpc, arc);
            APDUResponse tcResponse = simulator.GenerateAC(0x40, cdol2Data); // 0x40 indicates TC
            tcResponse = ProcessResponse(tcResponse); // Process the response to handle additional data

            if (tcResponse.SW1 != 0x90)
            {
                throw new Exception("Failed to generate TC with Issuer Authentication Data.");
            }

            // Parse the GAC response for TC
            var (tcCid, tcAtc, tcAc, tcIad) = ParseGACResponse(tcResponse.Data);

            // Extract the last 3 bytes of IAD as CVR
            byte[] tccvr = tcIad.Skip(3).Take(4).ToArray();

            // Concatenate CDOL1 Data, AIP, ATC, CVR for TC verification
            byte[] tcTransactionData = cdol1Data.Concat(aip).Concat(tcAtc).Concat(tccvr).ToArray();
            _transactionLogs.Add($"Constructed Txn Cert Data: {BitConverter.ToString(tcTransactionData).Replace("-", "")}");

            // Verify TC
            if (!VerifyApplicationCryptogram(tcAc, tcTransactionData, udk))
            {
                throw new Exception("ARPC verification failed.");
            }
            else
            {
                _transactionLogs.Add("ARPC verification succeeded.");
            }
        }

        // PROCESS AS MCHIP-----------------
        private void GenAuthARQCMchip(string pan, string panSequenceNumber, bool arpcEnabled)
        {
            _transactionLogs.Add($"Processing as MCHIP PayPass Online Transaction...");
            _logger.WriteLog($"Processing as MCHIP Contact Online Transaction...");
            try
            {
                EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());

                // Mask PAN
                string maskedPan = $"{pan.Substring(0, 6)}XXXXXX{pan.Substring(pan.Length - 4)}";
                _transactionLogs.Add($"MChip PAN: {maskedPan}, PAN Sequence Number: {panSequenceNumber}");
                _logger.WriteLog($"MChip PAN: {maskedPan}, PAN Sequence Number: {panSequenceNumber}");

                //byte[] masterKey = HexStringToByteArray("6BDF79EC6EECA2C7D0D65708AEA16E58");
                byte[] udk = SessionKeyDerivation.DeriveUDK(_masterKey, pan, panSequenceNumber);
                _transactionLogs.Add($"Derived UDK: {BitConverter.ToString(udk).Replace("-", "")}");
                _logger.WriteLog($"Session Key Derivation - Derived UDK: {BitConverter.ToString(udk).Replace("-", "")}");

                // Retrieve the length of the 8C tag from extractedTagValues
                if (_cardData.GetTagValue("8C") is string tag8C)
                {
                    int length8C = tag8C.Length;

                    // Generate ARQC
                    byte[] cdol1Data = simulator.ConstructCDOLDataMchip(length8C);
                    bool cdol1withTTMCD = length8C > 66;

                    APDUResponse arqcResponse = simulator.GenerateAC(0x80, cdol1Data); // 0x80 indicates ARQC
                    _logger.WriteLog($"Sending Generate AC command......");
                    arqcResponse = ProcessResponse(arqcResponse); // Process the response to handle additional data

                    if (arqcResponse.SW1 != 0x90)
                    {
                        _transactionLogs.Add("Failed to generate ARQC.");
                        throw new InvalidOperationException("Failed to generate ARQC.");
                    }

                    // Parse the GAC response
                    var (cid, atc, ac, iad) = ParseGACResponseFormat2(arqcResponse.Data);
                    _transactionLogs.Add($"CID: {cid}\nATC: {BitConverter.ToString(atc).Replace("-", "")}\nAC: {BitConverter.ToString(ac).Replace("-", "")}\n");
                    _logger.WriteLog($"Parsed data from Generate AC response - ATC: {BitConverter.ToString(atc).Replace("-", "")}  AC: {BitConverter.ToString(ac).Replace("-", "")}");
                    string extractedIAD = BitConverter.ToString(iad).Replace("-", "");
                    _cardData.AddTagValue("9F10", extractedIAD, "Issuer Application Data");

                    // Extract the last 3 bytes of IAD as CVR
                    byte[] cvr = iad.Skip(2).Take(6).ToArray(); // Adjusting the CVR extraction

                    // Trim the unnecessary part of cdol1Data when constructing transaction data for ARQC verification
                    int cdol1DataLengthToKeep = cdol1Data.Length - (1 + 2 + 8 + 3); // Length of CDOL1 data minus the length of the tags to trim

                    if (cdol1withTTMCD)
                    {
                        cdol1DataLengthToKeep -= (3 + 20); // Adjust trimming for additional data
                        _transactionLogs.Add("Trimmed Mchip Advance CDOL1 with additional data");
                        _logger.WriteLog("Trimmed Mchip Advance CDOL1 with additional data");
                    }
                    byte[] trimmedCdol1Data = cdol1Data.Take(cdol1DataLengthToKeep).ToArray();

                    // Concatenate CDOL1 Data, AIP, ATC, and CVR for ARQC verification
                    byte[] aip = HexStringToByteArray(_cardData.GetTagValue("82")); // AIP from extracted tag values
                    byte[] un = HexStringToByteArray("01020304");
                    byte[] transactionData = trimmedCdol1Data.Concat(aip).Concat(atc).Concat(cvr).ToArray();
                    _transactionLogs.Add($"Constructed Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
                    _logger.WriteLog($"Constructed Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");

                    // Calculate ARQC
                    byte[] skac = SessionKeyDerivation.DeriveSessionKeyMC(udk, atc, un);
                    _transactionLogs.Add($"Derived SKAC: {BitConverter.ToString(skac).Replace("-", "")}");
                    _logger.WriteLog($"Session Key Derivation - Derived SKAC: {BitConverter.ToString(skac).Replace("-", "")}");
                    byte[] arqc = CalculateApplicationCryptogramMC(transactionData, skac);
                    _transactionLogs.Add($"Calculated ARQC: {BitConverter.ToString(arqc).Replace("-", "")}\nReceived ARQC: {BitConverter.ToString(ac).Replace("-", "")}\n");
                    _logger.WriteLog($"Calculated ARQC: {BitConverter.ToString(arqc).Replace("-", "")}");
                    _logger.WriteLog($"Received ARQC: {BitConverter.ToString(ac).Replace("-", "")}");
                    // Verify ARQC
                    if (!ac.SequenceEqual(arqc))
                    {
                        _transactionLogs.Add("ARQC verification failed.");
                        _logger.WriteLog("ARQC verification failed.");
                        throw new InvalidOperationException("ARQC verification failed.");
                    }
                    else
                    {
                        _transactionLogs.Add("ARQC verification succeeded.");
                        _logger.WriteLog("ARQC verification succeeded.");
                    }

                    if (arpcEnabled)
                    {
                        GenerateARPCForMChip(ac, udk, skac, aip, trimmedCdol1Data);
                    }

                    _transactionLogs.Add("Transaction Simulation Successful.");
                    _logger.WriteLog("Transaction Simulation Successful.");
                }
                else
                {
                    _transactionLogs.Add("Tag 8C not found in card data.");
                    throw new InvalidOperationException("Tag 8C not found in card data.");
                }
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"Error during transaction simulation: {ex.Message}");
                _transactionLogs.Add($"Error during transaction simulation: {ex.Message}");
                throw;
            }
        }
        private void GenerateARPCForMChip(byte[] ac, byte[] udk, byte[] skac, byte[] aip, byte[] trimmedCdol1Data)
        {
            try
            {
                if (ac.Length < 8 || udk.Length < 16)
                {
                    throw new ArgumentException("Input arrays are not of the expected lengths.");
                }

                byte[] arc = new byte[] { 0x00, 0x12 }; // Example ARC
                byte[] arpc = GenerateARPCMchip(ac, arc, udk);


                EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());

                // Construct Mchip CDOL data with ARPC
                byte[] cdolArpcData = simulator.ConstructCDOLMchipARPC(arpc, arc);
                APDUResponse tcResponse = simulator.GenerateAC(0x40, cdolArpcData); // 0x40 indicates TC
                tcResponse = ProcessResponse(tcResponse); // Process the response to handle additional data

                if (tcResponse.SW1 != 0x90)
                {
                    throw new Exception("Failed to generate TC with Issuer Authentication Data.");
                }

                // Parse the GAC response
                var (tcCid, tcAtc, tcAc, tcIad) = ParseGACResponseFormat2(tcResponse.Data);
                _transactionLogs.Add($"CID: {tcCid}\nATC: {BitConverter.ToString(tcAtc).Replace("-", "")}\nAC: {BitConverter.ToString(tcAc).Replace("-", "")}");

                // Extract the last 6 bytes of IAD as CVR
                byte[] cvr = tcIad.Skip(2).Take(6).ToArray(); // Adjusting the CVR extraction

                byte[] transactionData = trimmedCdol1Data.Concat(aip).Concat(tcAtc).Concat(cvr).ToArray();
                _transactionLogs.Add($"Constructed Txn Data for Mchip ARPC: {BitConverter.ToString(transactionData).Replace("-", "")}");
                Debug.WriteLine($"Constructed Txn Data for Mchip ARPC: {BitConverter.ToString(transactionData).Replace("-", "")}");

                // Verify TC
                if (!VerifyApplicationCryptogramMC(tcAc, transactionData, skac))
                {
                    throw new Exception("ARPC verification failed.");
                }
                else
                {
                    _transactionLogs.Add("ARPC verification succeeded.");
                }
            }
            catch (Exception ex)
            {
                _transactionLogs.Add($"Error during ARPC generation: {ex.Message}");
                throw;
            }
        }


        // ----------------------ALL ARQC/ARPC--------------------------------------------//
        //--------------------------HELPERS-----------------------------------------------//

        //-----CRYTPO HELPERS TODO: MOVE CRYPTO HELPERS to CryptoFunctions.cs and update related
        //ARQC/ARPC methods to abstract away from this class 

        private static ICryptoTransform CreateDESEncryptor(byte[] key)
        {
            var des = DES.Create();
            des.Key = key;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            return des.CreateEncryptor();
        }

        private static ICryptoTransform CreateDESDecryptor(byte[] key)
        {
            var des = DES.Create();
            des.Key = key;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            return des.CreateDecryptor();
        }

        private static byte[] Xor(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }
        //---------- END OF CRYPTO HELPERS----------------------------------------------------

        //-----GENERATE AC RESPONSE PARSERS

        private (byte cid, byte[] atc, byte[] ac, byte[] iad) ParseGACResponse(byte[] responseData)
        {
            if (responseData.Length == 0)
                throw new Exception("Empty response data");

            byte cid = 0; // Initialize cid to a default value
            byte[] atc = new byte[2];
            byte[] ac = new byte[8];
            byte[] iad = null;

            Debug.WriteLine($"Response Data: {BitConverter.ToString(responseData).Replace("-", "")}");

            if (responseData[0] == 0x80)
            {
                // Format 1
                int index = 1;

                // Adjust parsing logic according to the existing format specifications
                cid = responseData[index + 1]; // CID is now the byte after 8012

                // ATC is now the 2 bytes after the new CID
                Array.Copy(responseData, index + 2, atc, 0, 2);

                // AC is now the next 8 bytes after the new ATC
                Array.Copy(responseData, index + 4, ac, 0, 8);

                // IAD is now the remaining bytes after AC
                int iadStartIndex = index + 12;
                if (iadStartIndex < responseData.Length)
                {
                    iad = new byte[responseData.Length - iadStartIndex];
                    Array.Copy(responseData, iadStartIndex, iad, 0, iad.Length);
                }

                Debug.WriteLine($"Parsed CID: {cid}");
                Debug.WriteLine($"Parsed ATC: {BitConverter.ToString(atc).Replace("-", "")}");
                Debug.WriteLine($"Parsed AC: {BitConverter.ToString(ac).Replace("-", "")}");
                Debug.WriteLine($"Parsed IAD: {BitConverter.ToString(iad).Replace("-", "")}");

            }
            else if (responseData[0] == 0x77)
            {
                // Format 2
                int index = 1; // Start after the tag byte
                int length = responseData[index++]; // Length byte

                while (index < responseData.Length)
                {
                    // Read the tag (assuming tag can be multi-byte)
                    byte tag1 = responseData[index++];
                    byte tag2 = responseData[index++]; // Read the second byte for tags that are multi-byte
                    int tag = (tag1 << 8) | tag2;

                    int valueLength = responseData[index++];
                    byte[] value = new byte[valueLength];
                    Array.Copy(responseData, index, value, 0, valueLength);
                    index += valueLength;

                    switch (tag)
                    {
                        case 0x9F27: // CID
                            cid = value[0];
                            Debug.WriteLine($"Parsed CID: {cid}");
                            break;
                        case 0x9F36: // ATC
                            atc = value;
                            Debug.WriteLine($"Parsed ATC: {BitConverter.ToString(atc).Replace("-", "")}");
                            break;
                        case 0x9F26: // AC
                            ac = value;
                            Debug.WriteLine($"Parsed AC: {BitConverter.ToString(ac).Replace("-", "")}");
                            break;
                        case 0x9F10: // IAD
                            iad = value;
                            Debug.WriteLine($"Parsed IAD: {BitConverter.ToString(iad).Replace("-", "")}");
                            break;
                    }
                }
            }
            else
            {
                throw new Exception("Unknown response format");
            }

            return (cid, atc, ac, iad);
        }


        private (byte[] cid, byte[] atc, byte[] ac, byte[] iad) ParseGACResponseFormat2(byte[] responseData)
        {
            ASN1 asn1Response = new ASN1(responseData);
            Asn1NodeViewModel root = new Asn1NodeViewModel("Root");
            BuildAsn1Tree(asn1Response, root);

            byte[] cid = null;
            byte[] atc = null;
            byte[] ac = null;
            byte[] iad = null;

            ExtractTagValuesFormat2(root, ref cid, ref atc, ref ac, ref iad);
            Debug.WriteLine($"Parsed CID: {BitConverter.ToString(cid).Replace("-", "")}");
            Debug.WriteLine($"Parsed ATC: {BitConverter.ToString(atc).Replace("-", "")}");
            Debug.WriteLine($"Parsed AC: {BitConverter.ToString(ac).Replace("-", "")}");
            Debug.WriteLine($"Parsed IAD: {BitConverter.ToString(iad).Replace("-", "")}");

            return (cid, atc, ac, iad);

        }

        private void ExtractTagValuesFormat2(Asn1NodeViewModel node, ref byte[] cid, ref byte[] atc, ref byte[] ac, ref byte[] iad)
        {
            foreach (var child in node.Children)
            {
                switch (child.Name)
                {
                    case "9F27":
                        cid = child.Value;
                        break;
                    case "9F36":
                        atc = child.Value;
                        break;
                    case "9F26":
                        ac = child.Value;
                        break;
                    case "9F10":
                        iad = child.Value;
                        break;
                    default:
                        ExtractTagValuesFormat2(child, ref cid, ref atc, ref ac, ref iad);
                        break;
                }
            }
        }
        private byte[] PadDataMethod1(byte[] data)
        {
            int blockSize = 8;
            int padLength = blockSize - (data.Length % blockSize);
            if (padLength == blockSize)
            {
                return data; // Already a multiple of 8 bytes, no padding needed
            }

            byte[] paddedData = new byte[data.Length + padLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
            // The rest of the paddedData array is already initialized to zero
            Debug.WriteLine($"Padding Length: {padLength}");
            Debug.WriteLine($"Padded Data (Post Padding): {BitConverter.ToString(paddedData).Replace("-", "")}");
            return paddedData;
        }

        private byte[] PadDataMethod2(byte[] data)
        {
            List<byte> paddedData = new List<byte>(data);
            paddedData.Add(0x80); // Add mandatory '80' byte
            while (paddedData.Count % 8 != 0)
            {
                paddedData.Add(0x00); // Pad with '00' bytes
            }
            return paddedData.ToArray();
        }

        private void BuildAsn1Tree(ASN1 asn, Asn1NodeViewModel parentNode)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in asn.Tag)
            {
                sb.AppendFormat("{0:X2}", b);
            }

            string tagHex = sb.ToString().ToUpper();  // Convert tag to uppercase hex string

            Asn1NodeViewModel node = new Asn1NodeViewModel(tagHex)
            {
                Asn1Data = asn.Value,
                Value = asn.Value
            };

            parentNode.Children.Add(node);

            if (asn.Count > 0)
            {
                for (int i = 0; i < asn.Count; i++)
                {
                    ASN1 child = asn[i];
                    BuildAsn1Tree(child, node);
                }
            }
        }


        public byte[] GenerateARPC(byte[] arqc, byte[] arc, byte[] udk)
        {
            // Concatenate ARQC and ARC
            byte[] arpcData = arqc.Concat(arc).ToArray();
            Debug.WriteLine($"ARPC Data: {BitConverter.ToString(arpcData).Replace("-", "")}");

            // Use the same MAC calculation process as for ARQC, with the ARPC data
            byte[] arpc = CalculateApplicationCryptogram(arpcData, udk);
            Debug.WriteLine($"Generated ARPC: {BitConverter.ToString(arpc).Replace("-", "")}");

            return arpc;
        }

        public byte[] GenerateARPCMchip(byte[] arqc, byte[] arc, byte[] udk)
        {
            // Check lengths of input arrays
            if (arqc.Length < 8 || arc.Length < 2 || udk.Length < 16)
            {
                Debug.WriteLine($"Invalid input lengths: ARQC Length: {arqc.Length}, ARC Length: {arc.Length}, UDK Length: {udk.Length}");
                throw new ArgumentException("Input arrays are not of the expected lengths.");
            }

            // Concatenate ARQC and ARC
            byte[] arpcData = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                arpcData[i] = (byte)(arqc[i] ^ arc[i % arc.Length]);
            }
            Debug.WriteLine($"ARPC Data after XOR: {BitConverter.ToString(arpcData).Replace("-", "")}");

            byte[] keyA = udk.Take(8).ToArray();
            byte[] keyB = udk.Skip(8).Take(8).ToArray();

            // Perform Triple DES encryption
            byte[] intermed1;
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                intermed1 = desEncryptor.TransformFinalBlock(arpcData, 0, 8);
            }
            Debug.WriteLine($"Intermediate 1 after Encrypt: {BitConverter.ToString(intermed1).Replace("-", "")}");

            byte[] intermed2;
            using (var desDecryptor = CreateDESDecryptor(keyB))
            {
                intermed2 = desDecryptor.TransformFinalBlock(intermed1, 0, 8);
            }
            Debug.WriteLine($"Intermediate 2 after Decrypt: {BitConverter.ToString(intermed2).Replace("-", "")}");

            byte[] finalArpc;
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                finalArpc = desEncryptor.TransformFinalBlock(intermed2, 0, 8);
            }
            Debug.WriteLine($"Final ARPC after Encrypt: {BitConverter.ToString(finalArpc).Replace("-", "")}");

            return finalArpc;
        }




        public byte[] GenerateARPC2(byte[] arqc, byte[] arc, byte[] skac)
        {
            // Concatenate ARQC and CSU
            byte[] csu = { 0x03, 0x92, 0x00, 0x00 };
            byte[] arpcData = arqc.Concat(csu).ToArray();
            Debug.WriteLine($"ARPC Data: {BitConverter.ToString(arpcData).Replace("-", "")}");

            // Use the same MAC calculation process as for ARQC, with the ARPC data
            byte[] arpc = CalculateApplicationCryptogramCVN18(arpcData, skac);
            Debug.WriteLine($"Generated ARPC: {BitConverter.ToString(arpc).Replace("-", "")}");

            return arpc;
        }



        //-----Application Cryptogram Matching/validation METHODS
        public bool VerifyApplicationCryptogram(byte[] arqc, byte[] transactionData, byte[] sessionKey)
        {
            // Calculate expected ARQC
            byte[] expectedArqc = CalculateApplicationCryptogram(transactionData, sessionKey);

            // Convert byte arrays to hex strings for easier readability
            string calculatedArqcHex = BitConverter.ToString(expectedArqc).Replace("-", "");
            string receivedArqcHex = BitConverter.ToString(arqc).Replace("-", "");
            string sessionKeyHex = BitConverter.ToString(sessionKey).Replace("-", "");

            // Debug output
            Debug.WriteLine($"Session Key: {sessionKeyHex}");
            Debug.WriteLine($"Calculated ARQC: {calculatedArqcHex}");
            Debug.WriteLine($"Received ARQC: {receivedArqcHex}");

            // Compare expected ARQC with received ARQC
            return arqc.SequenceEqual(expectedArqc);
        }

        public bool VerifyApplicationCryptogramCVN18(byte[] arqc, byte[] transactionData, byte[] sessionKey)
        {
            // Calculate expected ARQC
            byte[] expectedArqc = CalculateApplicationCryptogramCVN18(transactionData, sessionKey);

            // Convert byte arrays to hex strings for easier readability
            string calculatedArqcHex = BitConverter.ToString(expectedArqc).Replace("-", "");
            string receivedArqcHex = BitConverter.ToString(arqc).Replace("-", "");
            string sessionKeyHex = BitConverter.ToString(sessionKey).Replace("-", "");

            // Debug output
            Debug.WriteLine($"Session Key: {sessionKeyHex}");
            Debug.WriteLine($"Calculated ARQC: {calculatedArqcHex}");
            Debug.WriteLine($"Received ARQC: {receivedArqcHex}");

            // Compare expected ARQC with received ARQC
            return arqc.SequenceEqual(expectedArqc);
        }

        private byte[] CalculateApplicationCryptogram(byte[] transactionData, byte[] udk)
        {
            Debug.WriteLine($"Txn Data: {BitConverter.ToString(transactionData).Replace("-", "")}");
            byte[] keyA = udk.Take(8).ToArray();
            byte[] keyB = udk.Skip(8).Take(8).ToArray();
            byte[] iv = new byte[8];
            byte[] paddedData = PadDataMethod1(transactionData);
            Debug.WriteLine($"Padded Data: {BitConverter.ToString(paddedData).Replace("-", "")}");

            byte[] mac = new byte[8];
            byte[] intermediate = iv;

            // Process each 8-byte block
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                for (int i = 0; i < paddedData.Length; i += 8)
                {
                    byte[] block = paddedData.Skip(i).Take(8).ToArray();
                    intermediate = desEncryptor.TransformFinalBlock(Xor(block, intermediate), 0, 8);
                    Debug.WriteLine($"Block {i / 8}: {BitConverter.ToString(intermediate).Replace("-", "")}");
                }
            }

            // Apply ISO/IEC 9797-1 Algorithm 3 to the final block
            using (var desDecryptor = CreateDESDecryptor(keyB))
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                byte[] decryptedBlock = desDecryptor.TransformFinalBlock(intermediate, 0, 8);
                Debug.WriteLine($"Decrypted Final Block: {BitConverter.ToString(decryptedBlock).Replace("-", "")}");

                byte[] finalMac = desEncryptor.TransformFinalBlock(decryptedBlock, 0, 8);
                Debug.WriteLine($"Encrypted Final Block: {BitConverter.ToString(finalMac).Replace("-", "")}");

                return finalMac;
            }
        }
        private byte[] CalculateApplicationCryptogramCVN18(byte[] transactionData, byte[] udk)
        {
            byte[] keyA = udk.Take(8).ToArray();
            byte[] keyB = udk.Skip(8).Take(8).ToArray();
            byte[] iv = new byte[8];
            byte[] paddedData = PadDataMethod2(transactionData);
            Debug.WriteLine($"Padded Data: {BitConverter.ToString(paddedData).Replace("-", "")}");

            byte[] mac = new byte[8];
            byte[] intermediate = iv;

            // Process each 8-byte block
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                for (int i = 0; i < paddedData.Length; i += 8)
                {
                    byte[] block = paddedData.Skip(i).Take(8).ToArray();
                    intermediate = desEncryptor.TransformFinalBlock(Xor(block, intermediate), 0, 8);
                    Debug.WriteLine($"Block {i / 8}: {BitConverter.ToString(intermediate).Replace("-", "")}");
                }
            }

            // Apply ISO/IEC 9797-1 Algorithm 3 to the final block
            using (var desDecryptor = CreateDESDecryptor(keyB))
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                byte[] decryptedBlock = desDecryptor.TransformFinalBlock(intermediate, 0, 8);
                Debug.WriteLine($"Decrypted Final Block: {BitConverter.ToString(decryptedBlock).Replace("-", "")}");

                byte[] finalMac = desEncryptor.TransformFinalBlock(decryptedBlock, 0, 8);
                Debug.WriteLine($"Encrypted Final Block: {BitConverter.ToString(finalMac).Replace("-", "")}");

                return finalMac;
            }
        }

        public bool VerifyApplicationCryptogramMC(byte[] arqc, byte[] transactionData, byte[] sessionKey)
        {
            // Calculate expected ARQC
            byte[] expectedArqc = CalculateApplicationCryptogramMC(transactionData, sessionKey);

            // Convert byte arrays to hex strings for easier readability
            string calculatedArqcHex = BitConverter.ToString(expectedArqc).Replace("-", "");
            string receivedArqcHex = BitConverter.ToString(arqc).Replace("-", "");
            string sessionKeyHex = BitConverter.ToString(sessionKey).Replace("-", "");

            // Debug output
            Debug.WriteLine($"Session Key: {sessionKeyHex}");
            Debug.WriteLine($"Calculated ARQC: {calculatedArqcHex}");
            Debug.WriteLine($"Received ARQC: {receivedArqcHex}");

            // Compare expected ARQC with received ARQC
            return arqc.SequenceEqual(expectedArqc);
        }

        private byte[] CalculateApplicationCryptogramMC(byte[] transactionData, byte[] udk)
        {
            byte[] keyA = udk.Take(8).ToArray();
            byte[] keyB = udk.Skip(8).Take(8).ToArray();
            byte[] iv = new byte[8];
            byte[] paddedData = PadDataMethod2(transactionData);
            Debug.WriteLine($"Padded Data: {BitConverter.ToString(paddedData).Replace("-", "")}");

            byte[] mac = new byte[8];
            byte[] intermediate = iv;

            // Process each 8-byte block
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                for (int i = 0; i < paddedData.Length; i += 8)
                {
                    byte[] block = paddedData.Skip(i).Take(8).ToArray();
                    intermediate = desEncryptor.TransformFinalBlock(Xor(block, intermediate), 0, 8);
                    Debug.WriteLine($"Block {i / 8}: {BitConverter.ToString(intermediate).Replace("-", "")}");
                }
            }

            // Apply ISO/IEC 9797-1 Algorithm 3 to the final block
            using (var desDecryptor = CreateDESDecryptor(keyB))
            using (var desEncryptor = CreateDESEncryptor(keyA))
            {
                byte[] decryptedBlock = desDecryptor.TransformFinalBlock(intermediate, 0, 8);
                Debug.WriteLine($"Decrypted Final Block: {BitConverter.ToString(decryptedBlock).Replace("-", "")}");

                byte[] finalMac = desEncryptor.TransformFinalBlock(decryptedBlock, 0, 8);
                Debug.WriteLine($"Encrypted Final Block: {BitConverter.ToString(finalMac).Replace("-", "")}");

                return finalMac;
            }
        }


        //UTILITIES & GENERIC HELPERS

        public string[] GetTransactionLogs()
        {
            return _transactionLogs.ToArray();
        }

        public CardData GetCardData()
        {
            return _cardData;
        }



        private static byte[] HexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        private APDUResponse ProcessResponse(APDUResponse response)
        {
            var logger = new Logger();

            while (response.SW1 == 0x61)
            {
                logger.WriteLog("Status indicates more data is available. Fetching...");
                APDUCommand apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
                response = _cardReaderService.GetCardReader().Transmit(apdu);
                logger.WriteLog($"Received APDU Response with SW1 = {response.SW1:X2}, SW2 = {response.SW2:X2}.");
            }

            return response;
        }
    }
}
