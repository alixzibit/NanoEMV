using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static NanoEMV.Services.CardReaderService2;

namespace NanoEMV.Services
{
    public class OfflinePINTxn
    {
        private readonly ICardReaderService2 _cardReaderService;
        private readonly byte[] _offlinePin;
        private CardData _cardData;
        private List<string> _transactionLogs;
        private Logger _logger = new Logger();

        public OfflinePINTxn(ICardReaderService2 cardReaderService, string offlinePin)
        {
            _cardReaderService = cardReaderService ?? throw new ArgumentNullException(nameof(cardReaderService));
            _offlinePin = HexStringToByteArray(offlinePin);
            _transactionLogs = new List<string>();
        }

        public CardData SimulateOfflineTxn(string readerName)
        {
            try
            {
                _transactionLogs.Clear();
                _transactionLogs.Add("Starting Offline PIN - Contact transaction simulation...");
                _logger.WriteLog("============================= Starting Offline PIN - Contact transaction simulation =============================");

                // Step 1: Read all card data
                _cardData = _cardReaderService.ReadAllCardData(readerName);
                _transactionLogs.Add("Card data read successfully.");

                //Step 2: Check tag 8E CVM List if Card supports Offline PIN
                string CVMList = _cardData.GetTagValue("8E");
                if (string.IsNullOrEmpty(CVMList))
                {
                    _logger.WriteLog("CVM List (8E) not found");
                    throw new Exception("CVM List (8E) not found.");
                }

                string CVMDecoded = CVMDecoder.DecodeCVMList(CVMList);
                if (CVMDecoded.Contains("Plaintext PIN verification"))
                {
                    _transactionLogs.Add("CVM List indicates support for Offline-PIN");
                }
                else
                {
                    _transactionLogs.Add("Card does not support Offline-PIN");
                    throw new Exception("Card does not support Offline-PIN.");
                }

                // Step 3: Verify Entered PIN
                bool pinVerified = VerifyOfflinePin();
                if (pinVerified)
                {
                    // Step 4: Generate AC with P1=0x40 (TC)
                    GenerateAC();
                    _transactionLogs.Add("Offline PIN - Contact Transaction Simulated successfully.");
                    _logger.WriteLog("============================= Offline PIN - Contact Transaction Simulated successfully =========================");
                }
                else
                {
                    _transactionLogs.Add("PIN verification failed.");
                    _logger.WriteLog("PIN verification failed.");
                }
            }
            catch (Exception ex)
            {
                _transactionLogs.Add($"Error: {ex.Message}");
                _logger.WriteLog($"Error: {ex.Message}");
            }

            return _cardData; // Return the updated CardData instance
        }

        private bool VerifyOfflinePin()
        {
            var pinVerifier = new VerifyPIN(_cardReaderService, _offlinePin);
            return pinVerifier.Verify();
        }

        private void GenerateAC()
        {
            try
            {
                // Get PAN
                string pan = _cardData.GetTagValue("5A"); // PAN
                if (string.IsNullOrEmpty(pan))
                {
                    _logger.WriteLog("PAN not found.");
                    throw new Exception("PAN not found.");

                }

                string maskedPan = $"{pan.Substring(0, 6)}XXXXXX{pan.Substring(pan.Length - 4)}";
                _transactionLogs.Add($"PAN: {maskedPan}");
                _logger.WriteLog($"PAN: {maskedPan}");


                // Check if the card is MChip based on the PAN starting digit
                if (pan.StartsWith("5") || pan.StartsWith("6"))
                {
                    GenACforMCHIP();
                    return; // MChip-specific logic here if needed
                }


                // PROCESS AS VISA-----------------
                _logger.WriteLog("Starting Generate AC process for VISA.");
                EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());

                // Construct CDOL1 data (specific data elements may vary based on your card setup)
                byte[] cdol1Data = simulator.ConstructCDOLData();

                // Send the Generate AC command with P1 set to 0x40 for TC
                APDUResponse acResponse = simulator.GenerateAC(0x40, cdol1Data);
                _logger.WriteLog("Generate AC command sent.");

                acResponse = ProcessResponse(acResponse);  // Process the response to handle additional data

                if (acResponse.SW1 != 0x90)
                {
                    _logger.WriteLog("Failed to generate AC.");
                    throw new Exception("Failed to generate AC.");
                }

                // Parse the GAC response
                var (cid, atc, ac, iad) = ParseGACResponse(acResponse.Data);
                _transactionLogs.Add($"CID: {cid}\nATC: {BitConverter.ToString(atc).Replace("-", "")}\nAC: {BitConverter.ToString(ac).Replace("-", "")}");
                _logger.WriteLog($"Parsed data from Generate AC response - CID: {cid}, ATC: {BitConverter.ToString(atc).Replace("-", "")}, AC: {BitConverter.ToString(ac).Replace("-", "")}");

                string extractedIAD = BitConverter.ToString(iad).Replace("-", "");
                _cardData.AddTagValue("9F10", extractedIAD, "Issuer Application Data");
            }


            catch (Exception ex)
            {
                _transactionLogs.Add($"Error during transaction simulation: {ex.Message}");
                _logger.WriteLog($"Error during transaction simulation: {ex.Message}");
                throw;
            }
        }

        private void GenACforMCHIP()
        {
            _logger.WriteLog("Starting Generate AC process for MCHIP.");
            _transactionLogs.Add($"Starting Generate AC process for MCHIP..");
            try
            {
                EMVTransactionSimulator simulator = new EMVTransactionSimulator(_cardReaderService.GetCardReader());

                // Retrieve the length of the 8C tag from extractedTagValues
                if (_cardData.GetTagValue("8C") is string tag8C)
                {
                    int length8C = tag8C.Length;

                    // Generate ARQC
                    byte[] cdol1Data = simulator.ConstructCDOLDataMchip(length8C);
                    bool cdol1withTTMCD = length8C > 66;

                    APDUResponse acResponse = simulator.GenerateAC(0x80, cdol1Data); // 0x80 indicates ARQC
                    _logger.WriteLog($"Sending Generate AC command......");
                    acResponse = ProcessResponse(acResponse); // Process the response to handle additional data

                    if (acResponse.SW1 != 0x90)
                    {
                        _transactionLogs.Add("Failed to generate AC.");
                        _logger.WriteLog("Failed to generate AC.");
                        throw new InvalidOperationException("Failed to generate AC.");
                    }

                    // Parse the GAC response
                    var (cid, atc, ac, iad) = ParseGACResponseFormat2(acResponse.Data);
                    _transactionLogs.Add($"ATC: {BitConverter.ToString(atc).Replace("-", "")}\nAC: {BitConverter.ToString(ac).Replace("-", "")}\n");
                    _logger.WriteLog($"Parsed data from Generate AC response - ATC: {BitConverter.ToString(atc).Replace("-", "")}  AC: {BitConverter.ToString(ac).Replace("-", "")}");
                    string extractedIAD = BitConverter.ToString(iad).Replace("-", "");
                    _cardData.AddTagValue("9F10", extractedIAD, "Issuer Application Data");
                }
            }


            catch (Exception ex)
            {
                _logger.WriteLog($"Error during transaction simulation: {ex.Message}");
                _transactionLogs.Add($"Error during transaction simulation: {ex.Message}");
                throw;
            }

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

        private byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length / 2)
                .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                .ToArray();
        }

        public string[] GetTransactionLogs()
        {
            return _transactionLogs.ToArray();
        }

        public CardData GetCardData()
        {
            return _cardData;
        }
    }
}
