using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using NanoEMV;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Claims;

namespace NanoEMV.Services
{
    public interface ICardReaderService2
    {
        CardData ReadCard(string readerName, HashSet<string> tags);
        CardData ReadAllCardData(string readerName);
        CardData ReadCardContactless(string readerName);
        void LoadTagsFromResource();
        HashSet<string> GetDesiredTags();
        PCSCReader GetCardReader();
        CardData GetDataRead(string readerName, string emvTag);
        List<string> GetAvailableReaders();
    }

    public class CardReaderService2 : ICardReaderService2
    {
        private PCSCReader _cardReader;
        private Logger _logger = new Logger();
        private HashSet<string> desiredTags = new HashSet<string>();
        private CardData cardData = new CardData();

        public List<string> GetAvailableReaders()
        {
            _cardReader = new PCSCReader();
            return _cardReader.Readers.ToList();
        }

        public CardData ReadCard(string readerName, HashSet<string> tags)
        {
            desiredTags = tags;
            return ReadCardInternal(readerName);
        }

        public CardData ReadAllCardData(string readerName)
        {
            desiredTags = null; /*new HashSet<string>();*/ // Fetch all tags if no specific tags are provided
            return ReadCardInternal(readerName);
        }

        //Read Contactless methods
        public CardData ReadCardContactless(string readerName)
        {
            desiredTags = null;
            return ReadCTL(readerName);
        }



        public PCSCReader GetCardReader() // Implement this method
        {
            return _cardReader;
        }




        private CardData ReadCTL(string readerName)
        {
            var cardData = new CardData();
            var rootNodeCollection = new ObservableCollection<Asn1NodeViewModel>();

            try
            {
                _logger.WriteLog("=============================Identifying card in Contactless interface=============================");
                _cardReader = new PCSCReader();
                if (string.IsNullOrEmpty(readerName))
                {
                    throw new ArgumentException("Reader name cannot be null or empty.", nameof(readerName));
                }

                _logger.WriteLog($"Selected Reader: {readerName}");
                bool success = _cardReader.Connect(readerName);
                _logger.WriteLog(success ? "Successfully connected to card reader." : "Failed to connect to card reader.");

                if (!success)
                {
                    throw new InvalidOperationException("Failed to connect to the card reader.");
                }

                _cardReader.WarmReset();
                byte[] pse = Encoding.ASCII.GetBytes("2PAY.SYS.DDF01");
                APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, 0x00);
                APDUResponse response = _cardReader.Transmit(apdu);

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    string visaAid = "A0000000031010";
                    string mastercardAid = "A0000000041010";
                    string himyanAid = "A0000008841010";

                    byte[] visaAidBytes = StringToByteArray(visaAid);
                    byte[] mastercardAidBytes = StringToByteArray(mastercardAid);
                    byte[] himyanAidBytes = StringToByteArray(himyanAid);

                    if (ByteArrayContains(response.Data, visaAidBytes))
                    {
                        _logger.WriteLog($"VISA Contactless card detected");
                        desiredTags = null;
                        return ReadCardVISA_CTL(readerName);
                    }
                    if (ByteArrayContains(response.Data, mastercardAidBytes))
                    {
                        _logger.WriteLog($"MCHIP Contactless card detected");
                        _cardReader.WarmReset();
                        desiredTags = null;
                        return ReadCardMCHIP_CTL(readerName);
                    }
                    if  (ByteArrayContains(response.Data, himyanAidBytes))
                    {
                        _logger.WriteLog($"Himyan Contactless card detected");
                        _cardReader.WarmReset();
                        desiredTags = null;
                        return ReadCardMCHIP_CTL(readerName);
                    }
                    else
                        _logger.WriteLog($"Failed to read contactless card - If the inserted card is a valid EMV spec card, please check if contactless interface is locked");
                        throw new InvalidOperationException("Failed to read contactless card.");
                }
            }
            catch (PCSCException ex)
            {
                _logger.WriteLog($"PCSC Exception: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"General Exception: {ex.Message}");
                throw;
            }
            
            return new CardData(); 
        }


        private CardData ReadCardInternal(string readerName)
        {
            var cardData = new CardData();
            var rootNodeCollection = new ObservableCollection<Asn1NodeViewModel>();

            try
            {
                _logger.WriteLog("=============================Reading Card on Contact interface=============================");

                _cardReader = new PCSCReader();
                if (string.IsNullOrEmpty(readerName))
                {
                    throw new ArgumentException("Reader name cannot be null or empty.", nameof(readerName));
                }

                _logger.WriteLog($"Selected Reader: {readerName}");
                bool success = _cardReader.Connect(readerName);
                _logger.WriteLog(success ? "Successfully connected to card reader." : "Failed to connect to card reader.");

                if (!success)
                {
                    throw new InvalidOperationException("Failed to connect to the card reader.");
                }

                _cardReader.ColdReset();

                byte[] pse = Encoding.ASCII.GetBytes("1PAY.SYS.DDF01");
                _logger.WriteLog($"Sending APDU command to select the PSE: {BitConverter.ToString(pse)}");

                APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, (byte)pse.Length);
                APDUResponse response = _cardReader.Transmit(apdu);
                _logger.WriteLog($"Received response:  SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    AddResponseNodes(response, rootNodeCollection);
                }

                if (response.SW1 != 0x90)
                {
                    AIDSelection aidSelector = new AIDSelection(_cardReader);
                    var aidSelectionResult = aidSelector.SelectKnownAID();
                    response = aidSelectionResult.Response;

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Selected AID: {BitConverter.ToString(aidSelectionResult.AID)}");
                    string extractedAID = BitConverter.ToString(aidSelectionResult.AID).Replace("-", "");
                    cardData.AddTagValue("4F", extractedAID, "Application Identifier");

                    if (response == null)
                    {
                        throw new InvalidOperationException("Failed to select a known AID.");
                    }

                    ApplicationSelection appSelection = new ApplicationSelection(_cardReader);
                    response = appSelection.SelectApplication(aidSelectionResult.AID);

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Application Selection response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                    if (!appSelection.IsSelectionSuccessful(response))
                    {
                        throw new InvalidOperationException("Failed to select the application by AID.");
                    }
                }

                ProcessingOptions processingOptions = new ProcessingOptions(_cardReader);
                response = processingOptions.GetProcessingOptions();

                _logger.WriteLog($"Processing options response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (!processingOptions.IsGPOResponseSuccessful(response))
                {
                    throw new InvalidOperationException("Failed to get processing options.");
                }

                // Store the AIP value in the dictionary
                //if (desiredTags.Contains("82"))
                //{
                    string extractedAip = BitConverter.ToString(processingOptions.AIP).Replace("-", "");
                    cardData.AddTagValue("82", extractedAip, "Application Interchange Profile");
                //}

                // Store the AFL value in the dictionary
              
                    string extractedAfl = BitConverter.ToString(processingOptions.AFL).Replace("-", "");
                    cardData.AddTagValue("94", extractedAfl, "Application File Locator");
                

                var records = processingOptions.ReadRecords;

                _logger.WriteLog($"Number of records retrieved: {records.Count}");

                if (records.Count == 0)
                {
                    throw new InvalidOperationException("No records retrieved.");
                }

                foreach (var record in records)
                {
                    ASN1 asn1Response = new ASN1(record.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }

                return cardData;
                
            }
            catch (PCSCException ex)
            {
                _logger.WriteLog($"PCSC Exception: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"General Exception: {ex.Message}");
                throw;
            }
        }

       //helpers

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static bool ByteArrayContains(byte[] source, byte[] pattern)
        {
            for (int i = 0; i < source.Length - pattern.Length + 1; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (source[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found) return true;
            }
            return false;
        }

        private CardData ReadCardVISA_CTL(string readerName)
        {
            var cardData = new CardData();
            var rootNodeCollection = new ObservableCollection<Asn1NodeViewModel>();

            try
            {
                _logger.WriteLog("=============================Reading VISA Card on Contactless interface=============================");
                _cardReader = new PCSCReader();
                if (string.IsNullOrEmpty(readerName))
                {
                    throw new ArgumentException("Reader name cannot be null or empty.", nameof(readerName));
                }

                _logger.WriteLog($"Selected Reader: {readerName}");
                bool success = _cardReader.Connect(readerName);
                _logger.WriteLog(success ? "Successfully connected to card reader." : "Failed to connect to card reader.");

                if (!success)
                {
                    throw new InvalidOperationException("Failed to connect to the card reader.");
                }

                _cardReader.WarmReset();

                byte[] pse = Encoding.ASCII.GetBytes("2PAY.SYS.DDF01");
                _logger.WriteLog($"Sending APDU command to select the PSE: {BitConverter.ToString(pse)}");

                //APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, (byte)pse.Length);
                APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, 0x00);
                APDUResponse response = _cardReader.Transmit(apdu);
                _logger.WriteLog($"Received response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    AddResponseNodes(response, rootNodeCollection);
                }

                if (response.SW1 != 0x90 || response.SW1 == 0x90)
                {
                    _cardReader.WarmReset();
                    AIDSelection aidSelector = new AIDSelection(_cardReader);
                    var aidSelectionResult = aidSelector.SelectKnownAID();
                    response = aidSelectionResult.Response;

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Selected AID: {BitConverter.ToString(aidSelectionResult.AID)}");
                    string extractedAID = BitConverter.ToString(aidSelectionResult.AID).Replace("-", "");
                    cardData.AddTagValue("4F", extractedAID, "Application Identifier");

                    if (response == null)
                    {
                        throw new InvalidOperationException("Failed to select a known AID.");
                    }

                    //ApplicationSelection appSelection = new ApplicationSelection(_cardReader);
                    //response = appSelection.SelectApplication(aidSelectionResult.AID);

                    //if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    //{
                    //    ASN1 asn1Response = new ASN1(response.Data);
                    //    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    //}
                    //else
                    //{
                    //    AddResponseNodes(response, rootNodeCollection);
                    //}

                    //_logger.WriteLog($"Application Selection response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                    //if (!appSelection.IsSelectionSuccessful(response))
                    //{
                    //    throw new InvalidOperationException("Failed to select the application by AID.");
                    //}
                }

                ProcessingOptionsQVSDC processingOptions = new ProcessingOptionsQVSDC(_cardReader);
                response = processingOptions.GetProcessingOptionsQVSDC();

                _logger.WriteLog($"Processing options response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (!processingOptions.IsGPOResponseSuccessful(response))
                {
                    throw new InvalidOperationException("Failed to get processing options.");
                }

                // Store the AIP value in the dictionary
                //if (desiredTags.Contains("82"))
                //{
                string extractedAip = BitConverter.ToString(processingOptions.AIP).Replace("-", "");
                cardData.AddTagValue("82", extractedAip, "Application Interchange Profile");
                //}

                // Store the AFL value in the dictionary

                string extractedAfl = BitConverter.ToString(processingOptions.AFL).Replace("-", "");
                cardData.AddTagValue("94", extractedAfl, "Application File Locator");

                string extractedPAN = processingOptions.PAN;
                cardData.AddTagValue("5A", extractedPAN, "Primary Account Number (PAN)");
               
                string extractedAC = BitConverter.ToString(processingOptions.AC).Replace("-", "");
                cardData.AddTagValue("9F26", extractedAC, "Application Cryptogram");

                string extractedIAD = BitConverter.ToString(processingOptions.IAD).Replace("-", "");
                cardData.AddTagValue("9F10", extractedIAD, "Issuer Application Data");

                string extractedATC = BitConverter.ToString(processingOptions.ATC).Replace("-", "");
                cardData.AddTagValue("9F36", extractedATC, "Application Transaction Counter");

                string extractedPANSEQ = BitConverter.ToString(processingOptions.PANSEQ);
                cardData.AddTagValue("5F34", extractedPANSEQ, "Application PAN Sequence Number");

                var records = processingOptions.ReadRecords;
                _logger.WriteLog($"Number of records retrieved: {records.Count}");

                if (records.Count == 0)
                {
                    throw new InvalidOperationException("No records retrieved.");
                }

                foreach (var record in records)
                {
                    ASN1 asn1Response = new ASN1(record.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }

                return cardData;

            }
            catch (PCSCException ex)
            {
                _logger.WriteLog($"PCSC Exception: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"General Exception: {ex.Message}");
                throw;
            }
        }

        private CardData ReadCardMCHIP_CTL(string readerName)
        {
            var cardData = new CardData();
            var rootNodeCollection = new ObservableCollection<Asn1NodeViewModel>();

            try
            {
                _logger.WriteLog("=============================Reading MCHIP Card on Contactless interface=============================");
                _cardReader = new PCSCReader();
                if (string.IsNullOrEmpty(readerName))
                {
                    throw new ArgumentException("Reader name cannot be null or empty.", nameof(readerName));
                }

                _logger.WriteLog($"Selected Reader: {readerName}");
                bool success = _cardReader.Connect(readerName);
                _logger.WriteLog(success ? "Successfully connected to card reader." : "Failed to connect to card reader.");

                if (!success)
                {
                    throw new InvalidOperationException("Failed to connect to the card reader.");
                }

                _cardReader.ColdReset();

                byte[] pse = Encoding.ASCII.GetBytes("2PAY.SYS.DDF01");
                _logger.WriteLog($"Sending APDU command to select the PSE: {BitConverter.ToString(pse)}");

                APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, (byte)pse.Length);
                APDUResponse response = _cardReader.Transmit(apdu);
                _logger.WriteLog($"Received response:  SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    AddResponseNodes(response, rootNodeCollection);
                }

                if (response.SW1 != 0x90 || response.SW1 == 0x90)
                {
                    AIDSelection aidSelector = new AIDSelection(_cardReader);
                    var aidSelectionResult = aidSelector.SelectKnownAID();
                    response = aidSelectionResult.Response;

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Selected AID: {BitConverter.ToString(aidSelectionResult.AID)}");
                    string extractedAID = BitConverter.ToString(aidSelectionResult.AID).Replace("-", "");
                    cardData.AddTagValue("4F", extractedAID, "Application Identifier");

                    if (response == null)
                    {
                        throw new InvalidOperationException("Failed to select a known AID.");
                    }

                    _logger.WriteLog($"Application Selection response: SW1: {response.SW1:X2} , SW2:  {response.SW2:X2}");

                    //if (!appSelection.IsSelectionSuccessful(response))
                    //{
                    //    throw new InvalidOperationException("Failed to select the application by AID.");
                    //}
                }

                ProcessingOptionsMPaypass processingOptions = new ProcessingOptionsMPaypass(_cardReader);
                response = processingOptions.GetProcessingOptions();

                _logger.WriteLog($"Processing options response: SW1: {response.SW1:X2} , SW2: {response.SW2:X2}");

                if (!processingOptions.IsGPOResponseSuccessful(response))
                {
                    throw new InvalidOperationException("Failed to get processing options.");
                }

                // Store the AIP value in the dictionary
                //if (desiredTags.Contains("82"))
                //{
                string extractedAip = BitConverter.ToString(processingOptions.AIP).Replace("-", "");
                cardData.AddTagValue("82", extractedAip, "Application Interchange Profile");
                //}

                // Store the AFL value in the dictionary

                string extractedAfl = BitConverter.ToString(processingOptions.AFL).Replace("-", "");
                cardData.AddTagValue("94", extractedAfl, "Application File Locator");

                //string extractedPAN = processingOptions.PAN;
                //cardData.AddTagValue("5A", extractedPAN, "Primary Account Number (PAN)");

                //string extractedAC = BitConverter.ToString(processingOptions.AC).Replace("-", "");
                //cardData.AddTagValue("9F26", extractedAC, "Application Cryptogram");

                //string extractedIAD = BitConverter.ToString(processingOptions.IAD).Replace("-", "");
                //cardData.AddTagValue("9F10", extractedIAD, "Issuer Application Data");

                //string extractedATC = BitConverter.ToString(processingOptions.ATC).Replace("-", "");
                //cardData.AddTagValue("9F36", extractedATC, "Application Transaction Counter");

                //string extractedPANSEQ = BitConverter.ToString(processingOptions.PANSEQ);
                //cardData.AddTagValue("5F34", extractedPANSEQ, "Application PAN Sequence Number");

                var records = processingOptions.ReadRecords;
                _logger.WriteLog($"Number of records retrieved: {records.Count}");

                if (records.Count == 0)
                {
                    throw new InvalidOperationException("No records retrieved.");
                }

                foreach (var record in records)
                {
                    ASN1 asn1Response = new ASN1(record.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }

                return cardData;

            }
            catch (PCSCException ex)
            {
                _logger.WriteLog($"PCSC Exception: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"General Exception: {ex.Message}");
                throw;
            }
        }


        public CardData GetDataRead(string readerName, string emvTag)
        {
            var cardData = new CardData();
            var rootNodeCollection = new ObservableCollection<Asn1NodeViewModel>();

            try
            {
                _logger.WriteLog("=============================Performing GET DATA=============================");

                _cardReader = new PCSCReader();
                if (string.IsNullOrEmpty(readerName))
                {
                    throw new ArgumentException("Reader name cannot be null or empty.", nameof(readerName));
                }

                _logger.WriteLog($"Selected Reader: {readerName}");
                bool success = _cardReader.Connect(readerName);
                _logger.WriteLog(success ? "Successfully connected to card reader." : "Failed to connect to card reader.");

                if (!success)
                {
                    throw new InvalidOperationException("Failed to connect to the card reader.");
                }

                _cardReader.ColdReset();

                byte[] pse = Encoding.ASCII.GetBytes("1PAY.SYS.DDF01");
                _logger.WriteLog($"Sending APDU command to select the PSE: {BitConverter.ToString(pse)}");

                APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, pse, (byte)pse.Length);
                APDUResponse response = _cardReader.Transmit(apdu);
                _logger.WriteLog($"Received response: SW1: {response.SW1:X2}, SW2: {response.SW2:X2}");

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    AddResponseNodes(response, rootNodeCollection);
                }

                if (response.SW1 != 0x90)
                {
                    AIDSelection aidSelector = new AIDSelection(_cardReader);
                    var aidSelectionResult = aidSelector.SelectKnownAID();
                    response = aidSelectionResult.Response;

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Selected AID: {BitConverter.ToString(aidSelectionResult.AID)}");
                    string extractedAID = BitConverter.ToString(aidSelectionResult.AID).Replace("-", "");
                    cardData.AddTagValue("4F", extractedAID, "Application Identifier");

                    if (response == null)
                    {
                        throw new InvalidOperationException("Failed to select a known AID.");
                    }

                    ApplicationSelection appSelection = new ApplicationSelection(_cardReader);
                    response = appSelection.SelectApplication(aidSelectionResult.AID);

                    if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                    {
                        ASN1 asn1Response = new ASN1(response.Data);
                        AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                    }
                    else
                    {
                        AddResponseNodes(response, rootNodeCollection);
                    }

                    _logger.WriteLog($"Application Selection response: SW1: {response.SW1:X2} , SW2: {response.SW2:X2}");

                    if (!appSelection.IsSelectionSuccessful(response))
                    {
                        throw new InvalidOperationException("Failed to select the application by AID.");
                    }
                }

                ProcessingOptions processingOptions = new ProcessingOptions(_cardReader);
                response = processingOptions.GetProcessingOptions();

                _logger.WriteLog($"Processing options response: SW1: {response.SW1:X2} , SW2: {response.SW2:X2}");

                if (!processingOptions.IsGPOResponseSuccessful(response))
                {
                    throw new InvalidOperationException("Failed to get processing options.");
                }
                // Perform Get Data for the specified EMV tag
                var getData = new GetData(_cardReader, _logger);
                response = getData.ExecuteGetDataCommand(emvTag);

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    _logger.WriteLog("Failed to retrieve data for the specified EMV tag.");
                }

                return cardData;
            }
            catch (PCSCException ex)
            {
                _logger.WriteLog($"PCSC Exception: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.WriteLog($"General Exception: {ex.Message}");
                throw;
            } 
        }


        public void LoadTagsFromResource()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "NanoEMV.TagList.xml"; // Adjust this path based on your actual namespace and file location

            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    throw new InvalidOperationException($"Resource '{resourceName}' not found. Available resources: {string.Join(", ", assembly.GetManifestResourceNames())}");
                }

                using (StreamReader reader = new StreamReader(stream))
                {
                    var doc = XDocument.Load(resourceName);
                    foreach (var element in doc.Descendants("Tag"))
                    {
                        var tag = element.Attribute("Tag")?.Value;
                        var description = element.Attribute("Description")?.Value;

                        if (!string.IsNullOrEmpty(tag) && !string.IsNullOrEmpty(description))
                        {
                            _tagDescriptions[tag] = description;
                        }
                    }
                }
            }
        }
        private Dictionary<string, string> _tagDescriptions = new Dictionary<string, string>();

        public Dictionary<string, string> GetTagDescriptions()
        {
            return _tagDescriptions;
        }

        public HashSet<string> GetDesiredTags()
        {
            return desiredTags;
        }

        public class CardData2
        {
            private Dictionary<string, (string Value, string Description)> _tagValues = new Dictionary<string, (string, string)>();

            public void AddTagValue(string tag, string value, string description)
            {
                _tagValues[tag] = (value, description);
            }

            public string GetTagValue(string tag)
            {
                return _tagValues.ContainsKey(tag) ? _tagValues[tag].Value : null;
            }

            public string GetTagDescription(string tag)
            {
                return _tagValues.ContainsKey(tag) ? _tagValues[tag].Description : "Unknown";
            }

            public Dictionary<string, (string Value, string Description)> GetAllTagValues()
            {
                return _tagValues;
            }
        }



        //private void AddRecordNodes(ASN1 asn, ObservableCollection<Asn1NodeViewModel> parentNode, CardData cardData)
        //{
        //    StringBuilder sb = new StringBuilder();
        //    foreach (byte b in asn.Tag)
        //    {
        //        sb.AppendFormat("{0:X2}", b);
        //    }

        //    string tagHex = sb.ToString().ToUpper();

        //    Asn1NodeViewModel node = new Asn1NodeViewModel(tagHex)
        //    {
        //        Asn1Data = asn.Value,
        //        Value = asn.Value
        //    };

        //    parentNode.Add(node);

        //    if (desiredTags == null || desiredTags.Contains(tagHex))
        //    {
        //        string tagValue = BitConverter.ToString(asn.Value).Replace("-", "");

        //        if (tagHex == "50" || tagHex == "5F20")
        //        {
        //            cardData.TagValues[tagHex] = HexStringToAscii(tagValue);
        //        }
        //        else if (tagHex == "5A")
        //        {
        //            cardData.TagValues[tagHex] = BcdToString(asn.Value);
        //        }
        //        else if (tagHex == "5F24")
        //        {
        //            string rawDate = BcdToString(asn.Value);
        //            string formattedDate = "";

        //            if (rawDate.Length == 4)
        //            {
        //                formattedDate = rawDate.Substring(2, 2) + "/" + rawDate.Substring(0, 2);
        //            }
        //            else if (rawDate.Length == 6)
        //            {
        //                formattedDate = rawDate.Substring(2, 2) + "/" + rawDate.Substring(0, 2);
        //            }
        //            else
        //            {
        //                formattedDate = "Invalid Date";
        //            }

        //            cardData.TagValues[tagHex] = formattedDate;
        //        }
        //        else
        //        {
        //            cardData.TagValues[tagHex] = tagValue;
        //        }
        //    }

        //    if (asn.Count > 0)
        //    {
        //        foreach (ASN1 a in asn)
        //        {
        //            AddRecordNodes(a, node.Children, cardData);
        //        }
        //    }
        //}
        private void AddRecordNodes(ASN1 asn, ObservableCollection<Asn1NodeViewModel> parentNode, CardData cardData)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in asn.Tag)
            {
                sb.AppendFormat("{0:X2}", b);
            }

            string tagHex = sb.ToString().ToUpper();

            Asn1NodeViewModel node = new Asn1NodeViewModel(tagHex)
            {
                Asn1Data = asn.Value,
                Value = asn.Value
            };

            parentNode.Add(node);

            if (desiredTags == null || desiredTags.Contains(tagHex))
            {
                string tagValue = BitConverter.ToString(asn.Value).Replace("-", "");
                string tagDescription = _tagDescriptions.ContainsKey(tagHex) ? _tagDescriptions[tagHex] : "Unknown";

                if (tagHex == "50" || tagHex == "5F20")
                {
                    cardData.AddTagValue(tagHex, HexStringToAscii(tagValue), tagDescription);
                }
                else if (tagHex == "5A")
                {
                    cardData.AddTagValue(tagHex, BcdToString(asn.Value), tagDescription);
                }
                else if (tagHex == "5F24")
                {
                    string rawDate = BcdToString(asn.Value);
                    string formattedDate = "";

                    if (rawDate.Length == 4)
                    {
                        formattedDate = rawDate.Substring(2, 2) + "/" + rawDate.Substring(0, 2);
                    }
                    else if (rawDate.Length == 6)
                    {
                        formattedDate = rawDate.Substring(2, 2) + "/" + rawDate.Substring(0, 2);
                    }
                    else
                    {
                        formattedDate = "Invalid Date";
                    }

                    cardData.AddTagValue(tagHex, formattedDate, tagDescription);
                }
                else
                {
                    cardData.AddTagValue(tagHex, tagValue, tagDescription);
                }
            }

            if (asn.Count > 0)
            {
                foreach (ASN1 a in asn)
                {
                    AddRecordNodes(a, node.Children, cardData);
                }
            }
        }

        private void AddResponseNodes(APDUResponse response, ObservableCollection<Asn1NodeViewModel> parentNode)
        {
            if (response == null || response.Data == null || response.Data.Length == 0)
                return;

            Asn1NodeViewModel node = new Asn1NodeViewModel($"SW1 = {response.SW1}, SW2 = {response.SW2}")
            {
                Asn1Data = response.Data,
                Value = response.Data
            };

            parentNode.Add(node);
        }
        private string HexStringToAscii(string hexString)
        {
            StringBuilder ascii = new StringBuilder();

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string hs = hexString.Substring(i, 2);
                ascii.Append(Convert.ToChar(Convert.ToUInt32(hs, 16)));
            }

            return ascii.ToString();
        }

        private string BcdToString(byte[] bcd)
        {
            StringBuilder result = new StringBuilder(bcd.Length * 2);
            foreach (byte b in bcd)
            {
                result.Append((b >> 4) & 0x0F);
                result.Append(b & 0x0F);
            }
            return result.ToString();
        }
    }

}

