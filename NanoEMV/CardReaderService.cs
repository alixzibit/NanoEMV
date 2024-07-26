using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using NanoEMV;
using System.Collections.ObjectModel;

namespace NanoEMV.Services
{
    public interface ICardReaderService
    {
        CardData ReadCard(string readerName, HashSet<string> tags);
        void LoadTagsFromResource();
        HashSet<string> GetDesiredTags();
    }

    public class CardReaderService : ICardReaderService
    {
        private PCSCReader _cardReader;
        private Logger _logger = new Logger();
        private HashSet<string> desiredTags = new HashSet<string>();

        public CardData ReadCard(string readerName, HashSet<string> tags)
        {
            desiredTags = tags;
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
                _logger.WriteLog($"Received response: SW1 = {response.SW1}, SW2 = {response.SW2}");

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

                    _logger.WriteLog($"Application Selection response: SW1 = {response.SW1}, SW2 = {response.SW2}");

                    if (!appSelection.IsSelectionSuccessful(response))
                    {
                        throw new InvalidOperationException("Failed to select the application by AID.");
                    }
                }

                ProcessingOptions processingOptions = new ProcessingOptions(_cardReader);
                response = processingOptions.GetProcessingOptions();

                if (response.SW1 == 0x90 && response.Data != null && response.Data.Length > 0)
                {
                    ASN1 asn1Response = new ASN1(response.Data);
                    AddRecordNodes(asn1Response, rootNodeCollection, cardData);
                }
                else
                {
                    AddResponseNodes(response, rootNodeCollection);
                }

                _logger.WriteLog($"Processing options response: SW1 = {response.SW1}, SW2 = {response.SW2}");

                if (!processingOptions.IsGPOResponseSuccessful(response))
                {
                    throw new InvalidOperationException("Failed to get processing options.");
                }

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

        //public void LoadTagsFromResource()
        //{
        //    string appRoot = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        //    string filePath = Path.Combine(appRoot, "TagList.xml");

        //    if (!File.Exists(filePath))
        //    {
        //        throw new FileNotFoundException($"Tag list file not found at '{filePath}'.");
        //    }

        //    var doc = XDocument.Load(filePath);
        //    foreach (var element in doc.Descendants("Tag"))
        //    {
        //        var tag = element.Attribute("Tag")?.Value;
        //        if (!string.IsNullOrEmpty(tag))
        //        {
        //            desiredTags.Add(tag);
        //        }
        //    }
        //}

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
                    var doc = XDocument.Load(reader);
                    foreach (var element in doc.Descendants("Tag"))
                    {
                        var tag = element.Attribute("Tag")?.Value;
                        if (!string.IsNullOrEmpty(tag))
                        {
                            desiredTags.Add(tag);
                        }
                    }
                }
            }
        }

        public HashSet<string> GetDesiredTags()
        {
            return desiredTags;
        }

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

            if (desiredTags.Contains(tagHex))
            {
                if (tagHex == "50" || tagHex == "5F20")
                {
                    StringBuilder valueSb = new StringBuilder();
                    foreach (byte b in asn.Value)
                    {
                        valueSb.AppendFormat("{0:X2}", b);
                    }
                    string hexValue = valueSb.ToString();
                    cardData.TagValues[tagHex] = HexStringToAscii(hexValue);
                }
                else if (tagHex == "5A")
                {
                    cardData.TagValues[tagHex] = BcdToString(asn.Value);
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

                    cardData.TagValues[tagHex] = formattedDate;
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


    public class CardData
    {
        public Dictionary<string, string> TagValues { get; private set; } = new Dictionary<string, string>();
        public Dictionary<string, string> TagDescriptions { get; private set; } = new Dictionary<string, string>();

        public void AddTagValue(string tag, string value, string description)
        {
            TagValues[tag] = value;
            TagDescriptions[tag] = description;
        }

        public string GetTagValue(string tag)
        {
            return TagValues.ContainsKey(tag) ? TagValues[tag] : null;
        }

        public string GetTagDescription(string tag)
        {
            return TagDescriptions.ContainsKey(tag) ? TagDescriptions[tag] : null;
        }
    }
}
