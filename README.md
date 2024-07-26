NanoEMV .NET Library SDK                                                                                                  

Last Document Update
11/07/2024
Last Reference Library Update
11/07/2020

Resources for this library can be found here NanoEMV .NET Library SDK and development
NanoEMVTest application is also updated in parallel to NanoEMV library development to demonstrate NanoEMV library features
Overview
The NanoEMV.dll is a .NET library designed for reading and processing EMV card data. It provides functionalities to interact with EMV card readers, read card data, and perform EMV transactions, including generating and validating Authorization Request Cryptograms (ARQC). 
11.7.24 - Now NanoEMVTest application demonstrates how a VISA based contact card data can be checked against VPA and NanoPerso XML file
Note: The library is under development, and revisions to this document can be expected as more functionalities and features are added in the future. 
Current Feature Set
1. Detect and Establish Connections to PCSC Card Readers
- The library can detect connected PCSC-compatible card readers and establish a connection for communication.
2. Read Card and Return Data with Specified AFL/SFI EMV Tags
- Users can specify a set of EMV tags to read from the card. The library will return the corresponding data for these tags.
3. Read Card and Return All Available AFL/SFI EMV Data
- The library can read all available EMV data from the card without the need for specifying tags.
4. Generate and Authenticate ARQC (Authorization Request Cryptogram)
- The library includes functionality to generate and validate ARQC for performing online EMV transactions.
5. Interpret and Parse Transaction Logs
- The library can interpret and parse transaction logs generated during the card reading and transaction processes, extracting meaningful data.
6. Display Card Data in a DataGrid or Similar View
- For UI applications, the library provides methods to convert card data into a format that can be easily bound to UI controls like DataGrids.
New Updates 11.7.24
7. Library is now capable of simulating full Online transaction with ARPC
- OnlineTxnSim in NanoEMV Services now accepts a Boolean parameter which informs the method to perform ARPC in addition to ARQC only to simulate a full Online Transaction with Terminal Certificate 
8. Implemented GET DATA method for retrieving non-SFI EMV tags
-The library now supports the GetDataRead method for retrieving specific EMV tags that are not stored in AFL based Short File Identifiers (SFI). This method performs an application selection, retrieves processing options, and sends a GET DATA APDU command to fetch the specified tag data.
Example Usages
1. Detect and List Available Card Readers

var cardReaderService = new CardReaderService2();
var readers = cardReaderService.GetAvailableReaders();
foreach (var reader in readers)
{
    Console.WriteLine(reader);
}
`
2. Read Specific EMV Tags from Card

var cardReaderService = new CardReaderService2();
var tags = new HashSet<string> { "5A", "5F34", "82" };
var cardData = cardReaderService.ReadCard("HID Global OMNIKEY 3x21 Smart Card Reader 0", tags);

foreach (var tag in cardData.TagValues)
{
    Console.WriteLine($"{tag.Key}: {tag.Value}");
}

3. Read All Available EMV Data from Card

var cardReaderService = new CardReaderService2();
var cardData = cardReaderService.ReadAllCardData("HID Global OMNIKEY 3x21 Smart Card Reader 0");

foreach (var tag in cardData.TagValues)
{
    Console.WriteLine($"{tag.Key}: {tag.Value}");
}

4. Generate and Authenticate ARQC

string masterKeyHex = "6E46FE409DF704BCA75E7FF270B65E73"; // Example master key (TEST IMK AC - KCV 944A44)
var cardReaderService = new CardReaderService2();

var onlineTxnSim = new OnlineTxnSim(cardReaderService, masterKeyHex);
onlineTxnSim.SimulateTransaction("HID Global OMNIKEY 3x21 Smart Card Reader 0");

5. Parse Transaction Logs

public Dictionary<string, string> ParseTransactionLogs(string logs)
{
    var logData = new Dictionary<string, string>();
    var lines = logs.split('
');

    foreach (var line in lines)
    {
        var parts = line.split(':');
        if (parts.Length == 2)
        {
            logData[parts[0].Trim()] = parts[1].Trim();
        }
    }

    return logData;
}

var onlineTxnSim = new OnlineTxnSim(cardReaderService, masterKeyHex);
string logs = onlineTxnSim.SimulateTransaction("HID Global OMNIKEY 3x21 Smart Card Reader 0");
var parsedLogs = ParseTransactionLogs(logs);
foreach (var log in parsedLogs)
{
    Console.WriteLine($"{log.Key}: {log.Value}");
}

6. Display Card Data in a DataGrid (WPF Example)

using System.Collections.ObjectModel;

public class CardDataViewModel
{
    public ObservableCollection<CardDataItem> CardDataItems { get; set; }

    public CardDataViewModel()
    {
        CardDataItems = new ObservableCollection<CardDataItem>();
    }

    public void LoadCardData(CardData cardData)
    {
        foreach (var tag in cardData.TagValues)
        {
            CardDataItems.add(new CardDataItem { Tag = tag.Key, Value = tag.Value });
        }
    }
}

public class CardDataItem
{
    public string Tag { get; set; }
    public string Value { get; set; }
}

var cardReaderService = new CardReaderService2();
CardData cardData = cardReaderService.ReadAllCardData("HID Global OMNIKEY 3x21 Smart Card Reader 0");

var cardDataViewModel = new CardDataViewModel();
cardDataViewModel.LoadCardData(cardData);

// Bind cardDataViewModel.CardDataItems to a WPF DataGrid in XAML

7. Simulate Full Online Transactions with ARPC
// Example master key (TEST IMK AC - KCV 944A44) 
string masterKeyHex = "6E46FE409DF704BCA75E7FF270B65E73";
// Initialize OnlineTxnSim with the card reader service, master key, and ARPC enabled
OnlineTxnSim onlineTxnSim = new OnlineTxnSim(cardReaderService, masterKeyHex, true);
// Simulate the transaction
onlineTxnSim.SimulateTransaction("HID Global OMNIKEY 3x21 Smart Card Reader 0");
8. Using GetDataRead Method
CardData cardData = cardReaderService.GetDataRead("HID Global OMNIKEY 3x21 Smart Card Reader 0", "9F52");
foreach (var tag in cardData.TagValues)
{
    Console.WriteLine($"Tag: {tag.Key}, Value: {tag.Value}, Description: {cardData.GetTagDescription(tag.Key)}");
}





