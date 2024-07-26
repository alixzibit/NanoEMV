using NanoEMV;

public class GetData
{
    private readonly PCSCReader _cardReader;
    private readonly Logger _logger;

    public GetData(PCSCReader cardReader, Logger logger)
    {
        _cardReader = cardReader;
        _logger = logger;
    }

    public APDUResponse ExecuteGetDataCommand(string emvTag)
    {
        byte p1, p2;

        // Determine if the tag is one or two bytes long
        if (emvTag.Length == 2)
        {
            p1 = Convert.ToByte(emvTag, 16);
            p2 = 0x00; // Default value for p2 if the tag is one byte
        }
        else if (emvTag.Length == 4)
        {
            p1 = Convert.ToByte(emvTag.Substring(0, 2), 16);
            p2 = Convert.ToByte(emvTag.Substring(2, 2), 16);
        }
        else
        {
            throw new ArgumentException("Invalid EMV tag length.");
        }

        APDUCommand apdu = new APDUCommand(0x80, 0xCA, p1, p2, null, 0x00);

        _logger.WriteLog($"Sending Get Data command: {BitConverter.ToString(apdu.CommandData)}");
        APDUResponse response = _cardReader.Transmit(apdu);
        _logger.WriteLog($"Initial Get Data response: SW1 = {response.SW1}, SW2 = {response.SW2}");

        if (response.SW1 == 0x6C)
        {
            // If SW1 is 6C, the correct length is in SW2
            apdu = new APDUCommand(0x80, 0xCA, p1, p2, null, response.SW2);
            _logger.WriteLog($"Reissuing Get Data command with Le = {response.SW2}: {BitConverter.ToString(apdu.CommandData)}");
            response = _cardReader.Transmit(apdu);
        }

        _logger.WriteLog($"Final Get Data response: SW1 = {response.SW1}, SW2 = {response.SW2}");

        return response;
    }
}
