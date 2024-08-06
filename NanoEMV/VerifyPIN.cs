namespace NanoEMV.Services
{
    public class VerifyPIN
    {
        private readonly ICardReaderService2 _cardReaderService;
        private readonly byte[] _offlinePin;

        public VerifyPIN(ICardReaderService2 cardReaderService, byte[] offlinePin)
        {
            _cardReaderService = cardReaderService ?? throw new ArgumentNullException(nameof(cardReaderService));
            _offlinePin = offlinePin ?? throw new ArgumentNullException(nameof(offlinePin));
        }

        public bool Verify()
        {
            // Ensure the PIN is formatted correctly with padding and control field
            byte[] commandData = new byte[8];
            commandData[0] = 0x24; // Control field indicating plaintext PIN
            Array.Copy(_offlinePin, 0, commandData, 1, _offlinePin.Length);

            // Pad with 0xFF to make the total length 8 bytes
            for (int i = _offlinePin.Length + 1; i < commandData.Length; i++)
            {
                commandData[i] = 0xFF;
            }

            // Create the APDU command for PIN verification without the Le byte
            APDUCommand2 apduCommandWithoutLe = new APDUCommand2(0x00, 0x20, 0x00, 0x80, commandData);

            // Transmit the APDU command to the card reader
            APDUResponse response = _cardReaderService.GetCardReader().Transmit(apduCommandWithoutLe);

            // Check if the response indicates success (SW1 == 0x90 and SW2 == 0x00)
            return response.SW1 == 0x90 && response.SW2 == 0x00;
        }
    }
}
