using System;
using System.Text;

namespace NanoEMV
{
    public class AIDSelection
    {
        private PCSCReader _cardReader;

        private static readonly byte[][] knownAIDs =
        {
            // Visa
            new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 },
            // MasterCard
            new byte[] { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 },
             // Himyan
            new byte[] { 0xA0, 0x00, 0x00, 0x08, 0x84, 0x10, 0x10 }
        };

        public AIDSelection(PCSCReader cardReader)
        {
            _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
        }

        // This method attempts to select from the hardcoded list of AIDs.
        public (byte[] AID, APDUResponse Response) SelectKnownAID()
        {
            foreach (var aid in knownAIDs)
            {
                APDUResponse response = SelectAID(aid);
                if (IsSelectionSuccessful(response))
                {
                    return (aid, response);
                }
            }

            throw new InvalidOperationException("No known AID was selected successfully. Essential Card data missing - possibly empty card");
        }

        private APDUResponse SelectAID(byte[] aid)
        {
            // APDU for SELECT command (CLA=00, INS=A4, P1=04, P2=00, Lc=AID Length, Data=AID, Le=00)
            APDUCommand selectCommand = new APDUCommand(0x00, 0xA4, 0x04, 0x00, aid, 0x00);
            APDUResponse response = _cardReader.Transmit(selectCommand);

            // Check if the response indicates more data is available.
            if (response.SW1 == 0x61)
            {
                byte le = response.SW2;
                APDUCommand getResponseCommand = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, le);
                response = _cardReader.Transmit(getResponseCommand);
            }

            return response;
        }



        private bool IsSelectionSuccessful(APDUResponse response)
        {
            // SW1 of 0x90 and SW2 of 0x00 indicates success
            return response.SW1 == 0x90 && response.SW2 == 0x00;
        }
    }
}
