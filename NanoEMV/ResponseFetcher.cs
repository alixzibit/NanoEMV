using NanoEMV;
using System.Collections.Generic;

namespace NanoEMV
{
    public class ResponseFetcher
    {
        private PCSCReader _cardReader;

        public ResponseFetcher(PCSCReader cardReader)
        {
            _cardReader = cardReader;
        }

        public APDUResponse FetchFullResponse(APDUCommand initialCommand)
        {
            APDUResponse response = _cardReader.Transmit(initialCommand);
            List<byte> fullData = new List<byte>();

            while (response.SW1 == 0x61)
            {
                if (response.Data != null)
                {
                    fullData.AddRange(response.Data);
                }

                APDUCommand followUpCommand = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, response.SW2);
                response = _cardReader.Transmit(followUpCommand);
            }

            if (response.Data != null)
            {
                fullData.AddRange(response.Data);
            }

            // Add the SW1 and SW2 to the end of the data before creating a new APDUResponse
            fullData.Add(response.SW1);
            fullData.Add(response.SW2);

            return new APDUResponse(fullData.ToArray());
        }
    }
}
