using NanoEMV;
using System;

public class ApplicationSelection
{
    private PCSCReader _cardReader;

    public ApplicationSelection(PCSCReader cardReader)
    {
        _cardReader = cardReader ?? throw new ArgumentNullException(nameof(cardReader));
    }

    public APDUResponse SelectApplication(byte[] aid)
    {
        if (aid == null || aid.Length == 0)
        {
            throw new ArgumentException("AID is invalid.");
        }

        APDUCommand apdu = new APDUCommand(0x00, 0xA4, 0x04, 0x00, aid, (byte)aid.Length);
        APDUResponse response = _cardReader.Transmit(apdu);
        return HandleResponse(response);
    }

    public APDUResponse GetResponse(int byteCount)
    {
        APDUCommand apdu = new APDUCommand(0x00, 0xC0, 0x00, 0x00, null, (byte)byteCount);
        APDUResponse response = _cardReader.Transmit(apdu);
        return HandleResponse(response);
    }

    public APDUResponse ReadRecord(byte recordNumber, byte expectedLength = 0x00)
    {
        APDUCommand apdu = new APDUCommand(0x00, 0xB2, recordNumber, 0x0C, null, expectedLength);
        APDUResponse response = _cardReader.Transmit(apdu);
        return HandleResponse(response);
    }
    private int lastRecordNumber = 1; // or initialize with whatever starting record number you wish

    private APDUResponse HandleResponse(APDUResponse response)
    {
        while (response.SW1 == 0x61 || response.SW1 == 0x6C || ((response.SW1 << 8) | response.SW2) == 0x6A83)
        {
            if (response.SW1 == 0x61)
            {
                // Get additional data
                response = GetResponse(response.SW2);
            }
            else if (response.SW1 == 0x6C)
            {
                // Reissue the last command with the correct length
                response = ReadRecord((byte)lastRecordNumber, response.SW2);

            }
            else if (((response.SW1 << 8) | response.SW2) == 0x6A83)
            {
                // Record not found; exit the loop
                break;
            }
            else
            {
                // Increment the record number for the next iteration
                // Assuming lastRecordNumber is a class-level variable
                lastRecordNumber++;
                response = ReadRecord((byte)lastRecordNumber, response.SW2);
                // Assume initial Le=0, adjust if needed
            }
        }
        return response;
    }


    public bool IsSelectionSuccessful(APDUResponse response)
    {
        return response.SW1 == 0x90 && response.SW2 == 0x00;
    }
}
