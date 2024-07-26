using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NanoEMV.Services
{
    public class OfflinePINTxn
    {
        private readonly ICardReaderService2 _cardReaderService;
        private CardData _cardData;
        private List<string> _transactionLogs;
        private Logger _logger = new Logger();
    }
}
