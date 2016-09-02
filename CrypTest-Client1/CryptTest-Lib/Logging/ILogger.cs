using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Lib.Logging
{
    public interface ILogger
    {
        void Write(string message, bool addStartingNewLine = true, bool isNewSection = false);
    }
}
