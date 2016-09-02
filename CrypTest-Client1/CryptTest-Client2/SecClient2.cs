using CryptTest_Lib.Cryptography;
using CryptTest_Lib.Protocol;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CryptTest_Client2
{
    public class SecClient2 : IDisposable
    {
        private SecureServer _secureServer;
        private Logger _logger;
        private int _serverPort = 31089;
        private int _clientPort = 31088;

        public SecClient2(Logger logger)
            : base()
        {
            _logger = logger;
        }

        public void Dispose()
        {
            _secureServer.Dispose();
        }

        public void Start()
        {
            _secureServer = new SecureServer("Secure Client 2 - Server", _logger, _serverPort);
            _secureServer.Start();
        }

        public string SendSecureRequest(string message)
        {
            SecureClient secureClient = new SecureClient("Secure Client 2 - Client", _logger, _clientPort);
            return secureClient.SendSecureRequest(message);
        }
    }
}
