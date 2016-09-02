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
using System.Threading;
using System.Threading.Tasks;

namespace CrypTest_Client1
{
    /// <summary>
    /// TODO
    /// - DONE: private key symetric messgae encryption, using dymacially generated keys
    /// - DONE: public key asymetric key exchange, used to pass the priv-sym-key
    ///     NOTE only done for client1 to cliet2 as server
    /// - DONE: Digital signature to ensure authentication
    /// - DONE: MAC hash of message content to ensure it hasn't changed
    /// - Refactor to common library
    /// - Fill out both sides
    /// - Use a test certificate as the source of the asymetric keys?
    ///     Would probably have to install it locally with pub and priv keys, but be sure to load in client with just public key if possible
    /// </summary>
    public class SecClient1 : IDisposable
    {
        private SecureServer _secureServer;
        private Logger _logger;
        private int _serverPort = 31088;
        private int _clientPort = 31089;

        public SecClient1(Logger logger)
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
            _secureServer = new SecureServer("Secure Client 1 - Server", _logger, _serverPort);
            _secureServer.Start();
        }

        public string SendSecureRequest(string message)
        {
            SecureClient secureClient = new SecureClient("Secure Client 1 - Client", _logger, _clientPort);
            return secureClient.SendSecureRequest(message);
        }
    }
}
