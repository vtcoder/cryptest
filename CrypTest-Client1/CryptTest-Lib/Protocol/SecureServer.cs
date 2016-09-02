using CryptTest_Lib.Cryptography;
using CryptTest_Lib.Logging;
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

namespace CryptTest_Lib.Protocol
{
    public class SecureServer : IDisposable
    {
        private string _name;
        private int _port;
        private HttpListener _httpListenerSecure;
        private ILogger _logger;
        private Dictionary<string, Tuple<string, string, string>> _sessionKeys = new Dictionary<string, Tuple<string, string, string>>();

        public SecureServer(string name, ILogger logger, int port)
            : base()
        {
            _name = name;
            _port = port;
            _logger = logger;
        }

        public void Start()
        {
            _httpListenerSecure = new HttpListener();
            _httpListenerSecure.Prefixes.Add(@"http://+:" + _port + @"/sectest/secure/");
            ListenForRequestsSecure();
            _logger.Write("SecureServer [" + _name + "] is now listening (secure) on " + _httpListenerSecure.Prefixes.FirstOrDefault());
        }

        public void Dispose()
        {
            _logger.Write("SecureServer [" + _name + "] is stopping the HTTP listener...", isNewSection: true);
            _httpListenerSecure.Stop();
            _httpListenerSecure.Close();
        }

        private async void ListenForRequestsSecure()
        {
            _httpListenerSecure.Start();

            try
            {
                while (true)
                {
                    var context = await _httpListenerSecure.GetContextAsync();
                    _logger.Write("Receiving a request (secure).", isNewSection: true);

                    //Log the request details.
                    _logger.Write("Request headers:", isNewSection: true);
                    var request = context.Request;
                    foreach (var hKey in request.Headers.AllKeys)
                    {
                        _logger.Write($"  {hKey} = {request.Headers[hKey]}");
                    }
                    _logger.Write("\nRaw request body:", isNewSection: true);
                    string rawRequestBody = null;
                    using (StreamReader sr = new StreamReader(request.InputStream))
                    {
                        rawRequestBody = sr.ReadToEnd();
                    }
                    _logger.Write(rawRequestBody);

                    //Process the request.
                    ProcessSecureRequest(rawRequestBody, request.Headers, context);
                }
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private void ProcessSecureRequest(string message, NameValueCollection headers, HttpListenerContext context)
        {
            string action = "undefined";
            string sessID = "undefined";
            foreach (var hKey in headers.AllKeys)
            {
                if (hKey == "sectest-action")
                {
                    action = headers[hKey].ToLower();
                    _logger.Write("Action header found: " + action);
                }
                else if (hKey == "sectest-sessid")
                {
                    sessID = headers[hKey].ToLower();
                    _logger.Write("Session ID header found: " + sessID);
                }
            }

            switch (action)
            {
                case "handshake-init":
                    ProcessHandshakeInit(message, headers, context, sessID);
                    break;
                case "handshake-key-exchange":
                    var handshakeResponse = ProcessHandshakeKeyExchange(message, headers, context, sessID);
                    SendResponseSecure(handshakeResponse, context);
                    break;
                case "message-transfer":
                    var responseMessage = ProcessMessageSecure(message, headers, context, sessID);
                    SendResponseSecure(responseMessage, context);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        private void ProcessHandshakeInit(string message, NameValueCollection headers, HttpListenerContext context, string sessID)
        {
            AsymetricCrypto asymCrypto = new AsymetricCrypto();

            //Initialize our asymetric cryptography provider.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(2048);
            string rsaProviderPublicXML = rsaProvider.ToXmlString(false); //Exclude private key because we will send this to the client.

            //Add the session ID to the session dictionary, and include the RSA public and private key info.
            string rsaProviderPrivateXML = rsaProvider.ToXmlString(true);
            _sessionKeys.Add(sessID, new Tuple<string, string, string>(rsaProviderPrivateXML, null, null));

            //Create the authentication signature.
            string signature = asymCrypto.CreateSignature(rsaProvider, rsaProviderPublicXML);
            _logger.Write("Signature:", isNewSection: true);
            _logger.Write(signature);

            //Create a response header for the authentication signature.
            var responseHeaders = new NameValueCollection();
            responseHeaders.Add("sectest-auth-sig", signature);

            SendResponseSecure(rsaProviderPublicXML, context, "ok", responseHeaders);
        }

        private string ProcessHandshakeKeyExchange(string message, NameValueCollection headers, HttpListenerContext context, string sessID)
        {
            AsymetricCrypto asymCrypto = new AsymetricCrypto();

            //Get the encrypted key and IV.
            string encryptedKey = Regex.Match(message, "<sesskey>(?<RegKey>[^<]*)</sesskey").Groups["RegKey"].Value;
            string encryptedIv = Regex.Match(message, "<iv>(?<RegIv>[^<]*)</iv").Groups["RegIv"].Value;

            //Build RSA provider from XML string containing both public and private keys.
            string rsaProviderXml = _sessionKeys[sessID].Item1;

            //Decrypt the key and IV.
            string key = asymCrypto.Decrypt(encryptedKey, rsaProviderXml);
            string iv = asymCrypto.Decrypt(encryptedIv, rsaProviderXml);

            //Get the session data from the session dictionary and update it to include the symetric private key and IV.
            _sessionKeys[sessID] = new Tuple<string, string, string>(_sessionKeys[sessID].Item1, key, iv);

            string handshakeKeyExchangeResponse = $"<sectest><symcrypt>Private keys received - using symetrics encryption from this point forward.</symcrypt></sectest>";
            return handshakeKeyExchangeResponse;
        }

        private string ProcessMessageSecure(string encryptedMessage, NameValueCollection headers, HttpListenerContext context, string sessID)
        {
            SymetricCrypto symCrypto = new SymetricCrypto();
            HashCrypto hashCrypto = new HashCrypto();

            if (_sessionKeys.ContainsKey(sessID))
            {
                var keyInfo = _sessionKeys[sessID];
                string key = keyInfo.Item2;
                string iv = keyInfo.Item3;

                //Decrypt the symetrically encrypted body message.
                string message = symCrypto.Decrypt(encryptedMessage, key, iv);

                _logger.Write("Encrypted message:", isNewSection: true);
                _logger.Write(encryptedMessage);
                _logger.Write("Decrypted message:", isNewSection: true);
                _logger.Write(message);

                //Check the HMAC.
                string hmacHash = headers["sectest-hmac"];
                bool isHmacValid = hashCrypto.VerifyHmac(encryptedMessage, hmacHash, key); //NOTE we use the secret symetric key for the HMAC hash key.
                if (isHmacValid)
                {
                    _logger.Write("HMAC hash matched", isNewSection: true);
                }
                else
                {
                    _logger.Write("HMAC hash did not match", isNewSection: true);
                    return "";
                }

                return "Secure message received!";
            }
            else
            {
                _logger.Write("Message transfer request did not contain a session ID.");
                return "No session ID found";
            }
        }

        private void SendResponseSecure(string responseMessage, HttpListenerContext context, string status = null, NameValueCollection headers = null)
        {
            _logger.Write("Creating response...", isNewSection: true);
            var response = context.Response;
            if (!string.IsNullOrWhiteSpace(status))
            {
                response.AddHeader("sectest-status", status);
            }
            if (headers != null)
            {
                foreach (var headerKey in headers.Keys)
                    response.AddHeader(headerKey.ToString(), headers[headerKey.ToString()]);
            }
            response.StatusCode = 200;
            _logger.Write("Response body: ");
            _logger.Write(responseMessage);
            using (StreamWriter sw = new StreamWriter(response.OutputStream))
            {
                sw.Write(responseMessage);
            }
            response.Close();
            _logger.Write("Response sent");
        }
    }
}
