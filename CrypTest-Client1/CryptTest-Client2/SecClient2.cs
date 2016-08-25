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
        private const string STATIC_SHARED_AES_SYMETRIC_KEY = "uup59EXQZxa49+9W/NLjnZCk+gChopNTyYx04Y95l4U=";
        private const string STATIC_AES_IV = "ufbNZiWGEeyAlkWddhORcQ==";

        private HttpListener _httpListener;
        private HttpListener _httpListenerSecure;
        private Logger _logger;

        public SecClient2(Logger logger)
            : base()
        {
            _logger = logger;
        }

        #region Server 

        public void Dispose()
        {
            _logger.Write("SecClient2 is stopping the HTTP listener...", isNewSection: true);
            _httpListener.Stop();
            _httpListener.Close();

            _logger.Write("SecClient2 is stopping the HTTP listener (secure)...", isNewSection: true);
            _httpListenerSecure.Stop();
            _httpListenerSecure.Close();
        }

        public void Start()
        {
            _logger.Write("SecClient2 is preparing to listen...");
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add(@"http://+:13890/sectest/");
            ListenForRequests();
            _logger.Write("SecClient2 is now listening on " + _httpListener.Prefixes.FirstOrDefault());

            _logger.Write("SecClient2 is preparing to listen (secure)...");
            _httpListenerSecure = new HttpListener();
            _httpListenerSecure.Prefixes.Add(@"http://+:13490/sectest/secure/");
            ListenForRequestsSecure();
            _logger.Write("SecClient2 is now listening (secure) on " + _httpListenerSecure.Prefixes.FirstOrDefault());
        }

        private async void ListenForRequests()
        {
            _httpListener.Start();

            try
            {
                while (true)
                {
                    var context = await _httpListener.GetContextAsync();
                    _logger.Write("Receiving a request.", isNewSection: true);

                    _logger.Write("Request headers:", isNewSection: true);
                    var request = context.Request;
                    foreach (var hKey in request.Headers.AllKeys)
                    {
                        _logger.Write($"  {hKey} = {request.Headers[hKey]}");
                    }

                    _logger.Write("\nEncrypted request body:", isNewSection: true);
                    string encryptedRequestBody = null;
                    using (StreamReader sr = new StreamReader(request.InputStream))
                    {
                        encryptedRequestBody = sr.ReadToEnd();
                    }
                    _logger.Write(encryptedRequestBody);

                    _logger.Write("\nDecrypted request body:", isNewSection: true);
                    string requestBody = DecryptRequestBody(encryptedRequestBody);
                    _logger.Write(requestBody);

                    _logger.Write("Creating response...", isNewSection: true);
                    var response = context.Response;
                    response.StatusCode = 200;
                    string responseBody = "<sectestresp>testing response<sectestresp>";
                    _logger.Write("Response body: ");
                    _logger.Write(responseBody);
                    using (StreamWriter sw = new StreamWriter(response.OutputStream))
                    {
                        sw.Write(responseBody);
                    }
                    response.Close();
                    _logger.Write("Response sent");
                }
            }
            catch (ObjectDisposedException)
            {
            }
        }

        public string DecryptRequestBody(string encryptedRequestBody)
        {
            string plainTextBody = null;

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            aesProvider.Key = Convert.FromBase64String(STATIC_SHARED_AES_SYMETRIC_KEY);
            aesProvider.IV = Convert.FromBase64String(STATIC_AES_IV);

            var encryptedBytes = Convert.FromBase64String(encryptedRequestBody);

            using (MemoryStream ms = new MemoryStream(encryptedBytes))
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                plainTextBody = sr.ReadToEnd();
            }

            return plainTextBody;
        }

        #endregion

        #region Client

        public string SendRequest()
        {
            HttpWebRequest req = WebRequest.Create("http://localhost:13889/sectest/") as HttpWebRequest;
            req.Headers.Add("sectest-req-client", "2"); //Set header to indicate request came from security client #2.
            req.MediaType = "text/xml";
            req.Method = "POST";
            req.UserAgent = "sectest-client";
            var reqStream = req.GetRequestStream();
            using (StreamWriter sw = new StreamWriter(reqStream))
            {
                string body = CreateRequestBody();
                sw.Write(body);
            }
            var resp = req.GetResponse();
            var respStream = resp.GetResponseStream();
            using (StreamReader sr = new StreamReader(respStream))
            {
                return sr.ReadToEnd();
            }
        }

        public string CreateRequestBody()
        {
            string encryptedBody = null;
            string plainTextBody = "<sectest>Test message from CLIENT 2222</sectest>";

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            aesProvider.Key = Convert.FromBase64String(STATIC_SHARED_AES_SYMETRIC_KEY);
            aesProvider.IV = Convert.FromBase64String(STATIC_AES_IV);

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateEncryptor(), CryptoStreamMode.Write))
            using (StreamWriter sr = new StreamWriter(cs))
            {
                sr.Write(plainTextBody);
                sr.Close();

                encryptedBody = Convert.ToBase64String(ms.ToArray());
            }

            return encryptedBody;
        }

        #endregion

        #region Secure Server

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

        private Dictionary<string, Tuple<string, string, string>> _sessionKeys = new Dictionary<string, Tuple<string, string, string>>();

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
                else if(hKey == "sectest-sessid")
                {
                    sessID = headers[hKey].ToLower();
                    _logger.Write("Session ID header found: " + sessID);
                }
            }            

            switch(action)
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
            //Initialize our asymetric cryptography provider.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(2048);
            string rsaProviderXML = rsaProvider.ToXmlString(false); //Exclude private key because we will send this to the client.

            //Add the session ID to the session dictionary, and include the RSA public and private key info.
            _sessionKeys.Add(sessID, new Tuple<string, string, string>(rsaProvider.ToXmlString(true), null, null));

            SendResponseSecure(rsaProviderXML, context, "ok");
        }

        private string ProcessHandshakeKeyExchange(string message, NameValueCollection headers, HttpListenerContext context, string sessID)
        {
            //Get the encrypted key and IV.
            string encryptedKey = Regex.Match(message, "<sesskey>(?<RegKey>[^<]*)</sesskey").Groups["RegKey"].Value;
            string encryptedIv = Regex.Match(message, "<iv>(?<RegIv>[^<]*)</iv").Groups["RegIv"].Value;

            //Decode the encrypted key and IV from base 64 to bytes.
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKey);
            byte[] encryptedIvBytes = Convert.FromBase64String(encryptedIv);

            //Initialize our asymetric cryptography provider.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(2048);
            rsaProvider.FromXmlString(_sessionKeys[sessID].Item1); //Build RSA provider from XML string containing both public and private keys.

            //Decrypt the key and IV.
            byte[] decryptedKeyBytes = rsaProvider.Decrypt(encryptedKeyBytes, true);
            byte[] decryptedIvBytes = rsaProvider.Decrypt(encryptedIvBytes, true);

            //Encode the decrypted key and IV as base 64 string for storage in session (we don't have to do this, we could just store the byte arrays, but strings make it easier for debugging for this example app).
            string key = Convert.ToBase64String(decryptedKeyBytes);
            string iv = Convert.ToBase64String(decryptedIvBytes);

            //Get the session data from the session dictionary and update it to include the symetric private key and IV.
            _sessionKeys[sessID] = new Tuple<string, string, string>(_sessionKeys[sessID].Item1, key, iv);

            string handshakeKeyExchangeResponse = $"<sectest><symcrypt>Private keys received - using symetrics encryption from this point forward.</symcrypt></sectest>";
            return handshakeKeyExchangeResponse;
        }

        private string ProcessMessageSecure(string encryptedMessage, NameValueCollection headers, HttpListenerContext context, string sessID)
        {
            if (_sessionKeys.ContainsKey(sessID))
            {
                var keyInfo = _sessionKeys[sessID];
                string key = keyInfo.Item2;
                string iv = keyInfo.Item3;

                string message = DecryptRequestBodySecure(encryptedMessage, key, iv);

                _logger.Write("Encrypted message:", isNewSection: true);
                _logger.Write(encryptedMessage);
                _logger.Write("Decrypted message:", isNewSection: true);
                _logger.Write(message);

                return "Secure message received!";
            }
            else
            {
                _logger.Write("Message transfer request did not contain a session ID.");
                return "No session ID found";
            }
        }

        public string DecryptRequestBodySecure(string encryptedRequestBody, string key, string iv)
        {
            string plainTextBody = null;

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            aesProvider.Key = Convert.FromBase64String(key);
            aesProvider.IV = Convert.FromBase64String(iv);

            var encryptedBytes = Convert.FromBase64String(encryptedRequestBody);

            using (MemoryStream ms = new MemoryStream(encryptedBytes))
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                plainTextBody = sr.ReadToEnd();
            }

            return plainTextBody;
        }

        private void SendResponseSecure(string responseMessage, HttpListenerContext context, string status = null)
        {
            _logger.Write("Creating response...", isNewSection: true);
            var response = context.Response;
            if (!string.IsNullOrWhiteSpace(status))
            {
                response.AddHeader("sectest-status", status);
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

        #endregion
    }
}
