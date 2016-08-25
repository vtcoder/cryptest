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
    /// - IN PROG: public key asymetric key exchange, used to pass the priv-sym-key
    /// - MAC hash of message content to ensure it hasn't changed
    /// - Digital signature to ensure authentication
    /// </summary>
    public class SecClient1 : IDisposable
    {
        private const string STATIC_SHARED_AES_SYMETRIC_KEY = "uup59EXQZxa49+9W/NLjnZCk+gChopNTyYx04Y95l4U=";
        private const string STATIC_AES_IV = "ufbNZiWGEeyAlkWddhORcQ==";

        private HttpListener _httpListener;
        private Logger _logger;

        public SecClient1(Logger logger)
            : base()
        {
            _logger = logger;
        }

        #region Server 

        public void Dispose()
        {
            _logger.Write("SecClient1 is stopping the HTTP listener...", isNewSection: true);
            _httpListener.Stop();
            _httpListener.Close();
        }

        public void Start()
        {
            _logger.Write("SecClient1 is preparing to listen...");
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add(@"http://+:13889/sectest/");
            ListenForRequests();
            _logger.Write("SecClient1 is now listening on " + _httpListener.Prefixes.FirstOrDefault());
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
            HttpWebRequest req = WebRequest.Create("http://localhost:13890/sectest/") as HttpWebRequest;
            req.Headers.Add("sectest-req-client", "1"); //Set header to indicate request came from security client #2.
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
            string plainTextBody = "<sectest>Test message from CLIENT 1111</sectest>";

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

        #region Secure Client

        public string SendSecureRequest(string message)
        {
            //Generate a new session ID for this set of secure messages.
            string sessID = Guid.NewGuid().ToString();

            //Send unsecure init message with new session-id.
            _logger.Write("Sending handshake-init message.", isNewSection: true);
            var handshakeInitResponse = SendHttpMessageSecure("<sectest>init</sectest>", "handshake-init", sessID);

            //Check status of init message.
            string status = handshakeInitResponse.Item2["sectest-status"];
            _logger.Write("Handshake-init status: " + status);
            if (status.ToLower() != "ok")
            {
                _logger.Write("Handshake-init failed.");
                return "";
            }

            //Initialize our asymetric cryptography provider. This will just have the public key.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(handshakeInitResponse.Item1);
            
            //Initialize our symetric cryptography provider.
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            //Encrypte the symetric private key and IV with the asymetric public key.
            var encryptedKeyBytes = rsaProvider.Encrypt(aesProvider.Key, true);
            var encryptedIvBytes = rsaProvider.Encrypt(aesProvider.IV, true);

            //Encode encrypted key and IV as base64 string to send on wire.
            string encryptedKey = Convert.ToBase64String(encryptedKeyBytes);
            string encryptedIv = Convert.ToBase64String(encryptedIvBytes);

            //Send semi-secure handshake key exchange message to establish the private symetric key.
            _logger.Write("Sending handshake-key-exchange message.", isNewSection: true);
            var handshakeKeyExchangeResponse = SendSecureRequest_Handshake(encryptedKey, encryptedIv, sessID);

            //Check status of key-exchange messge.
            status = handshakeInitResponse.Item2["sectest-status"];
            _logger.Write("Handshake-key-exchange status: " + status);
            if (status.ToLower() != "ok")
            {
                _logger.Write("Handshake-key-exchange failed.");
                return "";
            }

            _logger.Write("Sending symetric encrypted data message.", isNewSection: true);

            //Encrypt the message.
            string encryptedMessage = SymetricEncryptMessage(message, aesProvider.Key, aesProvider.IV);

            //Send a symetricly encrypted message.
            var messageResponse = SendHttpMessageSecure(encryptedMessage, "message-transfer", sessID);

            //Check status of data messge.
            status = handshakeInitResponse.Item2["sectest-status"];
            _logger.Write("Data-message status: " + status);
            if (status.ToLower() != "ok")
            {
                _logger.Write("Data-message failed.");
                return "";
            }

            return messageResponse.Item1;
        }

        private Tuple<string, NameValueCollection> SendSecureRequest_Handshake(string encryptedSessKey, string encryptedIv, string sessID)
        {
            string handshakeKeyExchangeMessage = $"<sectest><symcrypt><sesskey>{encryptedSessKey}</sesskey><iv>{encryptedIv}</iv></symcrypt></sectest>";
            return SendHttpMessageSecure(handshakeKeyExchangeMessage, "handshake-key-exchange", sessID);
        }

        private string SymetricEncryptMessage(string message, byte[] sessKey, byte[] iv)
        {
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Key = sessKey;
            aesProvider.IV = iv;

            string encryptedMessage = null;
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateEncryptor(), CryptoStreamMode.Write))
            using (StreamWriter sr = new StreamWriter(cs))
            {
                sr.Write(message);
                sr.Close();

                encryptedMessage = Convert.ToBase64String(ms.ToArray());
            }

            return encryptedMessage;
        }

        private Tuple<string, NameValueCollection> SendHttpMessageSecure(string message, string secTestAction, string sessID = null)
        {
            HttpWebRequest req = WebRequest.Create("http://localhost:13490/sectest/secure/") as HttpWebRequest;
            req.Headers.Add("sectest-req-client", "1"); //Set header to indicate request came from security client #2.
            req.Headers.Add("sectest-action", secTestAction);
            if (!string.IsNullOrWhiteSpace(sessID))
            {
                req.Headers.Add("sectest-sessid", sessID);
            }
            req.MediaType = "text/xml";
            req.Method = "POST";
            req.UserAgent = "sectest-client";
            var reqStream = req.GetRequestStream();
            using (StreamWriter sw = new StreamWriter(reqStream))
            {
                sw.Write(message);
            }
            var resp = req.GetResponse();
            var respStream = resp.GetResponseStream();
            using (StreamReader sr = new StreamReader(respStream))
            {
                return new Tuple<string, NameValueCollection>(sr.ReadToEnd(), resp.Headers);
            }
        }

        #endregion
    }
}
