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
using System.Threading.Tasks;

namespace CryptTest_Lib.Protocol
{
    public class SecureClient
    {
        private string _name;
        private int _port;
        private ILogger _logger;

        public SecureClient(string name, ILogger logger, int port)
            : base()
        {
            _name = name;
            _port = port;
            _logger = logger;
        }

        public string SendRequest(string message)
        {
            AsymetricCrypto asymCrypto = new AsymetricCrypto();
            SymetricCrypto symCrypto = new SymetricCrypto();
            HashCrypto hashCrypto = new HashCrypto();

            //Generate a new session ID for this set of secure messages.
            string sessID = Guid.NewGuid().ToString();

            //Send unsecure init message with new session-id.
            _logger.Write("Sending handshake-init message.", isNewSection: true);
            var handshakeInitResponse = SendHttpMessage("<sectest>init</sectest>", "handshake-init", sessID);

            //Check status of init message.
            string status = handshakeInitResponse.Item2["sectest-status"];
            _logger.Write("Handshake-init status: " + status);
            if (status.ToLower() != "ok")
            {
                _logger.Write("Handshake-init failed.");
                return "";
            }

            //Check the authentication signature to make sure it is valid.
            //This tells us
            // a) The sender has the private key associated with this public key, so they are who they say they are (assuming we know we can trust the public key, like with a certificate, but ignoring that part for now)
            // b) The message content was not tampered with. This because the hash of the message has to match.
            string signature = handshakeInitResponse.Item2["sectest-auth-sig"];
            _logger.Write("Signature:", isNewSection: true);
            _logger.Write(signature);
            bool isSignatureValid = asymCrypto.VerifySignature(handshakeInitResponse.Item1, signature);
            _logger.Write("Authentication signature valid: " + isSignatureValid);
            if (!isSignatureValid)
                return "";

            //Generate symetric key and IV.
            var keyAndIv = symCrypto.GenerateKeyAndIv();

            //Encrypt the symetric private key and IV with the asymetric public key.
            string encryptedKey = asymCrypto.Encrypt(keyAndIv.Item1, handshakeInitResponse.Item1);
            string encryptedIv = asymCrypto.Encrypt(keyAndIv.Item2, handshakeInitResponse.Item1);

            //Send semi-secure handshake key exchange message to establish the private symetric key.
            _logger.Write("Sending handshake-key-exchange message.", isNewSection: true);
            var handshakeKeyExchangeResponse = SendRequest_Handshake(encryptedKey, encryptedIv, sessID);

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
            var encryptedData = SymetricEncryptMessage(message, sessKey: keyAndIv.Item1, iv: keyAndIv.Item2);
            string encryptedMessage = encryptedData.Item1;

            //Create a hash of the encrypted message (HMAC) to ensure message integrity.
            string hmacHash = hashCrypto.GenerateHmac(encryptedData.Item2, keyAndIv.Item1); //NOTE we use the secret symetric key for the HMAC hash key.

            //Create request header for the HMAC.
            var requestHeaders = new NameValueCollection();
            requestHeaders.Add("sectest-hmac", hmacHash);

            //Send a symetricly encrypted message. Include the HMAC as a header.            
            var messageResponse = SendHttpMessage(encryptedMessage, "message-transfer", sessID, requestHeaders);

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

        private Tuple<string, NameValueCollection> SendRequest_Handshake(string encryptedSessKey, string encryptedIv, string sessID)
        {
            string handshakeKeyExchangeMessage = $"<sectest><symcrypt><sesskey>{encryptedSessKey}</sesskey><iv>{encryptedIv}</iv></symcrypt></sectest>";
            return SendHttpMessage(handshakeKeyExchangeMessage, "handshake-key-exchange", sessID);
        }

        private Tuple<string, byte[]> SymetricEncryptMessage(string message, byte[] sessKey, byte[] iv)
        {
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Key = sessKey;
            aesProvider.IV = iv;

            string encryptedMessage = null;
            byte[] encryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateEncryptor(), CryptoStreamMode.Write))
            using (StreamWriter sr = new StreamWriter(cs))
            {
                sr.Write(message);
                sr.Close();

                encryptedBytes = ms.ToArray();
                encryptedMessage = Convert.ToBase64String(encryptedBytes);
            }

            return new Tuple<string, byte[]>(encryptedMessage, encryptedBytes);
        }

        private Tuple<string, NameValueCollection> SendHttpMessage(string message, string secTestAction, string sessID = null, NameValueCollection headers = null)
        {
            HttpWebRequest req = WebRequest.Create("http://localhost:" + _port + "/sectest/secure/") as HttpWebRequest;
            req.Headers.Add("sectest-req-client", "1"); //Set header to indicate request came from security client #2.
            req.Headers.Add("sectest-action", secTestAction);
            if (!string.IsNullOrWhiteSpace(sessID))
            {
                req.Headers.Add("sectest-sessid", sessID);
            }
            if (headers != null)
            {
                foreach (var headerKey in headers.Keys)
                    req.Headers.Add(headerKey.ToString(), headers[headerKey.ToString()]);
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
    }
}
