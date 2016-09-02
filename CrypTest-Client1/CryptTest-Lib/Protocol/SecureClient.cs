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

            //Create a hash of the message (to use for authentication signature verifiation).
            byte[] hashBytes = null;
            SHA256 sha256 = SHA256.Create();
            using (MemoryStream ms = new MemoryStream())
            using (StreamWriter sw = new StreamWriter(ms, Encoding.UTF8))
            {
                sw.Write(handshakeInitResponse.Item1);
                sw.Close();

                hashBytes = sha256.ComputeHash(ms.ToArray());
            }

            //Check the authentication signature to make sure it is valid.
            //This tells us
            // a) The sender has the private key associated with this public key, so they are who they say they are (assuming we know we can trust the public key, like with a certificate, but ignoring that part for now)
            // b) The message content was not tampered with. This because the hash of the message has to match.
            string signature = handshakeInitResponse.Item2["sectest-auth-sig"];
            _logger.Write("Signature:", isNewSection: true);
            _logger.Write(signature);
            byte[] signatureBytes = Convert.FromBase64String(signature);
            bool isSignatureValid = rsaProvider.VerifyHash(hashBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            _logger.Write("Authentication signature valid: " + isSignatureValid);
            if (!isSignatureValid)
                return "";

            //Initialize our symetric cryptography provider.
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            //Encrypt the symetric private key and IV with the asymetric public key.
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
            var encryptedData = SymetricEncryptMessage(message, aesProvider.Key, aesProvider.IV);
            string encryptedMessage = encryptedData.Item1;
            byte[] encryptedBytes = encryptedData.Item2;

            //Create a hash of the encrypted message (HMAC) to ensure message integrity.
            var hmacMD5 = HMACMD5.Create();
            hmacMD5.Key = aesProvider.Key; //NOTE we use the secret symetric key for the HMAC hash key.
            var hmacHashBytes = hmacMD5.ComputeHash(encryptedBytes);
            string hmacHash = Convert.ToBase64String(hmacHashBytes);

            //Create request header for the HMAC.
            var requestHeaders = new NameValueCollection();
            requestHeaders.Add("sectest-hmac", hmacHash);

            //Send a symetricly encrypted message. Include the HMAC as a header.            
            var messageResponse = SendHttpMessageSecure(encryptedMessage, "message-transfer", sessID, requestHeaders);

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

        private Tuple<string, NameValueCollection> SendHttpMessageSecure(string message, string secTestAction, string sessID = null, NameValueCollection headers = null)
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
