using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Client2
{
    public class SecClient2 : IDisposable
    {
        private const string SHARED_AES_SYMETRIC_KEY = "uup59EXQZxa49+9W/NLjnZCk+gChopNTyYx04Y95l4U=";
        private const string AES_IV = "ufbNZiWGEeyAlkWddhORcQ==";

        private HttpListener _httpListener;
        private Logger _logger;

        public SecClient2(Logger logger)
            : base()
        {
            _logger = logger;
        }

        public void Dispose()
        {
            _logger.Write("SecClient2 is stopping the HTTP listener...", isNewSection: true);
            _httpListener.Stop();
            _httpListener.Close();
        }

        public void Start()
        {
            _logger.Write("SecClient2 is preparing to listen...");
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add(@"http://+:13890/sectest/");
            ListenForRequests();
            _logger.Write("SecClient2 is now listening on " + _httpListener.Prefixes.FirstOrDefault());
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

            aesProvider.Key = Convert.FromBase64String(SHARED_AES_SYMETRIC_KEY);
            aesProvider.IV = Convert.FromBase64String(AES_IV);

            var encryptedBytes = Convert.FromBase64String(encryptedRequestBody);

            using (MemoryStream ms = new MemoryStream(encryptedBytes))
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                plainTextBody = sr.ReadToEnd();
            }

            return plainTextBody;
        }

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

            aesProvider.Key = Convert.FromBase64String(SHARED_AES_SYMETRIC_KEY);
            aesProvider.IV = Convert.FromBase64String(AES_IV);

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
    }
}
