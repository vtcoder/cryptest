using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Client2
{
    public class SecClient2 : IDisposable
    {
        private HttpListener _httpListener;
        private Logger _logger;

        public SecClient2(Logger logger)
            : base()
        {
            _logger = logger;
        }

        public void Dispose()
        {
            _logger.Write("SecClient2 is stopping the HTTP listener...");
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
                    _logger.Write("Receiving a request.");

                    var request = context.Request;
                }
            }
            catch (ObjectDisposedException)
            {
            }
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
                sw.Write("<sectest>testing</sectest>");
            }
            var resp = req.GetResponse();
            var respStream = resp.GetResponseStream();
            using (StreamReader sr = new StreamReader(respStream))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
