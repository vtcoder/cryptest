using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Lib.Cryptography
{
    public class SymetricCrypto
    {
        public Tuple<byte[], byte[]> GenerateKeyAndIv()
        {
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;
            return new Tuple<byte[], byte[]>(aesProvider.Key, aesProvider.IV);
        }

        public string Decrypt(string encryptedText, string key, string iv)
        {
            string plainText = null;

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = 256;

            aesProvider.Key = Convert.FromBase64String(key);
            aesProvider.IV = Convert.FromBase64String(iv);

            var encryptedBytes = Convert.FromBase64String(encryptedText);

            using (MemoryStream ms = new MemoryStream(encryptedBytes))
            using (CryptoStream cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                plainText = sr.ReadToEnd();
            }

            return plainText;
        }
    }
}
