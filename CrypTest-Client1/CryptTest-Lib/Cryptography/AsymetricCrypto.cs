using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Lib.Cryptography
{
    public class AsymetricCrypto
    {
        public string Decrypt(string encryptedText, string rsaProviderXml)
        {
            //Decode the encrypted text from base 64 to bytes.
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

            //Initialize our asymetric cryptography provider.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(2048);
            rsaProvider.FromXmlString(rsaProviderXml);

            //Decrypt the bytes.
            byte[] decryptedKeyBytes = rsaProvider.Decrypt(encryptedBytes, true);

            //Encode the decrypted bytes as base 64 string.
            string decryptedText = Convert.ToBase64String(decryptedKeyBytes);

            return decryptedText;
        }

        public string CreateSignature(RSACryptoServiceProvider rsaProvider, string message)
        {
            //Create a hash of the message.
            byte[] hashBytes = null;
            SHA256 sha256 = SHA256.Create();
            using (MemoryStream ms = new MemoryStream())
            using (StreamWriter sw = new StreamWriter(ms, Encoding.UTF8))
            {
                sw.Write(message);
                sw.Close();

                hashBytes = sha256.ComputeHash(ms.ToArray());
            }

            //Encrypt the hash using the asymetric private key (to be decrypted on the other side using public key soley as means for them to verify
            //this side has the associated private key).
            byte[] signedHashBytes = rsaProvider.SignHash(hashBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            //Encode the signed hash as base 64.
            string signedHash = Convert.ToBase64String(signedHashBytes);
            return signedHash;
        }
    }
}
