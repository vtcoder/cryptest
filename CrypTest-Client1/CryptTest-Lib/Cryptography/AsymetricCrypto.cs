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
        public string Encrypt(byte[] plainBytes, string rsaProviderXml)
        {
            //Initialize our asymetric cryptography provider.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(2048);
            rsaProvider.FromXmlString(rsaProviderXml);

            //Encrypt the symetric private key and IV with the asymetric public key.
            var encryptedBytes = rsaProvider.Encrypt(plainBytes, true);

            //Encode encrypted key and IV as base64 string to send on wire.
            string encryptedText = Convert.ToBase64String(encryptedBytes);
            return encryptedText;
        }

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

        public bool VerifySignature(string rsaProviderXml, string signature)
        {
            bool isSignatureValue = false;

            //Initialize our asymetric cryptography provider. This will just have the public key.
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(rsaProviderXml);

            //Create a hash of the message (to use for authentication signature verifiation).
            byte[] hashBytes = null;
            SHA256 sha256 = SHA256.Create();
            using (MemoryStream ms = new MemoryStream())
            using (StreamWriter sw = new StreamWriter(ms, Encoding.UTF8))
            {
                sw.Write(rsaProviderXml);
                sw.Close();

                hashBytes = sha256.ComputeHash(ms.ToArray());
            }

            //Check the authentication signature to make sure it is valid.
            //This tells us
            // a) The sender has the private key associated with this public key, so they are who they say they are (assuming we know we can trust the public key, like with a certificate, but ignoring that part for now)
            // b) The message content was not tampered with. This because the hash of the message has to match.
            byte[] signatureBytes = Convert.FromBase64String(signature);
            bool isSignatureValid = rsaProvider.VerifyHash(hashBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return isSignatureValue;
        }
    }
}
