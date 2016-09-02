using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptTest_Lib.Cryptography
{
    public class HashCrypto
    {
        public bool VerifyHmac(string encryptedMessage, string hmacHash, string key)
        {
            bool isHmacValid = false;
            
            //Initialize the HMAC MD5 component.
            var hmacMD5 = HMACMD5.Create();
            hmacMD5.Key = Convert.FromBase64String(key);
            
            //Compute our hash of the encrypted message.
            var encryptedMessageBytes = Convert.FromBase64String(encryptedMessage);
            var ourHmacHashBytes = hmacMD5.ComputeHash(encryptedMessageBytes);
            string ourHmacHash = Convert.ToBase64String(ourHmacHashBytes);

            //Consider the HMAC valid if our internally computed hash matches the one provided with the message.
            isHmacValid = hmacHash == ourHmacHash;
            return isHmacValid;
        }
    }
}
