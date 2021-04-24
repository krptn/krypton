using System;
using System.IO;
using System.Security.Cryptography;

namespace ExternalSecurity
{
    public class HSM
    {

    }
    
    public class helper
    {
        public helper()
        {

        }

        public byte[] AESEncrypt(byte[] text, byte[] key)
        {
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            byte[] iv;
            using (Aes myAes = Aes.Create())
            {
                iv = myAes.IV;
            }
                Aes aesAlg = Aes.Create();
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(text);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            aesAlg.Clear();
            byte[] r;

            byte[0] = encrypted;
            byte[1] = iv;


            return r;
        }
    }
}
