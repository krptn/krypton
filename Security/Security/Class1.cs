using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

static (byte[], byte[]) AESEncrypt(byte[] text, byte[] key)
{
    byte[] encrypted;
    var handle = GCHandle.Alloc(text, GCHandleType.Pinned);
    var hand = GCHandle.Alloc(key, GCHandleType.Pinned);
    // Create an Aes object
    // with the specified key and IV.
    byte[] iv;
    using (Aes myAes = Aes.Create())
    {
        iv = myAes.IV;
    }
    using (Aes aesAlg = Aes.Create())
    {
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
    } 
    var r = new Tuple<byte[], byte[]>(encrypted, iv);
    Array.Clear(text, 0, text.Length);
    Array.Clear(key, 0, key.Length);
    handle.Free();
    hand.Free();
    text = null;
    key = null;
    return (encrypted, iv);

}

static (String, GCHandle) AESDecrypt(Byte[] key, Byte[] thing, Byte[] IV)
{
    var handle = GCHandle.Alloc(key, GCHandleType.Pinned);
    // Create an Aes object
    // with the specified key and IV.
    string plaintext;
    GCHandle hand;
    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = key;
        aesAlg.IV = IV;

        // Create a decryptor to perform the stream transform.
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        // Create the streams used for decryption.
        using (MemoryStream msDecrypt = new MemoryStream(thing))
        {
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = srDecrypt.ReadToEnd();
                    hand = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                }
            }
        }
        aesAlg.Clear();
    }

    Array.Clear(key, 0, key.Length);
    handle.Free();
    key = null;
    return (plaintext, hand);
}


static string GetPass()
{
    ConsoleKey key = ConsoleKey.Escape;
    string pass = "000000000000000000";
    GCHandle handle = GCHandle.Alloc(pass, GCHandleType.Pinned);
    ConsoleKeyInfo keyinfo;
    int length = 0;
    while (length < pass.Length)
    {
        keyinfo = Console.ReadKey(intercept: true);
        key = keyinfo.Key;
        length += 1;

        if ((key == ConsoleKey.Backspace) && (pass.Length != 0))
        {
            Console.Write("\b \b");
            pass = pass.Substring(0, pass.Length - 1);
            unsafe
            {
                fixed (char* p = pass)
                {
                    char* i = p + (pass.Length - 1);
                    *i = (char)48;
                }
            }
        }
        else if (key == ConsoleKey.Enter)
        {
            Console.WriteLine("");
            break;
        }
        else
        {
            Console.Write('*');
            unsafe
            {
                fixed (char* p = pass)
                {
                    char* i = p + (length - 1);
                    *i = keyinfo.KeyChar;
                }
            }
        }
    }
    try
    {
        return pass;
    }
    finally
    {
        handle.Free();
        Console.WriteLine("");
    }
}


