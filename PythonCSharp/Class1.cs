using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PythonCSharp
{
    public class PythonObject
    {
        string name;
        StreamWriter writer;
        StreamReader reader;
        public PythonObject(string path, StreamWriter writera, StreamReader readera)
        {
            name = path;
            writer = writera;
            reader = readera;

        }
        public void ReadVar (string var)
        {

        }
        public void RunMethod (string var)
        {

        }
    }
    public class Crypto
    {
        public Crypto()
        {

        }
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

        static (string, GCHandle) AESDecrypt(byte[] key, byte[] thing, byte[] IV)
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
    }


    public class ToPython : IDisposable
    {
        private string path;
        private NamedPipeServerStream server;
        private Process process;
        string name;
        StreamReader reader;
        StreamWriter writer;
        public ToPython(string path)
        {
            this.path = path;
            name = Path.GetRandomFileName();
            server = new NamedPipeServerStream(name);
            process = new Process();
            process.StartInfo.FileName = path;
            process.StartInfo.Arguments = "-m PySec "+name;
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.Start();
            server.WaitForConnection();
            reader = new StreamReader(server);
            writer = new StreamWriter(server);
            writer.AutoFlush = true;

        }

        public PythonObject import(string name)
        {
            writer.WriteLine("import " + name);
            PythonObject b = new PythonObject(name, writer, reader);
            return b;
        }

        public void Dispose()
        {
            writer.Close();
            reader.Close();
            server.Close();
            process.Kill();
            process.Close();
            server.Dispose();
            writer.Dispose();
            reader.Dispose();
            process.Dispose();
            path = null;
            name = null;
            server = null;
            process = null;
            writer = null;
            reader = null;
        }
    }
}
