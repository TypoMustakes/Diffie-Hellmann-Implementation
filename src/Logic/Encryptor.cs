namespace Logic;
using Crypto.AES;
using System.IO;

public class Encryptor : IEncryptor
{
    public string EncryptString(string key, string input)
    {
        using (AES aes = new AES(key))
        {
            return aes.Encrypt(input);
        }
    }

    public string DecryptString(string key, string input)
    {
        using (AES aes = new AES(key))
        {
            return aes.Decrypt(input);
        }
    }

    public FileInfo EncryptFile(string key, string inPath, string outPath = "./.out.tmp")
    {
        return AES.EncryptFile(key, inPath, outPath);
    }

    public FileInfo DecryptFile(string key, string inPath, string outPath = "./.out.tmp")
    {
        return AES.DecryptFile(key, inPath, outPath);
    }
}
