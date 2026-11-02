namespace Logic;

public interface IEncryptor
{
    public string EncryptString(string key, string input);
    public string DecryptString(string key, string input);
    public FileInfo EncryptFile(string key, string inPath, string outPath);
    public FileInfo DecryptFile(string key, string inPath, string outPath);
}
