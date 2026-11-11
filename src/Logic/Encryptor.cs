using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Security;

namespace Logic;

public class Encryptor : IEncryptor
{
	private static byte[] GenerateKey(int length = 32)
	{
		return SecureRandom(length);
	}
	
	private static byte[] SecureRandom(int length)
	{
		SecureRandom defaultSecureRandom = new SecureRandom();
		byte[] bytes = new byte[length];
		defaultSecureRandom.NextBytes(bytes);
		return bytes;
	}
	
	public byte[] EncryptBytes(byte[] clearText, byte[] key, byte[] iv)
	{
		using (Aes aesAlg = Aes.Create())
		{
			aesAlg.Key = key;
			aesAlg.IV = iv;
			
			ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
			
			using (MemoryStream msEncrypt = new MemoryStream())
			{
				using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
				{
					csEncrypt.Write(clearText, 0, clearText.Length);
				}
				return msEncrypt.ToArray();
			}
		}
	}
	
	public byte[] DecryptBytes(byte[] cipherText, byte[] key, byte[] iv)
	{
		using (Aes aesAlg = Aes.Create())
		{
			aesAlg.Key = key;
			aesAlg.IV = iv;
			
			ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
			
			using (MemoryStream msDecrypt = new MemoryStream(cipherText))
			{
				using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
				{
					using (StreamReader srDecrypt = new StreamReader(csDecrypt))
					{
						return Encoding.UTF8.GetBytes(srDecrypt.ReadToEnd());
					}
				}
			}
		}
	}
}
