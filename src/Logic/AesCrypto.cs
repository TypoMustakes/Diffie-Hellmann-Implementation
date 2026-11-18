using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Logic;

public class AesCrypto : IAesCrypto
{
	public byte[] Encrypt(byte[] cleartext, byte[] key, byte[] iv)
	{
		ValidateParameters(key, iv);
		
		IBufferedCipher cipher = new PaddedBufferedBlockCipher(
			new CbcBlockCipher(new AesEngine()),
			new Pkcs7Padding()
		);
		
		cipher.Init(
			true,
			new ParametersWithIV(new KeyParameter(key), iv)
		);
		
		return cipher.DoFinal(cleartext);
	}
	
	public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
	{
		ValidateParameters(key, iv);
		
		IBufferedCipher cipher = new PaddedBufferedBlockCipher(
			new CbcBlockCipher(new AesEngine()),
			new Pkcs7Padding()
		);
		
		cipher.Init(
			false,
			new ParametersWithIV(new KeyParameter(key), iv)
		);
		
		return cipher.DoFinal(ciphertext);
	}
	
	private static void ValidateParameters(byte[] key, byte[] iv)
	{
		if (key == null || (key.Length != 16 &&
							key.Length != 24 &&
							key.Length != 32))
		{
			throw new ArgumentException(
				"AES key must be 16, 24, or 32 bytes."
			);
		}
		
		if (iv == null || iv.Length != 16)
		{
			throw new ArgumentException(
				"AES-CBC IV must be exactly 16 bytes."
			);
		}
	}
}
