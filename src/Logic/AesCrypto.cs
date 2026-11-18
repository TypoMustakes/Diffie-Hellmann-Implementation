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
		IBufferedCipher cipher = new PaddedBufferedBlockCipher(
			new CbcBlockCipher(new AesEngine()),
			new Pkcs7Padding()
		);

		cipher.Init(
			false,
			new ParametersWithIV(
				new KeyParameter(key),
				iv
			)
		);

		return cipher.DoFinal(ciphertext);
	}
}
