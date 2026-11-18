using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Logic;

/// <summary>
/// Provides AES encryption and decryption using the CBC (Cipher Block Chaining)
/// block cipher mode and PKCS#7 padding.
///
/// This implementation supports all three standard AES key sizes:
/// - 128-bit
/// - 192-bit
/// - 256-bit
///
/// AES always operates on fixed-size blocks of 128 bits (16 bytes),
/// regardless of the selected key size.
///
/// CBC mode combines each plaintext block with the previous ciphertext
/// block before encryption. An Initialization Vector is used
/// for the first block to ensure that no ciphertext is the same,
/// even if the cleartext input and the encryption key remain unchanged.
///
/// PKCS#7 padding is applied to ensure that the plaintext length
/// is a multiple of AES's 16-byte block size.
/// </summary>
public class AesCrypto : IAesCrypto
{
	/// <summary>
	/// Encrypts plaintext using AES in CBC mode with PKCS#7 padding.
	///
	/// The encryption process consists of:
	///
	/// 1. Validating the AES key and initialization vector.
	/// 2. Creating an AES-CBC cipher with PKCS#7 padding.
	/// 3. Initializing the cipher in encryption mode.
	/// 4. Encrypting the plaintext and applying padding.
	///
	///<param name="cleartext">The original, unencrypted data.</param>
	///<param name="key">The secret AES key. Must contain 16, 24, or 32 bytes.</param>
	///<param name="iv">The initialization vector. Must contain exactly 16 bytes.</param>
	///
	///<returns>The encrypted ciphertext, including any required padding.</returns>
	/// </summary>
	public byte[] Encrypt(byte[] cleartext, byte[] key, byte[] iv)
	{
		// Ensure that the supplied AES key and IV have valid lengths.
		// AES always uses a 128-bit block size, so CBC
		// requires an IV that is exactly 16 bytes long.
		ValidateParameters(key, iv);

		// Create a buffered block cipher using three components:
		//
		// 1. AesEngine:
		//	  Implements the underlying AES block cipher.
		//	  It performs the actual AES encryption operations on
		//	  individual 16-byte blocks.
		//
		// 2. CbcBlockCipher:
		//	  Wraps the AES engine in Cipher Block Chaining mode.
		//	  Each plaintext block is XORed with the previous ciphertext
		//	  block before being encrypted.
		//
		//	  For the first block, the IV is used instead of
		//	  a previous ciphertext block.
		//
		// 3. Pkcs7Padding:
		//	  Adds padding bytes when the plaintext length is not
		//	  an exact multiple of AES's 16-byte block size.
		//
		//	  PKCS#7 also adds a complete block of padding when the
		//	  plaintext length is already a multiple of 16 bytes.
		//
		// PaddedBufferedBlockCipher combines these components into
		// a cipher that can process arbitrary-length input data.
		IBufferedCipher cipher = new PaddedBufferedBlockCipher(
			new CbcBlockCipher(new AesEngine()),
			new Pkcs7Padding()
		);

		// Initialize the cipher with the key and IV.
		// The first argument determines the cipher's operating mode:
		//
		// true	 = encryption.
		// false = decryption.
		//
		// KeyParameter wraps the raw AES key in a BouncyCastle
		// parameter object understood by the AES engine.
		//
		// ParametersWithIV associates the AES key with the
		// initialization vector required by CBC mode.
		//
		// The resulting configuration is equivalent to:
		//
		// AES-CBC(
		//	   key = supplied AES key,
		//	   iv  = supplied initialization vector
		// )
		cipher.Init(
			true,
			new ParametersWithIV(new KeyParameter(key), iv)
		);

		// Encrypt the supplied plaintext and return the final ciphertext.
		//
		// DoFinal performs the remaining cipher operations and finalizes
		// the encryption process.
		//
		// During this operation:
		//
		// 1. PKCS#7 padding is applied to the plaintext.
		// 2. The padded plaintext is divided into 16-byte blocks.
		// 3. CBC mode combines each block with the previous ciphertext
		//	  block (or the IV for the first block).
		// 4. Each resulting block is encrypted using AES.
		//
		// Conceptually, CBC encryption works as follows:
		//
		// C[0] = AES_Encrypt(K, P[0] XOR IV)
		//
		// C[i] = AES_Encrypt(K, P[i] XOR C[i-1])
		//
		// Where:
		// - K is the AES encryption key.
		// - P[i] is the current plaintext block.
		// - C[i] is the resulting ciphertext block.
		// - XOR is the bitwise exclusive OR operation.
		//
		// The returned byte array contains the encrypted data,
		// including the effects of PKCS#7 padding.
		return cipher.DoFinal(cleartext);
	}

	/// <summary>
	/// Decrypts ciphertext using AES in CBC mode with PKCS#7 padding.
	///
	/// Decryption reverses the encryption process:
	///
	/// 1. Validating the AES key and initialization vector.
	/// 2. Creating an AES-CBC cipher with PKCS#7 padding.
	/// 3. Initializing the cipher in decryption mode.
	/// 4. Decrypting the ciphertext and removing padding.
	///
	/// The same AES key and IV used during encryption must be supplied.
	///
	///<param name="ciphertext">The encrypted data to decrypt.</param>
	///<param name="key">The same secret AES key used during encryption.</param>
	///<param name="iv">The same initialization vector used during encryption.</param>
	///
	///<returns>The original plaintext with PKCS#7 padding removed.</returns>
	/// </summary>
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


		// Decrypt the ciphertext and remove the PKCS#7 padding.
		//
		// DoFinal performs the complete decryption operation:
		//
		// 1. The ciphertext is divided into 16-byte blocks.
		// 2. Each block is decrypted using the AES algorithm.
		// 3. CBC chaining is reversed by XORing the decrypted block
		//	  with the previous ciphertext block (or the IV for the
		//	  first block).
		// 4. PKCS#7 padding is checked and removed.
		//
		// Conceptually, CBC decryption works as follows:
		//
		// P[0] = AES_Decrypt(K, C[0]) XOR IV
		//
		// P[i] = AES_Decrypt(K, C[i]) XOR C[i-1]
		//
		// Where:
		// - K is the AES encryption key.
		// - C[i] is the current ciphertext block.
		// - P[i] is the resulting plaintext block.
		// - XOR is the bitwise exclusive OR operation.
		return cipher.DoFinal(ciphertext);
	}

	/// <summary>
	/// Validates the lengths of the AES key and CBC initialization vector.
	///
	/// AES supports three standardized key sizes:
	/// - 128 bits (16 bytes).
	/// - 192 bits (24 bytes).
	/// - 256 bits (32 bytes).
	///
	/// Regardless of the key size, AES always operates on 128-bit
	/// (16-byte) blocks.
	///
	/// CBC mode requires an initialization vector matching the
	/// block size, meaning the IV must also contain exactly 16 bytes.
	///
	/// Parameters:
	///	  key: The AES secret key.
	///	  iv: The CBC initialization vector.
	///
	/// Throws:
	///	  ArgumentException if either parameter is null or has
	///	  an invalid length.
	/// </summary>
	private static void ValidateParameters(byte[] key, byte[] iv)
	{
		if (key == null || (key.Length != 16 &&
							key.Length != 24 &&
							key.Length != 32))
		{
			// Throw an exception rather than allowing the AES engine
			// to operate with an invalid key configuration.
			throw new ArgumentException(
				"AES key must be 16, 24, or 32 bytes."
			);
		}

		// Reject a null IV or an IV whose length differs from 16 bytes.
		if (iv == null || iv.Length != 16)
		{
			throw new ArgumentException(
				"AES-CBC IV must be exactly 16 bytes."
			);
		}
	}
}
