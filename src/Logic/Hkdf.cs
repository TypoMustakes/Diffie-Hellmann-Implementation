using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Logic;

public class Hkdf : IHkdf
{
	public byte[] DeriveKey(
		BigInteger sharedSecret,
		int outputLength = 32)
	{
		if (outputLength <= 0 || outputLength > 255 * 32)
		{
			throw new ArgumentOutOfRangeException(nameof(outputLength));
		}

		// Convert the shared secret to unsigned big-endian bytes.
		byte[] inputKeyMaterial = sharedSecret.ToByteArray(
			isUnsigned: true,
			isBigEndian: true
		);
		
		// Public, application-specific salt.
		byte[] salt = Encoding.UTF8.GetBytes(
			"DiffieHellman-AES-HKDF-SHA256"
		);
		
		// Context identifying the purpose of the derived key.
		byte[] info = Encoding.UTF8.GetBytes(
			"AES-256 encryption key"
		);
		
		// HKDF-Extract
		byte[] pseudorandomKey = HMACSHA256.HashData(
			salt,
			inputKeyMaterial
		);
		
		// HKDF-Expand
		byte[] output = new byte[outputLength];
		byte[] previousBlock = [];
		
		int offset = 0;
		byte counter = 1;
		
		while (offset < outputLength)
		{
			byte[] blockInput = new byte[
				previousBlock.Length + info.Length + 1
			];
			
			Buffer.BlockCopy(
				previousBlock, 0,
				blockInput, 0,
				previousBlock.Length
			);
			
			Buffer.BlockCopy(
				info, 0,
				blockInput, previousBlock.Length,
				info.Length
			);
			
			blockInput[^1] = counter;
			
			byte[] block = HMACSHA256.HashData(
				pseudorandomKey,
				blockInput
			);
			
			int bytesToCopy = Math.Min(
				block.Length,
				outputLength - offset
			);
			
			Buffer.BlockCopy(
				block, 0,
				output, offset,
				bytesToCopy
			);
			
			previousBlock = block;
			offset += bytesToCopy;
			counter++;
		}
		
		CryptographicOperations.ZeroMemory(inputKeyMaterial);
		CryptographicOperations.ZeroMemory(pseudorandomKey);
		
		return output;
	}
}
