using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;
using Logic;

namespace App;

public static class Program
{
	public static void Main()
	{
		AesCrypto crypto = new();

		DhKeyExchange dh = new(
			new ParameterGenerator()
		);

		Hkdf hkdf = new();

		// Generate private keys.
		BigInteger alicePrivateKey = dh.GeneratePrivateKey();
		BigInteger bobPrivateKey = dh.GeneratePrivateKey();

		// Generate public keys.
		BigInteger alicePublicKey =
			dh.GeneratePublicKey(alicePrivateKey);

		BigInteger bobPublicKey =
			dh.GeneratePublicKey(bobPrivateKey);

		// Derive shared secrets independently.
		BigInteger aliceSharedSecret =
			dh.DeriveSharedSecret(
				alicePrivateKey,
				bobPublicKey
			);

		BigInteger bobSharedSecret =
			dh.DeriveSharedSecret(
				bobPrivateKey,
				alicePublicKey
			);

		// Verify that both parties obtained the same secret.
		Debug.Assert(aliceSharedSecret == bobSharedSecret);

		Console.WriteLine(
			$"Shared secrets match: {aliceSharedSecret == bobSharedSecret}"
		);

		// Derive AES keys independently.
		byte[] aliceKey = hkdf.DeriveKey(aliceSharedSecret);
		byte[] bobKey = hkdf.DeriveKey(bobSharedSecret);

		Debug.Assert(aliceKey.SequenceEqual(bobKey));

		Console.WriteLine($"Alice AES key length: {aliceKey.Length}");
		Console.WriteLine($"Bob AES key length: {bobKey.Length}");

		// Generate a fresh random IV for this encryption.
		byte[] iv = RandomNumberGenerator.GetBytes(16);

		string original = "Here is some data to encrypt";

		byte[] plainText = Encoding.UTF8.GetBytes(original);

		// Alice encrypts.
		byte[] encrypted = crypto.Encrypt(
			plainText,
			aliceKey,
			iv
		);

		// Bob decrypts using his independently derived key.
		byte[] decrypted = crypto.Decrypt(
			encrypted,
			bobKey,
			iv
		);

		string decryptedText = Encoding.UTF8.GetString(decrypted);

		Console.WriteLine($"Original:  {original}");
		Console.WriteLine($"Encrypted: {Convert.ToBase64String(encrypted)}");
		Console.WriteLine($"Decrypted: {decryptedText}");

		// Clear sensitive key material.
		CryptographicOperations.ZeroMemory(aliceKey);
		CryptographicOperations.ZeroMemory(bobKey);
	}
}
