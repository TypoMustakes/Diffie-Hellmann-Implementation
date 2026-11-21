using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;

using Logic;
using Network;

public static class Program
{
	public static async Task Main()
	{
		using PeerToPeerService service = new();

		AesCrypto crypto = new();
		DhKeyExchange dh = new(new ParameterGenerator());
		Hkdf hkdf = new();

		// Queue incoming TCP messages.
		Channel<byte[]> incomingMessages =
			Channel.CreateUnbounded<byte[]>();

		service.DataReceived += data =>
		{
			incomingMessages.Writer.TryWrite(data);
		};

		// Start networking.
		service.Start();

		Console.WriteLine("Waiting for peer discovery...");

		// Advertise our presence.
		await service.BroadcastAsync(
			Encoding.UTF8.GetBytes("HELLO"));

		// Wait until we discover the other peer.
		using CancellationTokenSource timeout =
			new(TimeSpan.FromSeconds(60));

		while (service.PeerAddress == null)
		{
			timeout.Token.ThrowIfCancellationRequested();
			await Task.Delay(100, timeout.Token);
		}

		Console.WriteLine(
			$"Discovered peer: {service.PeerAddress}");

		Console.WriteLine("Generating Diffie-Hellmann keys...");

		BigInteger privateKey = dh.GeneratePrivateKey();

		BigInteger publicKey =
			dh.GeneratePublicKey(privateKey);

		// Send our public key.
		byte[] publicKeyBytes =
			publicKey.ToByteArray(
				isUnsigned: true,
				isBigEndian: true);

		await service.SendAsync(publicKeyBytes);

		Console.WriteLine("Public key sent. Waiting for peer...");

		// Receive the peer's public key.
		byte[] remotePublicKeyBytes =
			await incomingMessages.Reader.ReadAsync(
				timeout.Token);

		BigInteger remotePublicKey =
			new BigInteger(
				remotePublicKeyBytes,
				isUnsigned: true,
				isBigEndian: true);

		Console.WriteLine("Peer public key received.");

		BigInteger sharedSecret =
			dh.DeriveSharedSecret(
				privateKey,
				remotePublicKey);

		Console.WriteLine("Shared secret derived.");

		// Derive AES key.
		byte[] aesKey = hkdf.DeriveKey(sharedSecret);

		Console.WriteLine($"AES key length: {aesKey.Length}");

		// Encrypt and send message

		string original =
			"Hello from " + Environment.MachineName + "!";

		byte[] plainText =
			Encoding.UTF8.GetBytes(original);

		// Generate fresh IV.
		byte[] iv = RandomNumberGenerator.GetBytes(16);

		// Encrypt.
		byte[] encrypted = crypto.Encrypt(
			plainText,
			aesKey,
			iv);

		// Package IV + ciphertext into one message.
		byte[] packet = new byte[iv.Length + encrypted.Length];

		Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);

		Buffer.BlockCopy(
			encrypted,
			0,
			packet,
			iv.Length,
			encrypted.Length);

		// Send to discovered peer.
		await service.SendAsync(packet);

		Console.WriteLine("Encrypted message sent!");

		// Receive and decrypt message

		Console.WriteLine("Waiting for encrypted message...");

		byte[] receivedPacket =
			await incomingMessages.Reader.ReadAsync(
				timeout.Token);

		if (receivedPacket.Length < 16)
			throw new InvalidOperationException(
				"Invalid encrypted message.");

		// Extract IV.
		byte[] receivedIv =	receivedPacket[..16];

		// Extract ciphertext.
		byte[] receivedCiphertext =	receivedPacket[16..];

		// Decrypt.
		byte[] decrypted = crypto.Decrypt(
			receivedCiphertext,
			aesKey,
			receivedIv);

		string decryptedText =
			Encoding.UTF8.GetString(decrypted);

		Console.WriteLine();
		Console.WriteLine("=================================");
		Console.WriteLine("SECURE COMMUNICATION TEST");
		Console.WriteLine("=================================");

		Console.WriteLine($"Sent:	  {original}");
		Console.WriteLine($"Received: {decryptedText}");

		// Clear sensitive key material.
		CryptographicOperations.ZeroMemory(aesKey);

		Console.WriteLine();
		Console.WriteLine("Communication test completed!");

		Console.ReadLine();
	}
}
