using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Logic;
using Microsoft.Extensions.DependencyInjection;
using Network;

namespace App;

public class Program
{
	private static IPeerToPeerService peerToPeerService;
	private static IAesCrypto aesCryptoService;
	private static IDhKeyExchange dhKeyExchangeService;
	private static IHkdf hkdfService;

	public Program(
		IPeerToPeerService p2p,
		IAesCrypto aes,
		IDhKeyExchange diffie,
		IHkdf hkdf
	)
	{
		peerToPeerService = p2p;
		aesCryptoService = aes;
		dhKeyExchangeService = diffie;
		hkdfService = hkdf;
	}

	public static async Task Main()
	{
		using ServiceProvider provider = IoC.Build();
		Program program = ActivatorUtilities.CreateInstance<Program>(provider);

		await program.RunAsync();
	}

	public async Task RunAsync()
	{
		Channel<byte[]> incomingMessages =
			Channel.CreateUnbounded<byte[]>();

		peerToPeerService.DataReceived += data =>
		{
			incomingMessages.Writer.TryWrite(data);
		};

		peerToPeerService.StateChanged += (state) =>
		{
			Console.WriteLine($"New peer state: {state}");
		};

		// -------------------------------------------------
		// START NETWORKING
		// -------------------------------------------------

		peerToPeerService.Start();

		Console.WriteLine("Waiting for peer discovery...");

		using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(60));

		while (peerToPeerService.PeerAddress == null)
		{
			timeout.Token.ThrowIfCancellationRequested();
			await peerToPeerService.BroadcastAsync();
			await Task.Delay(1000, timeout.Token);
		}

		Console.WriteLine($"Discovered peer: {peerToPeerService.PeerAddress}");

		// -------------------------------------------------
		// DIFFIE-HELLMAN KEY EXCHANGE
		// -------------------------------------------------

		Console.WriteLine();
		Console.WriteLine("Generating Diffie-Hellman keys...");

		BigInteger privateKey = dhKeyExchangeService.GeneratePrivateKey();

		BigInteger publicKey =
			dhKeyExchangeService.GeneratePublicKey(privateKey);

		byte[] publicKeyBytes =
			publicKey.ToByteArray(
				isUnsigned: true,
				isBigEndian: true);

		Console.WriteLine("Public key generated.");
		Console.WriteLine("Sending public key...");

		await peerToPeerService.SendAsync(publicKeyBytes);

		Console.WriteLine("Public key sent. Waiting for peer...");

		byte[] remotePublicKeyBytes =
			await incomingMessages.Reader.ReadAsync(
				timeout.Token);

		BigInteger remotePublicKey =
			new BigInteger(
				remotePublicKeyBytes,
				isUnsigned: true,
				isBigEndian: true);

		Console.WriteLine("Peer public key received.");

		// -------------------------------------------------
		// DERIVE SHARED SECRET
		// -------------------------------------------------

		BigInteger sharedSecret =
			dhKeyExchangeService.DeriveSharedSecret(
				privateKey,
				remotePublicKey);

		Console.WriteLine();
		Console.WriteLine("Shared secret derived:");

		Console.WriteLine(sharedSecret.ToString("X"));

		// Derive AES key.
		byte[] aesKey = hkdfService.DeriveKey(sharedSecret);

		Console.WriteLine();
		Console.WriteLine("Derived AES key:");

		Console.WriteLine(
			Convert.ToHexString(aesKey));

		Console.WriteLine(
			$"AES key length: {aesKey.Length} bytes");

		// -------------------------------------------------
		// ENCRYPT AND SEND MESSAGE
		// -------------------------------------------------

		string original =
			"Hello from " + Environment.MachineName + "!";

		byte[] plainText =
			Encoding.UTF8.GetBytes(original);

		Console.WriteLine();
		Console.WriteLine("Preparing outgoing message:");

		Console.WriteLine($"Cleartext: {original}");

		byte[] iv = RandomNumberGenerator.GetBytes(16);

		byte[] encrypted = aesCryptoService.Encrypt(
			plainText,
			aesKey,
			iv);

		Console.WriteLine();
		Console.WriteLine("Encryption completed.");

		Console.WriteLine("Ciphertext:");

		Console.WriteLine(
			Convert.ToHexString(encrypted));

		// Package IV + ciphertext.
		byte[] packet = new byte[iv.Length + encrypted.Length];

		Buffer.BlockCopy(iv, 0, packet, 0, iv.Length);

		Buffer.BlockCopy(
			encrypted,
			0,
			packet,
			iv.Length,
			encrypted.Length);

		Console.WriteLine("Sending encrypted message...");

		await peerToPeerService.SendAsync(packet);

		Console.WriteLine("Encrypted message sent!");

		// -------------------------------------------------
		// RECEIVE AND DECRYPT MESSAGE
		// -------------------------------------------------

		Console.WriteLine();
		Console.WriteLine("Waiting for encrypted message...");

		byte[] receivedPacket =
			await incomingMessages.Reader.ReadAsync(
				timeout.Token);

		if (receivedPacket.Length < 16)
			throw new InvalidOperationException(
				"Invalid encrypted message.");

		// Extract IV.
		byte[] receivedIv =
			receivedPacket[..16];

		// Extract ciphertext.
		byte[] receivedCiphertext =
			receivedPacket[16..];

		Console.WriteLine();
		Console.WriteLine("Encrypted message received!");

		Console.WriteLine("Received ciphertext:");

		Console.WriteLine(
			Convert.ToHexString(receivedCiphertext));

		// Decrypt.
		byte[] decrypted = aesCryptoService.Decrypt(
			receivedCiphertext,
			aesKey,
			receivedIv);

		string decryptedText =
			Encoding.UTF8.GetString(decrypted);

		Console.WriteLine();
		Console.WriteLine("Decryption completed.");

		Console.WriteLine($"Received cleartext: {decryptedText}");

		// -------------------------------------------------
		// SUMMARY
		// -------------------------------------------------

		Console.WriteLine();
		Console.WriteLine("=================================");
		Console.WriteLine("SECURE COMMUNICATION TEST");
		Console.WriteLine("=================================");

		Console.WriteLine($"Peer:	  {peerToPeerService.PeerAddress}");
		Console.WriteLine($"Sent:	  {original}");
		Console.WriteLine($"Received: {decryptedText}");

		Console.WriteLine();
		Console.WriteLine("Communication test completed!");

		// -------------------------------------------------
		// CLEANUP
		// -------------------------------------------------

		CryptographicOperations.ZeroMemory(aesKey);
	}
}
