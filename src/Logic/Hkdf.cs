using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Logic;

/// <summary>
/// Implements HKDF (HMAC-based Key Derivation Function) using SHA-256.
///
/// Derive one or more cryptographically strong keys from existing
/// key material, such as, in this case, a shared secret established through Diffie-Hellman.
///
/// The implementation consists of two main stages:
///
/// 1. Extract: Converts the input key material into a pseudorandom key
///	   using HMAC-SHA256.
///
/// 2. Expand: Uses the pseudorandom key to generate the requested number
///	   of output bytes, again using HMAC-SHA256.
///
/// This implementation uses SHA-256, meaning each HMAC operation
/// produces a 256-bit result.
/// </summary>
public class Hkdf : IHkdf
{
	/// <summary>
	/// Derives cryptographically strong key material from a shared secret.
	///
	/// The shared secret is treated as the Input Keying Material (IKM)
	///
	/// The resulting key material can be used as an encryption key,
	/// provided the requested output length matches the requirements
	/// of the intended cryptographic algorithm.
	///
	/// The maximum output length for HKDF-SHA256 is 255 * 32 bytes.
	/// This is because the Expand stage uses a single-byte counter,
	/// allowing a maximum of 255 HMAC-SHA256 output blocks.
	///
	/// <param name="sharedSecret">The secret value established through key exchange</param>
	///	<param name="outputLength">The desired number of output bytes. Defaults to 32 bytes (256 bits), suitable for AES-256.</param>
	///
	///	<returns>A byte array containing the derived key material.</returns>
	/// </summary>
	public byte[] DeriveKey(
		BigInteger sharedSecret,
		int outputLength = 32)
	{
		// HKDF-SHA256 produces blocks of 32 bytes during the Expand stage.
		//
		// Its one-byte block counter limits the number of blocks to 255.
		// Therefore, the maximum possible output length is:
		//
		// 255 blocks * 32 bytes = 8160 bytes.
		if (outputLength <= 0 || outputLength > 255 * 32)
		{
			throw new ArgumentOutOfRangeException(nameof(outputLength));
		}
		
		// Convert the shared secret from BigInteger into a byte array.
		//
		// isUnsigned: true
		//	 Treats the BigInteger as an unsigned integer. We do
		//	 not want a sign bit or two's-complement representation.
		//
		// isBigEndian: true
		//	 Stores the most significant byte first.
		//
		// Big-endian encoding provides a consistent byte representation
		// for the input key material.
		//
		// IKM is the initial secret material
		// supplied to HKDF-Extract.
		byte[] inputKeyMaterial = sharedSecret.ToByteArray(
			isUnsigned: true,
			isBigEndian: true
		);
		
		// The salt is a public, application-specific value.
		//
		// The salt is used as the HMAC key during the Extract
		// stage. It helps ensure that the resulting pseudorandom key
		// is derived in a context-specific manner.
		//
		// Since a salt does not need to be secret, for demonstration purposes, I've hardcoded it here into the source code
		byte[] salt = Encoding.UTF8.GetBytes(
			"DiffieHellman-AES-HKDF-SHA256"
		);
		
		// The info parameter provides context about the purpose of
		// the key being derived.
		//
		// Unlike the salt, info is not used to extract randomness.
		// Instead, it provides domain separation: the same shared secret
		// can produce different derived keys when different info values
		// are supplied.
		//
		// For example, different info strings could be used to derive:
		// - An AES encryption key.
		// - An HMAC authentication key.
		// - A separate key for another communication direction.
		//
		// This helps prevent accidental reuse of the same derived key
		// for different cryptographic purposes.
		byte[] info = Encoding.UTF8.GetBytes(
			"AES-256 encryption key"
		);
		
		// HKDF-Extract takes the IKM and salt
		// and produces a pseudorandom key (PRK).
		//
		// PRK = HMAC-SHA256(salt, IKM)
		//
		// HMAC is a cryptographic construction
		// that combines a hash function with a secret key.
		//
		// Here:
		// - The salt is used as the HMAC key.
		// - The input key material is the HMAC message.
		// - SHA-256 is the underlying hash function.
		//
		// The result is always 32 bytes because SHA-256 produces
		// a 256-bit hash.
		//
		// The PRK is the pseudorandom key used as the HMAC key
		// in the subsequent Expand stage.
		byte[] pseudorandomKey = HMACSHA256.HashData(
			salt,
			inputKeyMaterial
		);
		
		// Allocate the output buffer that will hold the derived key.
		//
		// Its size is determined by the requested output length,
		// rather than the fixed 32-byte size of an individual HMAC block.
		byte[] output = new byte[outputLength];
		
		// T(0) is defined as an empty byte string.
		//
		// This variable stores the previous HMAC output block.
		// During the first iteration, it is empty.
		//
		// During subsequent iterations, it contains the previous
		// 32-byte HMAC result.
		//
		// The previous block is incorporated into the next HMAC
		// operation to ensure that the generated blocks are chained
		// together rather than independently generated.
		byte[] previousBlock = [];
		
		// Tracks the current write position in the output buffer.
		//
		// Each iteration copies as many bytes as are still needed
		// from the newly generated HMAC block.
		int offset = 0;
		
		// HKDF-Expand uses a one-byte counter to distinguish
		// individual output blocks.
		//
		// The counter starts at 1 and increases with each iteration.
		//
		// This allows HKDF to generate up to 255 distinct blocks.
		byte counter = 1;
		
		// Continue generating HMAC blocks until the requested
		// output length has been completely filled.
		while (offset < outputLength)
		{
			// Construct the input message for the current HMAC operation.
			//
			// According to RFC 5869, each Expand block is calculated as:
			//
			// T(i) = HMAC-SHA256(
			//	   PRK,
			//	   T(i-1) || info || counter
			// )
			//
			// Where:
			// - PRK is the pseudorandom key from Extract.
			// - T(i-1) is the previous output block.
			// - info provides application-specific context.
			// - counter identifies the current output block.
			//
			// The || symbol represents byte concatenation.
			//
			// The buffer therefore needs enough space for:
			// - The previous block.
			// - The info/context data.
			// - One byte for the counter.
			byte[] blockInput = new byte[
				previousBlock.Length + info.Length + 1
			];
			
			// Append the previous HMAC output block to the beginning
			// of the current HMAC input.
			//
			// On the first iteration, previousBlock is empty,
			// so nothing is copied.
			//
			// On later iterations, this ensures that each new block
			// depends on the previous block.
			Buffer.BlockCopy(
				previousBlock, 0,
				blockInput, 0,
				previousBlock.Length
			);
			
			// Append the context information immediately after
			// the previous block.
			//
			// The resulting buffer now contains:
			//
			// T(i-1) || info
			Buffer.BlockCopy(
				info, 0,
				blockInput, previousBlock.Length,
				info.Length
			);
			
			// Store the current block counter in the final byte
			// of the HMAC input buffer.
			//
			// The resulting complete message is:
			//
			// T(i-1) || info || counter
			//
			// Since the counter is a byte, it can represent values
			// from 0 to 255. HKDF specifically uses values 1 to 255.
			blockInput[^1] = counter;
			
			// Calculate the next HKDF output block.
			//
			// HMAC-SHA256 uses the pseudorandom key (PRK) as its key
			// and the constructed blockInput as its message.
			//
			//
			// T(i) = HMAC-SHA256(PRK, blockInput)
			//
			// Every call produces exactly 32 bytes.
			byte[] block = HMACSHA256.HashData(
				pseudorandomKey,
				blockInput
			);
			
			// Determine how many bytes should be copied into the
			// final output buffer.
			//
			// A full HMAC block contains 32 bytes, but the requested
			// output length might not be a multiple of 32.
			//
			// For example, if only 16 bytes remain, we copy 16 bytes
			// rather than the entire 32-byte block.
			int bytesToCopy = Math.Min(
				block.Length,
				outputLength - offset
			);
			
			// Copy the required portion of the current HMAC block
			// into the final output buffer.
			//
			// block:
			//	 The newly generated 32-byte HMAC result.
			//
			// output:
			//	 The destination buffer containing the derived key.
			//
			// offset:
			//	 The position where the new bytes should be written.
			//
			// bytesToCopy:
			//	 The number of bytes to copy from this block.
			Buffer.BlockCopy(
				block, 0,
				output, offset,
				bytesToCopy
			);
			
			// Preserve the current block for the next iteration.
			//
			// In the next iteration, this becomes T(i-1), allowing
			// the HKDF output blocks to be chained together.
			previousBlock = block;
			
			// Advance the output position by the number of bytes
			// that were just copied.
			offset += bytesToCopy;
			
			// Increment the counter so the next HMAC operation
			// produces a different output block.
			//
			// The loop is guaranteed to finish before more than
			// 255 blocks are required because of the initial
			// outputLength validation.
			counter++;
		}
		
		// Last step: clean up sensitive leftover data
		// Explicitly overwrite the input key material buffer.
		//
		// The original shared secret is sensitive cryptographic data.
		// Once the Extract stage has completed, this particular byte
		// array is no longer required.
		//
		// ZeroMemory attempts to overwrite the contents of the buffer
		// rather than simply allowing it to be reclaimed by the garbage
		// collector later, which would be unpredictable.
		CryptographicOperations.ZeroMemory(inputKeyMaterial);
		
		// Explicitly overwrite the pseudorandom key (PRK).
		//
		// The PRK is also sensitive because it is the key used
		// throughout the Expand stage.
		//
		// It is no longer needed after all output blocks have
		// been generated.
		CryptographicOperations.ZeroMemory(pseudorandomKey);
		
		// Return the derived key material.
		//
		// The output buffer is intentionally not cleared because
		// it contains the key material that the caller requested.
		return output;
	}
}

// Research material used for this implementation:
//	   - RFC standards
//	   - ComputerPhile
