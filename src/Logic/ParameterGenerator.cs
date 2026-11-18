using System.Numerics;
using System.Security.Cryptography;

namespace Logic;

public class ParameterGenerator : IParameterGenerator
{
	// RFC 3526, 2048-bit MODP Group (Group 14)
	// Essentially 2^2048 - 2^1984 - 1 + 2^64 * (pi*2^1918 + 124476)
	// The generator is 2
	private const string PrimeHex =
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
	private readonly BigInteger _g = 2;

	public BigInteger[] GenerateParameters(int bitLength)
	{
		byte[] primeBytes = Convert.FromHexString(PrimeHex);
		
		BigInteger p = new BigInteger(
			primeBytes,
			isUnsigned: true,
			isBigEndian: true
		);
		
		return [p, _g];
	}
	
	public BigInteger RandomBelow(BigInteger max)
	{
		if (max <= 0)
			throw new ArgumentOutOfRangeException(nameof(max));
		
		byte[] bytes = max.ToByteArray(
			isUnsigned: true,
			isBigEndian: true
		);
		
		BigInteger result;
		
		do
		{
			RandomNumberGenerator.Fill(bytes);
			
			result = new BigInteger(
				bytes,
				isUnsigned: true,
				isBigEndian: true
			);
		}
		while (result >= max);
		
		return result;
	}
}

