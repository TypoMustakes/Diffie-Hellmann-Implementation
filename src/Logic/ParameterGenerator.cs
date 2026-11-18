using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;

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

	private BigInteger GeneratePrime(int bitLength)
	{
		SecureRandom random = new SecureRandom();
		
		byte[] bytes = Org.BouncyCastle.Math.BigInteger
			.ProbablePrime(bitLength, random)
			.ToByteArrayUnsigned();
		
		return new BigInteger(
			bytes,
			isUnsigned: true,
			isBigEndian: true
		);
	}

	// Find a primitive root modulo p
	private BigInteger FindPrimitiveRoot(BigInteger p)
	{
		List<BigInteger> primeFactors = GetPrimeFactors(p - 1);
		
		for (BigInteger g = 2; g < p; g++)
		{
			if (IsGenerator(g, p, primeFactors))
				return g;
		}

		throw new NoPrimeFactorException();
	}
	
	// Check if a number is a primitive root modulo p
	private bool IsGenerator(
		BigInteger g,
		BigInteger p,
		List<BigInteger> primeFactors)
	{
		foreach (BigInteger q in primeFactors)
		{
			if (BigInteger.ModPow(g, (p - 1) / q, p) == 1)
				return false;
		}
		
		return true;
	}

	// Find distinct prime factors of a number
	private List<BigInteger> GetPrimeFactors(BigInteger n)
	{
		List<BigInteger> factors = new();
		
		if (n % 2 == 0)
		{
			factors.Add(2);
			while (n % 2 == 0)
			{
				n /= 2;
			}
		}
		
		for (BigInteger i = 3; i * i <= n; i += 2)
		{
			if (n % i == 0)
			{
				factors.Add(i);
				while (n % i == 0)
				{
					n /= i;
				}
			}
		}

		if (n > 1)
		{
			factors.Add(n);
		}

		return factors;
	}

	//Miller-Rabin primality test
	private bool IsPrime(BigInteger n, int rounds = 40)
	{
		if (n < 2)
			return false;

		// Handle small primes.
		int[] smallPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };

		foreach (int p in smallPrimes)
		{
			if (n == p)
				return true;

			if (n % p == 0)
				return false;
		}

		if (rounds < 1)
			throw new ArgumentOutOfRangeException(nameof(rounds));

		// Write n - 1 as d * 2^s, where d is odd.
		BigInteger d = n - 1;
		int s = 0;

		while (d.IsEven)
		{
			d >>= 1;
			s++;
		}

		// Miller-Rabin rounds.
		for (int i = 0; i < rounds; i++)
		{
			// Choose random a in [2, n - 2].
			BigInteger a = RandomBelow(n - 3) + 2;

			BigInteger x = BigInteger.ModPow(a, d, n);

			if (x == 1 || x == n - 1)
				continue;

			bool probablyPrime = false;

			for (int r = 1; r < s; r++)
			{
				x = BigInteger.ModPow(x, 2, n);

				if (x == n - 1)
				{
					probablyPrime = true;
					break;
				}

				if (x == 1)
					return false;
			}

			if (!probablyPrime)
				return false;
		}

		return true;
	}

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

