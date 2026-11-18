using System.Numerics;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace Logic;

public class ParameterGenerator : IParameterGenerator
{
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

	// Generate large prime and primitive root
	public BigInteger[] GenerateParameters(int bitLength)
	{
		BigInteger p = new();
		BigInteger g = new();
		bool escape = true;

		do
		{
			escape = true;
			try
			{
				p = GeneratePrime(bitLength);
				g = FindPrimitiveRoot(p);
			} catch (NoPrimeFactorException)
			{
				escape = false;
			}
		} while (!escape);

		return [p, g];
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

	public BigInteger RandomBelow(BigInteger max)
	{
		if (max <= 0)
			throw new ArgumentOutOfRangeException(nameof(max));

		byte[] bytes = max.ToByteArray(
			isUnsigned: true,
			isBigEndian: false);

		BigInteger result;

		do
		{
			RandomNumberGenerator.Fill(bytes);
			result = new BigInteger(
				bytes,
				isUnsigned: true,
				isBigEndian: false);
		}
		while (result >= max);

		return result;
	}
}
