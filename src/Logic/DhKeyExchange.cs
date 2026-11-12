using System.Numerics;

namespace Logic;

public class DhKeyExchange : IDhKeyExchange
{
	private readonly IParameterGenerator _parameterGenerator;
	
	public BigInteger P { get; private set; }
	public BigInteger G { get; private set; }

	public DhKeyExchange(IParameterGenerator parameterGenerator)
	{
		_parameterGenerator = parameterGenerator;
		GenerateParameters();
	}

	//For demonstration purposes, key length is decreased to 32 bits
	private void GenerateParameters(int bitLength = 32)
	{
		BigInteger[] parameters = _parameterGenerator.GenerateParameters(bitLength);
		P = parameters[0];
		G = parameters[1];
	}

	// Generate a private key (random integer in [2, p-2])
	public BigInteger GeneratePrivateKey()
	{
		return P <= 3 ? throw new ArgumentOutOfRangeException(nameof(P)) : _parameterGenerator.RandomBelow(P - 3) + 2;
	}
	
	// Generate a public key based on the private key and the primitive root
	public BigInteger GeneratePublicKey(BigInteger privateKey)
	{
		return BigInteger.ModPow(G, privateKey, P);
	}
	
	// Exchange keys to derive a shared secret
	public BigInteger DeriveSharedSecret(BigInteger privateKey, BigInteger publicKey)
	{
		return BigInteger.ModPow(publicKey, privateKey, P);
	}
}

