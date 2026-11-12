using System.Numerics;

namespace Logic;

public interface IDhKeyExchange
{
	public BigInteger GeneratePrivateKey();
	public BigInteger GeneratePublicKey(BigInteger privateKey);
	public BigInteger DeriveSharedSecret(BigInteger privateKey, BigInteger publicKey);
}
