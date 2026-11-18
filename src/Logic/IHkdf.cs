using System.Numerics;

namespace Logic;

public interface IHkdf
{
	public byte[] DeriveKey(BigInteger sharedSecret,int outputLength = 32);
}
