using System.Numerics;

namespace Logic;

public interface IParameterGenerator
{

	public BigInteger[] GenerateParameters(int bitLength);
	public BigInteger RandomBelow(BigInteger max);
}
