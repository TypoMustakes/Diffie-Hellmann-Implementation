namespace Logic;

public interface IAesCrypto
{
	public byte[] Encrypt(byte[] content, byte[] key, byte[] iv);
	public byte[] Decrypt(byte[] content, byte[] key, byte[] iv);
}
