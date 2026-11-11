namespace Logic;

public interface IEncryptor
{
	public byte[] EncryptBytes(byte[] content, byte[] key, byte[] iv);
	public byte[] DecryptBytes(byte[] content, byte[] key, byte[] iv);
}
