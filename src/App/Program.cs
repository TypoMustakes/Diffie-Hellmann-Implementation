using System.Diagnostics;
using System.Numerics;
using System.Text;
using Logic;

namespace App;

class Program
{
    public static void Main()
    {
        AesCrypto crypto = new();
        DhKeyExchange dh = new DhKeyExchange(new ParameterGenerator());

        // Generate private and public keys for Alice and Bob
        BigInteger alicePrivateKey = dh.GeneratePrivateKey();
        BigInteger bobPrivateKey = dh.GeneratePrivateKey();
			
        BigInteger alicePublicKey = dh.GeneratePublicKey(alicePrivateKey);
        BigInteger bobPublicKey = dh.GeneratePublicKey(bobPrivateKey);
			
        // Exchange public keys and derive shared secrets
        BigInteger aliceSharedSecret = dh.DeriveSharedSecret(alicePrivateKey, bobPublicKey);
        BigInteger bobSharedSecret = dh.DeriveSharedSecret(bobPrivateKey, alicePublicKey);
			
        Console.WriteLine("Alice's Shared Secret: " + aliceSharedSecret.ToString());
        Console.WriteLine("Bob's Shared Secret: " + bobSharedSecret.ToString());

        // Ensure both sides have the same shared secret
        Debug.Assert(aliceSharedSecret == bobSharedSecret);
			
        // Example usage of AES encryption with the derived shared secret as key and IV (for simplicity)
        string original = "Here is some data to encrypt";
        byte[] plainText = Encoding.UTF8.GetBytes(original);
        byte[] key = aliceSharedSecret.ToByteArray();
        byte[] iv = new byte[2]; // Use a random IV for AES
			
        byte[] encrypted = crypto.Encrypt(plainText, key, iv);
			
        string decrypted = Encoding.UTF8.GetString(crypto.Decrypt(encrypted, key, iv));
			
        Console.WriteLine("Original:   {0}", original);
        Console.WriteLine("Encrypted:  {0}", Convert.ToBase64String(encrypted));
        Console.WriteLine("Decrypted:  {0}", decrypted);
    }
}
