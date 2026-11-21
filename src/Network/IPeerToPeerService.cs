using System.Net;

namespace Network;

public interface IPeerToPeerService
{
	public void Start();
	public Task SendAsync(byte[] data);
	public event Action<byte[]>? DataReceived;
	public IPAddress? PeerAddress { get; }
}
