using System.Net;

namespace Network;

public interface IPeerToPeerService
{
	public void Start();
	public Task SendAsync(byte[] data);
	public event Action<byte[]>? DataReceived;
	public IPAddress? PeerAddress { get; }
	public PeerState State { get; }
	public event Action? PeerLost;
	public event Action? PeerRestored;
	public event Action<PeerState>? StateChanged;
}
