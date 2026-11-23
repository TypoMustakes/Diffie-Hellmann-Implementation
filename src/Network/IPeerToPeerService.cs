using System.Net;

namespace Network;

public interface IPeerToPeerService
{
	public void Start();
	public Task BroadcastAsync();
	public Task SendAsync(byte[] data);
	public IPAddress? PeerAddress { get; }
	public PeerState State { get; }
	public event Action? PeerLost;
	public event Action? PeerRestored;
	public event Action<byte[]>? DataReceived;
	public event Action<PeerState>? StateChanged;
}
