using System.Net;
using System.Net.Sockets;

namespace Network;

public sealed class PeerToPeerService : IDisposable, IPeerToPeerService
{
	private const int DiscoveryPort = 50000;
	private const int TcpPort = 50001;

	private UdpClient? _udpListener;
	private UdpClient? _udpBroadcaster;
	private TcpListener? _tcpListener;

	private CancellationTokenSource? _cts;

	// The single discovered peer.
	private IPAddress? _peerAddress;
	public IPAddress? PeerAddress => _peerAddress;

	public event Action<byte[]>? DataReceived;

	public void Start()
	{
		if (_cts != null)
		{
			throw new InvalidOperationException("Service is already running.");
		}

		_cts = new CancellationTokenSource();

		// Start UDP discovery listener.
		_udpListener = new UdpClient(DiscoveryPort);

		// Start TCP listener.
		_tcpListener = new TcpListener(
			IPAddress.Any,
			TcpPort);

		_tcpListener.Start();

		// We don't need to store the tasks, we can discard them
		_ = ListenForPeerAsync(_cts.Token);
		_ = ListenForTcpConnectionsAsync(_cts.Token);
	}

	private async Task ListenForPeerAsync(CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				UdpReceiveResult result =
					await _udpListener!.ReceiveAsync(
						cancellationToken);

				// Only store the first discovered peer. This is fine for demonstration purposes.
				_peerAddress ??= result.RemoteEndPoint.Address;
			}
		}
		catch (OperationCanceledException) { }
		catch (ObjectDisposedException) { }
	}

	public async Task BroadcastAsync(byte[] data)
	{
		_udpBroadcaster ??= new UdpClient();

		_udpBroadcaster.EnableBroadcast = true;

		await _udpBroadcaster.SendAsync(
			data,
			new IPEndPoint(
				IPAddress.Broadcast,
				DiscoveryPort));
	}

	private async Task ListenForTcpConnectionsAsync(CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				TcpClient client =
					await _tcpListener!.AcceptTcpClientAsync(
						cancellationToken);

				_ = HandleTcpClientAsync(
					client,
					cancellationToken);
			}
		}
		catch (OperationCanceledException) { }
		catch (ObjectDisposedException) { }
	}

	private async Task HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
	{
		using (client)
		{
			try
			{
				NetworkStream stream = client.GetStream();

				byte[] lengthBuffer = new byte[4];

				await stream.ReadExactlyAsync(
					lengthBuffer,
					cancellationToken);

				int length = BitConverter.ToInt32(lengthBuffer);

				if (length < 0 || length > 10_000_000)
				{
					return;
				}

				byte[] data = new byte[length];

				await stream.ReadExactlyAsync(
					data,
					cancellationToken);

				DataReceived?.Invoke(data);
			}
			catch (OperationCanceledException) { }
			catch (System.IO.IOException) { }
		}
	}

	public async Task SendAsync(byte[] data)
	{
		if (_peerAddress == null)
			throw new InvalidOperationException(
				"No peer has been discovered.");

		using TcpClient client = new TcpClient();

		await client.ConnectAsync(
			_peerAddress,
			TcpPort);

		NetworkStream stream = client.GetStream();

		byte[] lengthBuffer =
			BitConverter.GetBytes(data.Length);

		await stream.WriteAsync(lengthBuffer);
		await stream.WriteAsync(data);
	}

	public void Dispose()
	{
		_cts?.Cancel();

		_udpListener?.Dispose();
		_udpBroadcaster?.Dispose();

		_tcpListener?.Stop();

		_cts?.Dispose();

		_cts = null;
		_udpListener = null;
		_udpBroadcaster = null;
		_tcpListener = null;
	}
}
