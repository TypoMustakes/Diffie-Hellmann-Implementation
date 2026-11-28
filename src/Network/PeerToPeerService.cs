using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Network;

public sealed class PeerToPeerService :
	IDisposable,
	IAsyncDisposable,
	IPeerToPeerService
{
	private const int DiscoveryPort = 50000;
	private const int TcpPort = 50001;
	
	private const int PingIntervalMs = 2000;
	private const int PeerTimeoutMs = 8000;
	
	private const int MaxMessageSize = 10_000_000;
	
	private const byte DiscoveryMessage = 0x01;
	private const byte PingMessage = 0x02;
	private const byte PongMessage = 0x03;
	
	private const int PingPacketLength = 9;
	
	private readonly object _sync = new();
	
	private UdpClient? _udpListener;
	private UdpClient? _udpBroadcaster;
	private TcpListener? _tcpListener;
	
	private CancellationTokenSource? _cts;
	
	private Task? _udpTask;
	private Task? _tcpTask;
	private Task? _heartbeatTask;
	
	private IPAddress? _peerAddress;
	private HashSet<IPAddress> _localAddresses = new();
	
	private PeerState _state = PeerState.Disconnected;
	
	private bool _peerAvailable;
	private bool _hasBeenAvailable;
	
	private long _lastPeerResponse;
	private long _nextPingSequence;
	
	// Tracks recently sent pings and their timestamps.
	private readonly Dictionary<long, long> _pendingPings = new();
	
	public IPAddress? PeerAddress
	{
		get
		{
			lock (_sync)
				return _peerAddress;
		}
	}
	
	public PeerState State
	{
		get
		{
			lock (_sync)
				return _state;
		}
		private set => SetState(value);
	}
	
	public event Action? PeerLost;
	public event Action? PeerRestored;
	public event Action<PeerState>? StateChanged;
	public event Action<byte[]>? DataReceived;
	
	public void Start()
	{
		if (_cts != null)
			throw new InvalidOperationException(
				"Service is already running.");
		
		_cts = new CancellationTokenSource();
		
		_localAddresses = GetLocalIPAddresses();
		
		_udpListener = new UdpClient(DiscoveryPort);
		
		_udpBroadcaster = new UdpClient();
		_udpBroadcaster.EnableBroadcast = true;
		
		_tcpListener = new TcpListener(
			IPAddress.Any,
			TcpPort);
		
		_tcpListener.Start();
		
		State = PeerState.Discovering;
		
		CancellationToken token = _cts.Token;
		
		_udpTask = ListenForPeerAsync(token);
		_tcpTask = ListenForTcpConnectionsAsync(token);
		_heartbeatTask = HeartbeatAsync(token);
	}
	
	private void SetState(PeerState state)
	{
		lock (_sync)
		{
			if (_state == state)
				return;
			
			_state = state;
		}
		StateChanged?.Invoke(state);
	}
	
	private HashSet<IPAddress> GetLocalIPAddresses()
	{
		return NetworkInterface
			.GetAllNetworkInterfaces()
			.Where(n =>
				   n.OperationalStatus == OperationalStatus.Up)
			.SelectMany(n =>
						n.GetIPProperties().UnicastAddresses)
			.Where(a =>
				   a.Address.AddressFamily ==
				   AddressFamily.InterNetwork)
			.Select(a => a.Address)
			.ToHashSet();
	}
	
	private static IPAddress NormalizeAddress(IPAddress address)
	{
		return address.IsIPv4MappedToIPv6
			? address.MapToIPv4()
			: address;
	}
	
	private async Task ListenForPeerAsync(
		CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				UdpReceiveResult result =
					await _udpListener!.ReceiveAsync(
						cancellationToken);
				
				if (result.Buffer.Length == 0)
					continue;
				
				IPAddress sender =
					NormalizeAddress(result.RemoteEndPoint.Address);
				
				// Ignore our own messages.
				if (_localAddresses.Contains(sender))
					continue;
				
				byte message = result.Buffer[0];
				
				if (message == DiscoveryMessage)
				{
					// Discovery packets must contain exactly one byte.
					if (result.Buffer.Length != 1)
						continue;
					
					AcceptPeer(sender);
					continue;
				}
				
				IPAddress? peer = PeerAddress;
				
				// Only communicate with the discovered peer.
				if (peer == null || !peer.Equals(sender))
					continue;
				
				switch (message)
				{
					case PingMessage:
						if (result.Buffer.Length != PingPacketLength)
							continue;
						
						await SendPongAsync(
							sender,
							result.Buffer.AsMemory(1, 8),
							cancellationToken);
						
						break;
						
					case PongMessage:
						if (result.Buffer.Length != PingPacketLength)
							continue;
						
						ProcessPong(result.Buffer);
						break;
				}
			}
		}
		catch (OperationCanceledException)
		{
		}
		catch (ObjectDisposedException)
		{
		}
		catch (SocketException) when (cancellationToken.IsCancellationRequested)
								{
								}
	}
	
	private void AcceptPeer(IPAddress sender)
	{
		bool accepted = false;
		
		lock (_sync)
		{
			if (_peerAddress == null)
			{
				_peerAddress = sender;
				
				_lastPeerResponse = Stopwatch.GetTimestamp();
				
				_peerAvailable = false;
				_hasBeenAvailable = false;
				
				accepted = true;
			}
		}
		
		if (accepted)
		{
			State = PeerState.PeerDiscovered;
		}
	}
	
	private async Task SendPongAsync(
		IPAddress address,
		ReadOnlyMemory<byte> sequence,
		CancellationToken cancellationToken)
	{
		byte[] packet = new byte[PingPacketLength];
		
		packet[0] = PongMessage;
		sequence.CopyTo(packet.AsMemory(1));
		
		await _udpBroadcaster!.SendAsync(
			packet,
			new IPEndPoint(address, DiscoveryPort),
			cancellationToken);
	}
	
	private void ProcessPong(byte[] packet)
	{
		long sequence =
			BinaryPrimitives.ReadInt64BigEndian(
				packet.AsSpan(1, 8));
		
		bool restored = false;
		
		lock (_sync)
		{
			// Ignore PONGs that don't match a recently sent PING.
			if (!_pendingPings.Remove(sequence))
				return;
			
			_lastPeerResponse = Stopwatch.GetTimestamp();
			
			if (!_peerAvailable)
			{
				restored = _hasBeenAvailable;
				
				_peerAvailable = true;
				_hasBeenAvailable = true;
			}
			
			// A restored peer must go through the handshake again.
		}
		
		if (restored)
		{
			State = PeerState.PeerDiscovered;
			PeerRestored?.Invoke();
		}
	}
	
	private async Task HeartbeatAsync(
		CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				await Task.Delay(
					PingIntervalMs,
					cancellationToken);
				
				IPAddress? peer = PeerAddress;
				
				if (peer == null)
					continue;
				
				await SendPingAsync(peer);
				
				CheckPeerTimeout();
			}
		}
		catch (OperationCanceledException)
		{
		}
		catch (ObjectDisposedException)
		{
		}
		catch (SocketException) when (cancellationToken.IsCancellationRequested)
								{
								}
	}
	
	private async Task SendPingAsync(IPAddress peer)
	{
		long sequence;
		byte[] packet = new byte[PingPacketLength];
		
		lock (_sync)
		{
			sequence = ++_nextPingSequence;
			
			_pendingPings[sequence] = Stopwatch.GetTimestamp();
			
			// Keep the pending-ping collection bounded.
			long now = Stopwatch.GetTimestamp();
			
			long timeoutTicks =
				(long)(PeerTimeoutMs *
					   (double)Stopwatch.Frequency / 1000);
			
			foreach (long oldSequence in _pendingPings
					 .Where(p => now - p.Value > timeoutTicks)
					 .Select(p => p.Key)
					 .ToArray())
			{
				_pendingPings.Remove(oldSequence);
			}
		}
		
		packet[0] = PingMessage;
		
		BinaryPrimitives.WriteInt64BigEndian(
			packet.AsSpan(1, 8),
			sequence);
		
		await _udpBroadcaster!.SendAsync(
			packet,
			new IPEndPoint(peer, DiscoveryPort));
	}
	
	private void CheckPeerTimeout()
	{
		bool lost = false;
		
		long now = Stopwatch.GetTimestamp();
		
		long timeoutTicks =
			(long)(PeerTimeoutMs *
				   (double)Stopwatch.Frequency / 1000);
		
		lock (_sync)
		{
			if (_peerAddress == null ||
				!_peerAvailable ||
				now - _lastPeerResponse <= timeoutTicks)
			{
				return;
			}
			
			_peerAvailable = false;
			lost = _hasBeenAvailable;
		}
		
		if (lost)
		{
			State = PeerState.Disconnected;
			PeerLost?.Invoke();
		}
	}
	
	public async Task BroadcastAsync()
	{
		if (_udpBroadcaster == null)
			throw new InvalidOperationException(
				"Service has not been started.");
		
		await _udpBroadcaster.SendAsync(
			new byte[] { DiscoveryMessage },
			new IPEndPoint(
			IPAddress.Broadcast,
			DiscoveryPort));
	}
	
	private async Task ListenForTcpConnectionsAsync(
		CancellationToken cancellationToken)
	{
		try
		{
			while (!cancellationToken.IsCancellationRequested)
			{
				TcpClient client =
					await _tcpListener!.AcceptTcpClientAsync(
						cancellationToken);
				
				IPAddress? remoteAddress =
					(client.Client.RemoteEndPoint as IPEndPoint)?.Address;
				
				IPAddress? peer = PeerAddress;
				
				if (remoteAddress == null ||
					peer == null ||
					!NormalizeAddress(remoteAddress).Equals(peer))
				{
					client.Dispose();
					continue;
				}
				
				_ = HandleTcpClientAsync(
					client,
					cancellationToken);
			}
		}
		catch (OperationCanceledException)
		{
		}
		catch (ObjectDisposedException)
		{
		}
		catch (SocketException) when (cancellationToken.IsCancellationRequested)
								{
								}
	}
	
	private async Task HandleTcpClientAsync(
		TcpClient client,
		CancellationToken cancellationToken)
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
				
				int length =
					BinaryPrimitives.ReadInt32BigEndian(
						lengthBuffer);
				
				if (length < 0 || length > MaxMessageSize)
					return;
				
				byte[] data = new byte[length];
				
				await stream.ReadExactlyAsync(
					data,
					cancellationToken);
				
				DataReceived?.Invoke(data);
			}
			catch (OperationCanceledException)
			{
			}
			catch (System.IO.IOException)
			{
			}
		}
	}
	
	public async Task SendAsync(byte[] data)
	{
		ArgumentNullException.ThrowIfNull(data);
		
		if (data.Length > MaxMessageSize)
			throw new ArgumentOutOfRangeException(
				nameof(data),
				$"Messages cannot exceed {MaxMessageSize} bytes.");
		
		IPAddress? peer = PeerAddress;
		
		if (peer == null)
			throw new InvalidOperationException(
				"No peer has been discovered.");
		
		using TcpClient client = new TcpClient();
		
		await client.ConnectAsync(peer, TcpPort);
		
		NetworkStream stream = client.GetStream();
		
		byte[] lengthBuffer = new byte[4];
		
		BinaryPrimitives.WriteInt32BigEndian(
			lengthBuffer,
			data.Length);
		
		await stream.WriteAsync(lengthBuffer);
		await stream.WriteAsync(data);
		await stream.FlushAsync();
	}
	
	private void Stop()
	{
		_cts?.Cancel();
		
		_udpListener?.Dispose();
		_udpBroadcaster?.Dispose();
		
		_tcpListener?.Stop();
		
		_udpListener = null;
		_udpBroadcaster = null;
		_tcpListener = null;
	}
	
	public void Dispose()
	{
		CancellationTokenSource? cts = _cts;
		
		if (cts == null)
			return;
		
		Stop();
		
		Task[] tasks =
			{
				_udpTask ?? Task.CompletedTask,
				_tcpTask ?? Task.CompletedTask,
				_heartbeatTask ?? Task.CompletedTask
			};
		
		// Dispose the cancellation source after the loops finish.
		_ = Task.WhenAll(tasks).ContinueWith(
			_ => cts.Dispose(),
			TaskScheduler.Default);
		
		_cts = null;
		
		GC.SuppressFinalize(this);
	}
	
	public async ValueTask DisposeAsync()
	{
		CancellationTokenSource? cts = _cts;
		
		if (cts == null)
			return;
		
		Stop();
		
		Task[] tasks =
			{
				_udpTask ?? Task.CompletedTask,
				_tcpTask ?? Task.CompletedTask,
				_heartbeatTask ?? Task.CompletedTask
			};
		
		try
		{
			await Task.WhenAll(tasks);
		}
		finally
		{
			cts.Dispose();
			_cts = null;
		}
		
		GC.SuppressFinalize(this);
	}
}

public enum PeerState
{
	Disconnected,
	Discovering,
	PeerDiscovered,
	Handshaking,
	Connected
}
