//-----------------------------------------------------------------------------
// Filename: UdpReceiver.cs
//
// Description: A UDP socket manager that encapsulates the common logic for managing UDP sockets.
// Original use case for managing RTP communications..
//
// Author(s):
// Aaron Clauson (aaron@sipsorcery.com)
// 
// History:
// 14 Sep 2025	Aaron Clauson	Refactored from RTPChannel class.
//
// License: 
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Extensions.Logging;
using SIPSorcery.Sys;

namespace SIPSorcery.Net;

public delegate void PacketReceivedDelegate(UdpReceiver receiver, int localPort, IPEndPoint remoteEndPoint, ReadOnlySpan<byte> packet);

/// <summary>
/// A basic UDP socket manager. The RTP channel may need both an RTP and Control socket. This class encapsulates
/// the common logic for UDP socket management.
/// </summary>
/// <remarks>
/// .NET Framework Socket source:
/// https://referencesource.microsoft.com/#system/net/system/net/Sockets/Socket.cs
/// .NET Core Socket source:
/// https://github.com/dotnet/runtime/blob/master/src/libraries/System.Net.Sockets/src/System/Net/Sockets/Socket.cs
/// Mono Socket source:
/// https://github.com/mono/mono/blob/master/mcs/class/System/System.Net.Sockets/Socket.cs
/// </remarks>
public class UdpReceiver
{
    /// <summary>
    /// MTU is 1452 bytes so this should be heaps [AC 03 Nov 2024: turns out it's not when considering UDP fragmentation can
    /// result in a max UDP payload of 65535 - 8 (header) = 65527 bytes].
    /// An issue was reported with a real World WeBRTC implementation producing UDP packet sizes of 2144 byes #1045. Consequently
    /// updated from 2048 to 3000.
    /// </summary>
    protected const int RECEIVE_BUFFER_SIZE = 3000;

    protected static readonly ILogger logger = LogFactory.CreateLogger<UdpReceiver>();

    protected readonly Socket m_socket;
    protected byte[] m_recvBuffer;
    protected bool m_isClosed;
    protected bool m_isRunningReceive;
    protected IPEndPoint m_localEndPoint;
    protected AddressFamily m_addressFamily;
    protected readonly AsyncCallback endReceiveFrom;

    protected static readonly IPEndPoint IPv4AnyEndPoint = new(IPAddress.Any, 0);
    protected static readonly IPEndPoint IPv6AnyEndPoint = new(IPAddress.IPv6Any, 0);

    public virtual bool IsClosed
    {
        get
        {
            return m_isClosed;
        }
        protected set
        {
            if (m_isClosed == value)
            {
                return;
            }
            m_isClosed = value;
        }
    }

    public virtual bool IsRunningReceive
    {
        get
        {
            return m_isRunningReceive;
        }
        protected set
        {
            if (m_isRunningReceive == value)
            {
                return;
            }
            m_isRunningReceive = value;
        }
    }

    /// <summary>
    /// Fires when a new packet has been received on the UDP socket.
    /// </summary>
    public event PacketReceivedDelegate OnPacketReceived;

    /// <summary>
    /// Fires when there is an error attempting to receive on the UDP socket.
    /// </summary>
    public event Action<string> OnClosed;

    public UdpReceiver(Socket socket, int mtu = RECEIVE_BUFFER_SIZE)
    {
        m_socket = socket;
        m_localEndPoint = m_socket.LocalEndPoint as IPEndPoint;
        m_recvBuffer = new byte[mtu];
        m_addressFamily = m_socket.LocalEndPoint.AddressFamily;
        endReceiveFrom = EndReceiveFrom;
    }

    /// <summary>
    /// Starts the receive. This method returns immediately. An event will be fired in the corresponding "End" event to
    /// return any data received.
    /// </summary>
    public virtual void BeginReceiveFrom()
    {
        //Prevent call BeginReceiveFrom if it is already running
        if (m_isClosed && m_isRunningReceive)
        {
            m_isRunningReceive = false;
        }
        if (m_isRunningReceive || m_isClosed)
        {
            return;
        }

        try
        {
            m_isRunningReceive = true;
            EndPoint recvEndPoint = m_addressFamily == AddressFamily.InterNetwork ? IPv4AnyEndPoint : IPv6AnyEndPoint;
#if NET8_0_OR_GREATER
            var receive = m_socket.ReceiveFromAsync(m_recvBuffer.AsMemory(), SocketFlags.None, recvEndPoint);
            if (receive.IsCompleted)
            {
                ThreadPool.UnsafeQueueUserWorkItem(static state =>
                {
                    var (receiver, completedReceive) = ((UdpReceiver, ValueTaskSource))state;
                    completedReceive.Complete(receiver);
                }, (this, new ValueTaskSource(receive)));
            }
            else
            {
                receive.AsTask().ContinueWith(t =>
                {
                    try
                    {
                        EndReceiveFrom(t.GetAwaiter().GetResult());
                    }
                    catch (Exception excp)
                    {
                        EndReceiveFrom(excp);
                        RestartReceiveLoop();
                    }
                }).Forget(logger);
            }
#else
            m_socket.BeginReceiveFrom(m_recvBuffer, 0, m_recvBuffer.Length, SocketFlags.None, ref recvEndPoint, endReceiveFrom, null);
#endif
        }
        catch (ObjectDisposedException)
        {
            // Thrown when socket is closed. Can be safely ignored.
            m_isRunningReceive = false;
        }
        catch (SocketException sockExcp)
        {
            // A SocketException here (including ConnectionReset / ICMP port unreachable) typically
            // reflects a transient condition on the remote side — for example the remote RTP socket
            // has not been opened yet, or an endpoint change during hold/transfer left a stale route.
            // The local socket remains usable, so we log and allow the next BeginReceiveFrom attempt
            // from the EndReceiveFrom finally block rather than tearing down the receive loop.
            m_isRunningReceive = false;
            logger.LogWarning("Socket error {SocketErrorCode} in UdpReceiver.BeginReceiveFrom. {Message}", sockExcp.SocketErrorCode, sockExcp.Message);
        }
        catch (Exception excp)
        {
            m_isRunningReceive = false;
            // From https://github.com/dotnet/corefx/blob/e99ec129cfd594d53f4390bf97d1d736cff6f860/src/System.Net.Sockets/src/System/Net/Sockets/Socket.cs#L3262
            // the BeginReceiveFrom will only throw if there is an problem with the arguments or the socket has been disposed of. In that
            // case the socket can be considered to be unusable and there's no point trying another receive.
            logger.LogError(excp, "Exception UdpReceiver.BeginReceiveFrom. {ErrorMessage}", excp.Message);
            Close(excp.Message);
        }
    }

#if NET8_0_OR_GREATER
    private readonly struct ValueTaskSource
    {
        private readonly System.Threading.Tasks.ValueTask<SocketReceiveFromResult> _receive;

        public ValueTaskSource(System.Threading.Tasks.ValueTask<SocketReceiveFromResult> receive)
        {
            _receive = receive;
        }

        public void Complete(UdpReceiver receiver)
        {
            try
            {
                receiver.EndReceiveFrom(_receive.GetAwaiter().GetResult());
            }
            catch (Exception excp)
            {
                receiver.EndReceiveFrom(excp);
                receiver.RestartReceiveLoop();
            }
        }
    }
#endif

#if NET8_0_OR_GREATER
    protected virtual void EndReceiveFrom(SocketReceiveFromResult result)
    {
        try
        {
            OnBytesRead(result.RemoteEndPoint, result.ReceivedBytes);
            Drain();
        }
        catch (Exception excp)
        {
            EndReceiveFrom(excp);
        }
        finally
        {
            RestartReceiveLoop();
        }
    }
#endif

    /// <summary>
    /// Handler for end of the begin receive call.
    /// </summary>
    /// <param name="ar">Contains the results of the receive.</param>
    protected virtual void EndReceiveFrom(IAsyncResult ar)
    {
        try
        {
            EndPoint remoteEP = m_addressFamily == AddressFamily.InterNetwork ? IPv4AnyEndPoint : IPv6AnyEndPoint;
            // When socket is closed the object will be disposed of in the middle of a receive.
            if (!m_isClosed)
            {
                int bytesRead = m_socket.EndReceiveFrom(ar, ref remoteEP);

                OnBytesRead(remoteEP, bytesRead);
            }
            else
            {
                m_socket.EndReceiveFromClosed(ar, ref remoteEP);
            }

            Drain();
        }
        catch (Exception excp)
        {
            EndReceiveFrom(excp);
        }
        finally
        {
            RestartReceiveLoop();
        }
    }

    protected virtual void EndReceiveFrom(Exception excp)
    {
        switch (excp)
        {
            case SocketException resetSockExcp when resetSockExcp.SocketErrorCode == SocketError.ConnectionReset:
                // ConnectionReset is raised when the OS receives an ICMP "port unreachable" message.
                // The local UDP socket remains usable; keep the receive loop alive.
                logger.LogWarning("SocketException UdpReceiver.EndReceiveFrom ({SocketErrorCode}). {ErrorMessage}", resetSockExcp.SocketErrorCode, resetSockExcp.Message);
                break;
            case SocketException { SocketErrorCode: SocketError.OperationAborted } when m_isClosed:
            case ObjectDisposedException:
                // Thrown when socket is closed. Can be safely ignored.
                break;
            case SocketException sockExcp:
                logger.LogWarning("SocketException UdpReceiver.EndReceiveFrom ({SocketErrorCode}). {ErrorMessage}", sockExcp.SocketErrorCode, sockExcp.Message);
                break;
            case AggregateException aggregateExcp:
                foreach (var innerExcp in aggregateExcp.InnerExceptions)
                {
                    EndReceiveFrom(innerExcp);
                }
                break;
            default:
                logger.LogError(excp, "Exception UdpReceiver.EndReceiveFrom. {ErrorMessage}", excp.Message);
                Close(excp.Message);
                break;
        }
    }

    protected void OnBytesRead(EndPoint remoteEP, int bytesRead)
    {
        if (bytesRead > 0)
        {
            // During experiments IPPacketInformation wasn't getting set on Linux. Without it the local IP address
            // cannot be determined when a listener was bound to IPAddress.Any (or IPv6 equivalent). If the caller
            // is relying on getting the local IP address on Linux then something may fail.
            //if (packetInfo != null && packetInfo.Address != null)
            //{
            //    localEndPoint = new IPEndPoint(packetInfo.Address, localEndPoint.Port);
            //}

            CallOnPacketReceivedCallback(m_localEndPoint.Port, remoteEP as IPEndPoint, m_recvBuffer.AsSpan(0, bytesRead));
        }
    }

    protected void Drain()
    {
        // If there is still data available it should be read now. This is more efficient than calling
        // BeginReceiveFrom which will incur the overhead of creating the callback and then immediately firing it.
        // It also avoids the situation where if the application cannot keep up with the network then BeginReceiveFrom
        // will be called synchronously (if data is available it calls the callback method immediately) which can
        // create a very nasty stack.
        while (!m_isClosed && m_socket.Available > 0)
        {
            EndPoint remoteEP = m_addressFamily == AddressFamily.InterNetwork ? IPv4AnyEndPoint : IPv6AnyEndPoint;
            int bytesReadSync = m_socket.ReceiveFrom(m_recvBuffer, 0, m_recvBuffer.Length, SocketFlags.None, ref remoteEP);

            if (bytesReadSync > 0)
            {
                CallOnPacketReceivedCallback(m_localEndPoint.Port, remoteEP as IPEndPoint, m_recvBuffer.AsSpan(0, bytesReadSync));
            }
            else
            {
                break;
            }
        }
    }

    protected void RestartReceiveLoop()
    {
        m_isRunningReceive = false;
        if (!m_isClosed)
        {
            BeginReceiveFrom();
        }
    }

    /// <summary>
    /// Closes the socket and stops any new receives from being initiated.
    /// </summary>
    public virtual void Close(string reason)
    {
        if (!m_isClosed)
        {
            m_isClosed = true;
            m_socket?.Close();

            OnClosed?.Invoke(reason);
        }
    }

    protected virtual void CallOnPacketReceivedCallback(int localPort, IPEndPoint remoteEndPoint, ReadOnlySpan<byte> packet)
    {
        OnPacketReceived?.Invoke(this, localPort, remoteEndPoint, packet);
    }
}
