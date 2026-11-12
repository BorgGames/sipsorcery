//-----------------------------------------------------------------------------
// Filename: DtlsSrtpTransport.cs
//
// Description: This class represents the DTLS SRTP transport connection to use 
// as Client or Server.
//
// Author(s):
// Rafael Soares (raf.csoares@kyubinteractive.com)
//
// History:
// 01 Jul 2020	Rafael Soares   Created.
// 02 Jul 2020  Aaron Clauson   Switched underlying transport from socket to
//                              piped memory stream.
// 30 Dec 2025  Lukas Volf      New DTLS/SRTP impl
// 14 Oct 2026  Andy Ventura    Receive waits on the queue instead of polling it.
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Threading;
using Org.BouncyCastle.Tls;
using SIPSorcery.Net.SharpSRTP.DTLS;
using SIPSorcery.Net.SharpSRTP.DTLSSRTP;
using SIPSorcery.Net.SharpSRTP.SRTP;

namespace SIPSorcery.Net
{
    public delegate void OnDataReadyEvent(ReadOnlySpan<byte> data);
    public delegate void OnDtlsAlertEvent(TlsAlertLevelsEnum alertLevel, TlsAlertTypesEnum alertType, string alertDescription);

    public class DtlsSrtpTransport : DatagramTransport
    {
        public const int MAXIMUM_MTU = 1472; // 1500 - 20 (IP) - 8 (UDP)
        public const int DTLS_RETRANSMISSION_CODE = -1;

        private IDtlsSrtpPeer _connection;

        private readonly BlockingCollection<ArraySegment<byte>> _data = new BlockingCollection<ArraySegment<byte>>(new ConcurrentQueue<ArraySegment<byte>>());

        /// <summary>
        /// Cancelled if the transport is closed before the DTLS handshake has completed. A handshake
        /// waiting on <see cref="Receive(byte[], int, int, int)"/> for the remote peer's next flight is
        /// then aborted instead of waiting out the handshake timeout.
        /// </summary>
        private readonly CancellationTokenSource _handshakeCancellation = new CancellationTokenSource();

        private volatile bool _isHandshakeComplete;
        private Certificate _peerCertificate;

        public DatagramTransport Transport { get; internal set; }
        public bool IsClient { get { return _connection is DtlsSrtpClient; } }
        internal SrtpKeys Keys { get; private set; }

        internal ThreadSafeSrtpSessionContext Context { get; private set; }

        public int TimeoutMilliseconds { get { return _connection.TimeoutMilliseconds; } set { _connection.TimeoutMilliseconds = value; } }

        public event OnDataReadyEvent OnDataReady;

        public event OnDtlsAlertEvent OnAlert;

        internal DtlsSrtpTransport(IDtlsSrtpPeer connection)
        {
            this._connection = connection;
            this._connection.OnSessionStarted += DtlsSrtpTransport_OnSessionStarted;
            this._connection.OnAlert += DtlsSrtpTransport_OnAlert;
        }

        private void DtlsSrtpTransport_OnSessionStarted(object sender, DtlsSessionStartedEventArgs e)
        {
            this._peerCertificate = e.PeerCertificate;
            this.Context = new ThreadSafeSrtpSessionContext(e.Context);
        }

        private void DtlsSrtpTransport_OnAlert(object sender, DtlsAlertEventArgs args)
        {
            OnAlert?.Invoke(args.Level, args.AlertType, args.Description);
        }

        public bool DoHandshake(out string handshakeError)
        {
            DtlsTransport transport = _connection.DoHandshake(out handshakeError, this, null);
            Transport = transport;
            _isHandshakeComplete = transport != null;
            return string.IsNullOrEmpty(handshakeError);
        }

        public bool IsHandshakeComplete()
        {
            return Transport != null;
        }

        public int ProtectRTP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.UnprotectRtp(payload, length, out outputBufferLength);
        }        

        public int ProtectRTCP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtcp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTCP(Span<byte> payload, int length, out int outputBufferLength)
        {
            return Context.UnprotectRtcp(payload, length, out outputBufferLength);
        }

        public Certificate GetRemoteCertificate()
        {
            return _peerCertificate;
        }

        public int GetReceiveLimit() => MAXIMUM_MTU;

        public int GetSendLimit() => MAXIMUM_MTU;

        public void WriteToRecvStream(ReadOnlySpan<byte> buffer)
        {
            byte[] chunk = ArrayPool<byte>.Shared.Rent(buffer.Length);
            buffer.CopyTo(chunk);
            _data.Add(new ArraySegment<byte>(chunk, 0, buffer.Length));
        }

        public void Close()
        {
            if (!_isHandshakeComplete)
            {
                _handshakeCancellation.Cancel();
            }

            var transport = Transport;
            if (transport != null)
            {
                Transport = null;
                transport.Close();
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            return Receive(buf.AsSpan(off, len), waitMillis);
        }

        public int Receive(Span<byte> buffer, int waitMillis)
        {
            // As per the BouncyCastle DatagramReceiver contract a wait of zero is an infinite timeout.
            int timeout = waitMillis == 0 ? Timeout.Infinite : Math.Max(waitMillis, 0);

            ArraySegment<byte> data;

            try
            {
                if (!_data.TryTake(out data, timeout, _handshakeCancellation.Token))
                {
                    return DTLS_RETRANSMISSION_CODE;
                }
            }
            catch (OperationCanceledException)
            {
                // Closed before the handshake completed, no further flights will be delivered.
                throw new TlsFatalAlert(AlertDescription.user_canceled);
            }

            try
            {
                data.AsSpan().CopyTo(buffer);
                return data.Count;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(data.Array);
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            Send(buf.AsSpan(off, len));
        }

        public void Send(ReadOnlySpan<byte> buffer)
        {
            OnDataReady?.Invoke(buffer);
        }
    }
}
