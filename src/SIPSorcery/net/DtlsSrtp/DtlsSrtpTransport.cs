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
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Concurrent;
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

        private BlockingCollection<ArraySegment<byte>> _data = new BlockingCollection<ArraySegment<byte>>(new ConcurrentQueue<ArraySegment<byte>>());
        private ArraySegment<byte> _partialChunk = default;
        private int _partialChunkOffset;
        private bool _isClosed;
        private Certificate _peerCertificate;

        public DatagramTransport Transport { get; internal set; }
        public bool IsClient { get { return _connection is DtlsSrtpClient; } }
        public SrtpKeys Keys { get; private set; }

        public SrtpSessionContext Context { get; private set; }

        public int TimeoutMilliseconds { get { return _connection.TimeoutMilliseconds; } set { _connection.TimeoutMilliseconds = value; } }

        public event OnDataReadyEvent OnDataReady;

        public event OnDtlsAlertEvent OnAlert;

        public DtlsSrtpTransport(IDtlsSrtpPeer connection)
        {
            this._connection = connection;
            this._connection.OnSessionStarted += DtlsSrtpTransport_OnSessionStarted;
            this._connection.OnAlert += DtlsSrtpTransport_OnAlert;
        }

        private void DtlsSrtpTransport_OnSessionStarted(object sender, DtlsSessionStartedEventArgs e)
        {
            this._peerCertificate = e.PeerCertificate;
            this.Context = e.Context;
        }

        private void DtlsSrtpTransport_OnAlert(object sender, DtlsAlertEventArgs args)
        {
            OnAlert?.Invoke(args.Level, args.AlertType, args.Description);
        }

        public bool DoHandshake(out string handshakeError)
        {
            DtlsTransport transport = _connection.DoHandshake(out handshakeError, this, null);
            Transport = transport;
            return string.IsNullOrEmpty(handshakeError);
        }

        public bool IsHandshakeComplete()
        {
            return Transport != null;
        }

        public int ProtectRTP(byte[] payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTP(byte[] payload, int length, out int outputBufferLength)
        {
            return Context.UnprotectRtp(payload, length, out outputBufferLength);
        }        

        public int ProtectRTCP(byte[] payload, int length, out int outputBufferLength)
        {
            return Context.ProtectRtcp(payload, length, out outputBufferLength);
        }

        public int UnprotectRTCP(byte[] payload, int length, out int outputBufferLength)
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
            if (_isClosed)
            {
                return;
            }

            byte[] chunk = ArrayPool<byte>.Shared.Rent(buffer.Length);
            buffer.CopyTo(chunk);
            try
            {
                _data.Add(new ArraySegment<byte>(chunk, 0, buffer.Length));
            }
            catch (InvalidOperationException) when (_isClosed)
            {
                ArrayPool<byte>.Shared.Return(chunk);
            }
        }

        public void Close()
        {
            if (_isClosed)
            {
                return;
            }

            _isClosed = true;

            var transport = Transport;
            if (transport != null)
            {
                Transport = null;
                transport.Close();
            }

            _data.CompleteAdding();
            while (_data.TryTake(out var chunk))
            {
                ArrayPool<byte>.Shared.Return(chunk.Array);
            }
            if (_partialChunk.Array != null)
            {
                ArrayPool<byte>.Shared.Return(_partialChunk.Array);
                _partialChunk = default;
                _partialChunkOffset = 0;
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            return Read(buf.AsSpan(off, len), waitMillis);
        }

        private int Read(Span<byte> buffer, int waitMillis)
        {
            if (_isClosed)
            {
                return DTLS_RETRANSMISSION_CODE;
            }

            try
            {
                if (_partialChunk.Array != null)
                {
                    int bytesToCopy = Math.Min(buffer.Length, _partialChunk.Count - _partialChunkOffset);
                    _partialChunk.AsSpan(_partialChunkOffset, bytesToCopy).CopyTo(buffer);
                    _partialChunkOffset += bytesToCopy;

                    if (_partialChunkOffset == _partialChunk.Count)
                    {
                        ArrayPool<byte>.Shared.Return(_partialChunk.Array);
                        _partialChunk = default;
                        _partialChunkOffset = 0;
                    }

                    return bytesToCopy;
                }

                if (_data.TryTake(out var chunk, waitMillis))
                {
                    int bytesToCopy = Math.Min(buffer.Length, chunk.Count);
                    chunk.AsSpan(0, bytesToCopy).CopyTo(buffer);

                    if (bytesToCopy < chunk.Count)
                    {
                        _partialChunk = chunk;
                        _partialChunkOffset = bytesToCopy;
                    }
                    else
                    {
                        ArrayPool<byte>.Shared.Return(chunk.Array);
                    }

                    return bytesToCopy;
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (InvalidOperationException) when (_isClosed)
            {
            }

            return DTLS_RETRANSMISSION_CODE;
        }

        public void Send(byte[] buf, int off, int len)
        {
            OnDataReady?.Invoke(buf.AsSpan(off, len));
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Receive(Span<byte> buffer, int waitMillis)
        {
            return Read(buffer, waitMillis);
        }

        public void Send(ReadOnlySpan<byte> buffer)
        {
            OnDataReady?.Invoke(buffer);
        }
#endif
    }
}
