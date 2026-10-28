using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Org.BouncyCastle.Tls;
using SIPSorcery.Sys;
using Xunit;

namespace SIPSorcery.Net.UnitTests;

public class RTCSctpTransportUnitTest
{
    [Theory]
    [InlineData(SctpChunkType.DATA)]
    [InlineData(SctpChunkType.SACK)]
    [InlineData(SctpChunkType.INIT)]
    [InlineData(SctpChunkType.ERROR)]
    public async Task ReceiveLoopSurvivesMalformedChunk(SctpChunkType malformedType)
    {
        const ushort SctpPort = 5000;
        using var datagrams = new QueuedDatagramTransport();
        var receiver = new RTCSctpTransport(SctpPort, SctpPort, 0);
        uint verificationTag = receiver.RTCSctpAssociation.VerificationTag;
        try
        {
            int causeLength = malformedType == SctpChunkType.ERROR ? SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH : 0;
            byte[] malformed = new byte[SctpHeader.SCTP_HEADER_LENGTH + SctpChunk.SCTP_CHUNK_HEADER_LENGTH + causeLength];
            new SctpHeader { SourcePort = SctpPort, DestinationPort = SctpPort, VerificationTag = verificationTag }.WriteToBuffer(malformed, 0);
            malformed[SctpHeader.SCTP_HEADER_LENGTH] = (byte)malformedType;
            BinaryPrimitives.WriteUInt16BigEndian(malformed.AsSpan(SctpHeader.SCTP_HEADER_LENGTH + sizeof(byte) + sizeof(byte)),
                (ushort)(SctpChunk.SCTP_CHUNK_HEADER_LENGTH + causeLength));
            NetConvert.ToBuffer(NetConvert.EndianFlip(CRC32C.Calculate(malformed, 0, malformed.Length)),
                malformed, SctpPacket.CHECKSUM_BUFFER_POSITION);
            Assert.True(SctpPacket.VerifyChecksum(malformed));
            Assert.Throws<FormatException>(() => { SctpPacketView.Parse(malformed); });

            var heartbeat = new SctpPacket(SctpPort, SctpPort, verificationTag);
            heartbeat.AddChunk(new SctpChunk(SctpChunkType.HEARTBEAT));
            datagrams.Input.Add(malformed);
            datagrams.Input.Add(heartbeat.GetBytes());
            receiver.Start(datagrams, true);

            Task<byte[]> response = datagrams.Sent.Task;
            Assert.Same(response, await Task.WhenAny(response, Task.Delay(2000)));
            Assert.Equal(SctpChunkType.HEARTBEAT_ACK, SctpPacketView.Parse(await response).GetChunk(SctpChunkType.HEARTBEAT_ACK).Type);
        }
        finally
        {
            receiver.Close();
        }
    }

    private sealed class QueuedDatagramTransport : DatagramTransport, IDisposable
    {
        public BlockingCollection<byte[]> Input { get; } = new();
        public TaskCompletionSource<byte[]> Sent { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int GetReceiveLimit() => RTCPeerSctpAssociation.DEFAULT_DTLS_MTU;
        public int GetSendLimit() => RTCPeerSctpAssociation.DEFAULT_DTLS_MTU;
        public int Receive(byte[] buffer, int offset, int length, int waitMillis)
            => Receive(buffer.AsSpan(offset, length), waitMillis);
        public int Receive(Span<byte> buffer, int waitMillis)
        {
            if (!Input.TryTake(out var packet, waitMillis))
            {
                return DtlsSrtpTransport.DTLS_RETRANSMISSION_CODE;
            }
            packet.AsSpan().CopyTo(buffer);
            return packet.Length;
        }
        public void Send(byte[] buffer, int offset, int length) => Send(buffer.AsSpan(offset, length));
        public void Send(ReadOnlySpan<byte> buffer) => Sent.TrySetResult(buffer.ToArray());
        public void Close() => Input.CompleteAdding();
        public void Dispose() => Close();
    }
}
