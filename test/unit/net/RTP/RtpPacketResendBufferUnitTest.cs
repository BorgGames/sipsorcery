//-----------------------------------------------------------------------------
// Filename: RtpPacketResendBufferUnitTest.cs
//
// Description: Unit tests for the buffer of sent RTP packets kept to be sent
// again when a generic NACK (RFC 4585) reports them lost.
//
// Author(s):
// SIPSorcery contributors
//
// License:
// BSD 3-Clause "New" or "Revised" License, see included LICENSE.md file.
//-----------------------------------------------------------------------------

using System;
using Xunit;

namespace SIPSorcery.Net.UnitTests;

[Trait("Category", "unit")]
public class RtpPacketResendBufferUnitTest
{
    private static readonly TimeSpan Start = TimeSpan.FromHours(1);
    private static readonly TimeSpan MinResendInterval = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan Tick = TimeSpan.FromTicks(1);

    private static ArraySegment<byte> Packet(params byte[] bytes) => new(bytes);

    [Fact]
    public void ReturnsTheSamePacketUntilItExpires()
    {
        var buffer = new RtpPacketResendBuffer();
        var packet = new ArraySegment<byte>([1, 2, 3, 4, 5], 0, 4);
        buffer.Add(7, packet, 3, Start);

        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(7, Start + RtpPacketResendBuffer.MaxAge, MinResendInterval, out var found, out var payloadLength));
        Assert.Equal(packet, found);
        Assert.Equal(3u, payloadLength);

        var expired = new RtpPacketResendBuffer();
        expired.Add(7, packet, 3, Start);
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.NotKept, expired.ClaimForResend(7, Start + RtpPacketResendBuffer.MaxAge + Tick, MinResendInterval, out _, out _));
    }

    [Fact]
    public void PacketsNeverSentOrOverwrittenAreNotKept()
    {
        var buffer = new RtpPacketResendBuffer();
        buffer.Add(5, Packet(5), 1, Start);
        buffer.Add(5 + RtpPacketResendBuffer.CAPACITY, Packet(6), 1, Start);

        Assert.Equal(RtpPacketResendBuffer.ClaimResult.NotKept, buffer.ClaimForResend(4, Start, MinResendInterval, out _, out _));
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.NotKept, buffer.ClaimForResend(5, Start, MinResendInterval, out _, out _));
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(5 + RtpPacketResendBuffer.CAPACITY, Start, MinResendInterval, out var packet, out _));
        Assert.Equal(6, packet.AsSpan()[0]);
    }

    [Fact]
    public void SequenceNumbersWrap()
    {
        var buffer = new RtpPacketResendBuffer();
        buffer.Add(ushort.MaxValue, Packet(1), 1, Start);
        buffer.Add(0, Packet(2), 1, Start);

        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(ushort.MaxValue, Start, MinResendInterval, out var last, out _));
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(0, Start, MinResendInterval, out var first, out _));
        Assert.Equal(1, last.AsSpan()[0]);
        Assert.Equal(2, first.AsSpan()[0]);
    }

    [Fact]
    public void RequestsWhileAResendMayBeInFlightAreSuppressed()
    {
        var buffer = new RtpPacketResendBuffer();
        buffer.Add(9, Packet(9), 1, Start);

        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(9, Start, MinResendInterval, out _, out _));
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.RecentlyResent, buffer.ClaimForResend(9, Start + MinResendInterval - Tick, MinResendInterval, out var suppressed, out _));
        Assert.Null(suppressed.Array);
        buffer.Add(10, Packet(10), 1, Start);
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(9, Start + MinResendInterval, MinResendInterval, out _, out _));
    }

    /// <summary>
    /// However often packets are asked for, a burst of resends is at most every packet kept, and after it the
    /// bytes resent cannot exceed the bytes sent.
    /// </summary>
    [Fact]
    public void ResendsAreLimitedToTheBytesKeptAndThenToTheBytesSent()
    {
        const int PACKET_LENGTH = 10;
        var buffer = new RtpPacketResendBuffer();
        for (int i = 0; i < 2 * RtpPacketResendBuffer.CAPACITY; i++)
        {
            buffer.Add((ushort)i, Packet(new byte[PACKET_LENGTH]), 1, Start);
        }

        for (int i = RtpPacketResendBuffer.CAPACITY; i < 2 * RtpPacketResendBuffer.CAPACITY; i++)
        {
            Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend((ushort)i, Start, MinResendInterval, out _, out _));
        }

        var later = Start + MinResendInterval;
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.OverBudget, buffer.ClaimForResend(RtpPacketResendBuffer.CAPACITY, later, MinResendInterval, out _, out _));

        buffer.Add(2 * RtpPacketResendBuffer.CAPACITY, Packet(new byte[PACKET_LENGTH]), 1, later);
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.Claimed, buffer.ClaimForResend(RtpPacketResendBuffer.CAPACITY + 1, later, MinResendInterval, out _, out _));
        Assert.Equal(RtpPacketResendBuffer.ClaimResult.OverBudget, buffer.ClaimForResend(RtpPacketResendBuffer.CAPACITY + 2, later, MinResendInterval, out _, out _));
    }
}
