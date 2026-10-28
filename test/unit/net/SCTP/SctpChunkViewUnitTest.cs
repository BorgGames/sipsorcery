using System;
using System.Buffers.Binary;
using Xunit;

namespace SIPSorcery.Net.UnitTests;

public class SctpChunkViewUnitTest
{
    [Theory]
    [InlineData(SctpChunkType.DATA, SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpDataChunk.FIXED_PARAMETERS_LENGTH - 1)]
    [InlineData(SctpChunkType.SACK, SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpSackChunk.FIXED_PARAMETERS_LENGTH - 1)]
    [InlineData(SctpChunkType.INIT, SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpInitChunk.FIXED_PARAMETERS_LENGTH - 1)]
    [InlineData(SctpChunkType.INIT_ACK, SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpInitChunk.FIXED_PARAMETERS_LENGTH - 1)]
    public void RejectsTruncatedFixedParameters(SctpChunkType type, int length)
    {
        byte[] chunk = CreateChunk(type, length);
        Assert.Throws<FormatException>(() => { _ = new SctpChunkView(chunk); });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RejectsTruncatedSackReports(bool duplicateReports)
    {
        byte[] chunk = CreateChunk(SctpChunkType.SACK,
            SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpSackChunk.FIXED_PARAMETERS_LENGTH);
        const int GapCountOffset = SctpChunk.SCTP_CHUNK_HEADER_LENGTH + sizeof(uint) + sizeof(uint);
        int countOffset = GapCountOffset + (duplicateReports ? sizeof(ushort) : 0);
        BinaryPrimitives.WriteUInt16BigEndian(chunk.AsSpan(countOffset), 1);
        Assert.Throws<FormatException>(() => { _ = new SctpChunkView(chunk); });
    }

    [Theory]
    [InlineData(SctpChunkType.ERROR, 0)]
    [InlineData(SctpChunkType.ERROR, SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH - 1)]
    [InlineData(SctpChunkType.ERROR, SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH + 1)]
    [InlineData(SctpChunkType.ABORT, 0)]
    public void RejectsInvalidErrorCauseLengths(SctpChunkType type, ushort causeLength)
    {
        byte[] chunk = CreateChunk(type,
            SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH);
        WriteCauseHeader(chunk.AsSpan(SctpChunk.SCTP_CHUNK_HEADER_LENGTH), causeLength);
        Assert.Throws<FormatException>(() => { _ = new SctpChunkView(chunk); });
    }

    [Fact]
    public void RejectsTruncatedAbortCauseValue()
    {
        const int CauseLength = SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH + 1;
        byte[] chunk = CreateChunk(SctpChunkType.ABORT, SctpChunk.SCTP_CHUNK_HEADER_LENGTH + CauseLength);
        Span<byte> cause = chunk.AsSpan(SctpChunk.SCTP_CHUNK_HEADER_LENGTH);
        WriteCauseHeader(cause, CauseLength);
        BinaryPrimitives.WriteUInt16BigEndian(cause, (ushort)SctpErrorCauseCode.InvalidStreamIdentifier);
        Assert.Throws<IndexOutOfRangeException>(() => { _ = new SctpChunkView(chunk); });
    }

    [Fact]
    public void RejectsTruncatedErrorCauseHeader()
    {
        byte[] chunk = CreateChunk(SctpChunkType.ERROR,
            SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH - 1);
        Assert.Throws<FormatException>(() => { _ = new SctpChunkView(chunk); });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ErrorCausesSkipPaddingAndPermitUnpaddedFinalCause(bool includeFinalPadding)
    {
        const int CauseLength = SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH + 1;
        int paddedLength = SctpPadding.PadTo4ByteBoundary(CauseLength);
        byte[] chunk = CreateChunk(SctpChunkType.ERROR,
            SctpChunk.SCTP_CHUNK_HEADER_LENGTH + paddedLength + (includeFinalPadding ? paddedLength : CauseLength));
        WriteCauseHeader(chunk.AsSpan(SctpChunk.SCTP_CHUNK_HEADER_LENGTH), CauseLength);
        WriteCauseHeader(chunk.AsSpan(SctpChunk.SCTP_CHUNK_HEADER_LENGTH + paddedLength), CauseLength);
        var view = new SctpChunkView(chunk);
        var enumerator = view.GetErrorCodes().GetEnumerator();
        Assert.True(enumerator.MoveNext());
        Assert.Equal(SctpErrorCauseCode.UserInitiatedAbort, enumerator.Current);
        Assert.True(enumerator.MoveNext());
        Assert.Equal(SctpErrorCauseCode.UserInitiatedAbort, enumerator.Current);
        Assert.False(enumerator.MoveNext());
        Assert.False(enumerator.MoveNext());
    }

    private static byte[] CreateChunk(SctpChunkType type, int length)
    {
        byte[] chunk = new byte[length];
        chunk[0] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(chunk.AsSpan(sizeof(byte) + sizeof(byte)), (ushort)length);
        return chunk;
    }

    private static void WriteCauseHeader(Span<byte> buffer, ushort length)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)SctpErrorCauseCode.UserInitiatedAbort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(sizeof(ushort)), length);
    }
}
