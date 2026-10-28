using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

using SIPSorcery.Sys;

using static SIPSorcery.Net.SctpChunkType;

namespace SIPSorcery.Net;

public readonly ref struct SctpChunkView
{
    static readonly ILogger logger = LogFactory.CreateLogger<SctpChunk>();

    readonly ReadOnlySpan<byte> buffer;

    public ReadOnlySpan<byte> Buffer => buffer;

    public SctpChunkType Type => (SctpChunkType)buffer[0];
    public SctpDataChunk.Flags Flags => (SctpDataChunk.Flags)buffer[1];
    public bool Unordered => (Flags & SctpDataChunk.Flags.Unordered) != default;
    public bool Beginning => (Flags & SctpDataChunk.Flags.Beginning) != default;
    public bool Ending => (Flags & SctpDataChunk.Flags.Ending) != default;
    public ushort Length => BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
    public ReadOnlySpan<byte> Value => buffer.Slice(SctpChunk.SCTP_CHUNK_HEADER_LENGTH, Length - SctpChunk.SCTP_CHUNK_HEADER_LENGTH);

    #region Data Chunk
    public uint TSN => BinaryPrimitives.ReadUInt32BigEndian(Value);
    public ushort StreamID => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(4, 2));
    public ushort StreamSeqNum => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(6, 2));
    public uint PPID => BinaryPrimitives.ReadUInt32BigEndian(Value.Slice(8, 4));
    public ReadOnlySpan<byte> UserData
    {
        get
        {
            int pos = SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpDataChunk.FIXED_PARAMETERS_LENGTH;
            int len = Length - pos;
            return buffer.Slice(pos, len);
        }
    }
    #endregion Data Chunk

    #region SACK Chunk
    public uint CumulativeTsnAck => BinaryPrimitives.ReadUInt32BigEndian(Value);
    public uint ARwnd => BinaryPrimitives.ReadUInt32BigEndian(Value.Slice(4, 4));
    public ushort NumGapAckBlocks => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(8, 2));
    public ushort NumDuplicateTSNs => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(10, 2));
    public SctpTsnGapBlock GetTsnGapBlock(int index)
    {
        int posn = SctpSackChunk.FIXED_PARAMETERS_LENGTH
                 + (index * SctpSackChunk.GAP_REPORT_LENGTH);
        return new SctpTsnGapBlock
        {
            Start = BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(posn, 2)),
            End = BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(posn + 2, 2))
        };
    }
    public ReadOnlySpan<byte> GapAckBlocks
        => Value.Slice(SctpSackChunk.FIXED_PARAMETERS_LENGTH, NumGapAckBlocks * SctpSackChunk.GAP_REPORT_LENGTH);
    public uint GetDuplicateTSN(int index)
    {
        int posn = SctpSackChunk.FIXED_PARAMETERS_LENGTH
                 + (NumGapAckBlocks * SctpSackChunk.GAP_REPORT_LENGTH)
                 + (index * SctpSackChunk.DUPLICATE_TSN_LENGTH);
        return BinaryPrimitives.ReadUInt32BigEndian(Value.Slice(posn));
    }
    #endregion SACK Chunk

    #region Init Chunk
    public uint InitiateTag => BinaryPrimitives.ReadUInt32BigEndian(Value);
    public uint ARwndInit => BinaryPrimitives.ReadUInt32BigEndian(Value.Slice(4, 4));
    public ushort NumberInboundStreams => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(8, 2));
    public ushort NumberOutboundStreams => BinaryPrimitives.ReadUInt16BigEndian(Value.Slice(10, 2));
    public uint InitialTSN => BinaryPrimitives.ReadUInt32BigEndian(Value.Slice(12, 4));
    #endregion Init Chunk

    public ErrorCodeEnumerable GetErrorCodes()
    {
        int paramsBufferLength = Length - SctpChunk.SCTP_CHUNK_HEADER_LENGTH;
        int paramPosn = 0;
        var paramsBuffer = Value.Slice(paramPosn, paramsBufferLength);
        return new ErrorCodeEnumerable(paramsBuffer);
    }

    public readonly ref struct ErrorCodeEnumerable(ReadOnlySpan<byte> paramsBuffer)
    {
        readonly ReadOnlySpan<byte> originalParamsBuffer = paramsBuffer;
        public ErrorCodeEnumerator GetEnumerator() => new (originalParamsBuffer);
    }

    public ref struct ErrorCodeEnumerator(ReadOnlySpan<byte> paramsBuffer)
    {
        private const int ErrorCauseAlignment = 4;
        readonly ReadOnlySpan<byte> originalParamsBuffer = paramsBuffer;
        ReadOnlySpan<byte> paramsBuffer;
        bool started;

        public readonly SctpErrorCauseCode Current
        {
            get
            {
                SctpTlvChunkParameter.ParseFirstWord(paramsBuffer, out var type);
                return (SctpErrorCauseCode)type;
            }
        }

        public bool MoveNext()
        {
            if (started && !paramsBuffer.IsEmpty)
            {
                int length = SctpTlvChunkParameter.ParseFirstWord(paramsBuffer, out _);
                int padding = (ErrorCauseAlignment - length % ErrorCauseAlignment) % ErrorCauseAlignment;
                paramsBuffer = paramsBuffer.Slice(Math.Min(length + padding, paramsBuffer.Length));
            }
            else if (!started)
            {
                started = true;
                paramsBuffer = originalParamsBuffer;
            }

            if (paramsBuffer.IsEmpty)
            {
                return false;
            }
            if (paramsBuffer.Length < SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH)
            {
                throw new FormatException("SCTP error cause header is truncated.");
            }
            int causeLength = BinaryPrimitives.ReadUInt16BigEndian(paramsBuffer.Slice(sizeof(ushort), sizeof(ushort)));
            if (causeLength < SctpTlvChunkParameter.SCTP_PARAMETER_HEADER_LENGTH || causeLength > paramsBuffer.Length)
            {
                throw new FormatException("SCTP error cause length is invalid.");
            }
            return true;
        }

        public void Dispose() { }

        public void Reset()
        {
            throw new NotSupportedException();
        }
    }

    public SctpChunkView(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < SctpChunk.SCTP_CHUNK_HEADER_LENGTH)
        {
            throw new ArgumentException("Buffer too short to be a valid SCTP chunk.");
        }
        this.buffer = buffer;
        if (!Type.IsDefined())
        {
            throw new ArgumentException($"Unknown chunk type {Type}");
        }

        _ = Type switch
        {
            ABORT or ERROR => ValidateError(),
            DATA => ValidateData(),
            SACK => ValidateSack(),
            COOKIE_ACK or COOKIE_ECHO
            or HEARTBEAT or HEARTBEAT_ACK
            or SHUTDOWN_ACK or SHUTDOWN_COMPLETE
                => ValidateBase(),
            INIT or INIT_ACK => ValidateInit(),
            SHUTDOWN => ValidateShutdown(),
            _ => ValidateUnknownBase(),
        };
    }

    public SctpChunk AsChunk() => SctpChunk.Parse(buffer, 0);

    bool ValidateShutdown()
    {
        ValidateBase();
        return true;
    }

    bool ValidateInit()
    {
        ValidateBase();
        if (Length < SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpInitChunk.FIXED_PARAMETERS_LENGTH)
        {
            throw new FormatException("SCTP INIT chunk is too short for fixed parameter fields.");
        }
        return true;
    }

    bool ValidateSack()
    {
        ValidateBase();
        int minimumLength = SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpSackChunk.FIXED_PARAMETERS_LENGTH;
        if (Length < minimumLength)
        {
            throw new FormatException("SCTP SACK chunk is too short for fixed parameter fields.");
        }
        int gapAckSize = NumGapAckBlocks * SctpSackChunk.GAP_REPORT_LENGTH;
        int dupTsnSize = NumDuplicateTSNs * SctpSackChunk.DUPLICATE_TSN_LENGTH;
        int expectedLength = minimumLength + gapAckSize + dupTsnSize;
        if (Length < expectedLength)
        {
            throw new FormatException($"SCTP SACK chunk length {Length} does not match expected length {expectedLength}.");
        }
        return true;
    }

    bool ValidateBase()
    {
        if (Length < SctpChunk.SCTP_CHUNK_HEADER_LENGTH || Length > buffer.Length)
        {
            throw new ArgumentException("Buffer too short to be a valid SCTP chunk.");
        }
        return true;
    }

    bool ValidateData()
    {
        ValidateBase();
        if (Length < SctpChunk.SCTP_CHUNK_HEADER_LENGTH + SctpDataChunk.FIXED_PARAMETERS_LENGTH)
        {
            throw new FormatException($"SCTP data chunk cannot be parsed as buffer too short for fixed parameter fields.");
        }
        return true;
    }

    bool ValidateError()
    {
        ValidateBase();
        // Validate every cause before the association can process or log any of them.
        foreach (var errorCode in GetErrorCodes())
        {
            _ = errorCode;
        }
        SctpErrorChunk.ParseChunk(buffer, 0, isAbort: Type == ABORT);
        return true;
    }

    bool ValidateUnknownBase()
    {
        logger.LogDebug("TODO: Implement parsing logic for well known chunk type {Type}.", Type);
        return ValidateBase();
    }
}
