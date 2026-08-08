using System.Buffers.Binary;
using System.Net;

namespace Plugin.UplayServer.Storm;

/// <summary>
/// Storm MPE wire format. 
/// </summary>
internal static class MpeWire
{
    public static readonly byte[] MpeConst = [0x04, 0x03, 0x01, 0x03];

    // Frame types.
    public const byte TypeReq  = 0x10;
    public const byte TypeReq2 = 0x11;
    public const byte TypeRsp  = 0x12;
    public const byte TypeAck  = 0x13;

    // Traversal phase flags.
    public const byte FlagDetect      = 0x01;
    public const byte FlagHandshake   = 0x40;
    public const byte FlagHandshake2  = 0x41;
    public const byte FlagKeepAliveA  = 0x42;
    public const byte FlagKeepAliveB  = 0x43;
    public const byte FlagIntroduce   = 0x44;

    public const int ShortFrameLen = 28;

    public static byte[] CandidateTlv(IPAddress ip, int port)
    {
        var tlv = new byte[8];
        tlv[0] = 0x02;
        tlv[1] = 0x04;
        BinaryPrimitives.WriteUInt16BigEndian(tlv.AsSpan(2), (ushort)port);
        ip.MapToIPv4().GetAddressBytes().CopyTo(tlv, 4);
        return tlv;
    }

    public static byte[] WrapIntegrity(ReadOnlySpan<byte> inner)
    {
        var outBuf = new byte[22 + 5 + inner.Length];
        // 22 zeros are already zero-initialised.
        outBuf[22] = 0x80;
        outBuf[26] = 0x20;
        inner.CopyTo(outBuf.AsSpan(27));
        return outBuf;
    }

    public static ReadOnlySpan<byte> Unwrap(ReadOnlySpan<byte> data)
    {
        if (data.Length < 21) return data;
        int i = 0;
        while (i < data.Length && data[i] == 0) i++;
        if (i >= 16 && i + 5 <= data.Length && data[i] == 0x80 && data[i + 4] == 0x20)
            return data[(i + 5)..];
        return data;
    }
}
