using System.Buffers.Binary;
using System.Net;

namespace Plugin.UplayServer.Storm;

/// <summary>
/// Storm MPE responder
/// </summary>
internal sealed class StormResponder(StormSettings settings)
{
    private readonly PeerRegistry _peers = new(
        settings.GamePort, settings.BaseRvcid, settings.MaxPeers,
        IPAddress.TryParse(settings.HostHint, out var h) ? h : null);

    private readonly byte[] _appId = Convert.FromHexString(settings.AppIdHex);

    public required Action<byte[], IPEndPoint> Send { get; init; }

    public void Reset() => _peers.Clear();

    public void HandleDetect(ReadOnlySpan<byte> data, IPEndPoint src)
    {
        ushort seq = data.Length >= 4 ? BinaryPrimitives.ReadUInt16BigEndian(data[2..4]) : (ushort)0;
        var reply = new byte[4 + 8];
        reply[0] = MpeWire.TypeAck;
        reply[1] = MpeWire.FlagDetect;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2), seq);
        MpeWire.CandidateTlv(src.Address, src.Port).CopyTo(reply, 4);
        Send(reply, src);
        Log.Debug("[storm] detect  <- {Src}: echo {Ip}:{Port}", src, src.Address, src.Port);
    }

    public void HandleTraversal(ReadOnlySpan<byte> data, IPEndPoint src)
    {
        var peer = _peers.Resolve(src);
        if (peer is null) return;
        peer.TraversalAddr = src;
        if (data.Length < 4) return;

        var inner = MpeWire.Unwrap(data);
        if (inner.Length < 4) return;
        byte type = inner[0], flags = inner[1];
        ushort seq = BinaryPrimitives.ReadUInt16BigEndian(inner[2..4]);

        if (flags == MpeWire.FlagHandshake && type == MpeWire.TypeReq)
        {
            // initial REQ -> RSP(0x41): hand the client its idx/rvcid/cookie plus
            // its own reflexive candidate.
            var body = new List<byte>();
            body.AddRange(MpeWire.MpeConst);
            body.AddRange(Le(peer.Idx));
            body.AddRange(Le(peer.Idx));
            body.AddRange(Le(peer.Rvcid));
            body.AddRange([0x02, 0x02, 0x00, 0x00]);
            body.AddRange(Le(peer.Cookie));
            body.AddRange(MpeWire.CandidateTlv(src.Address, src.Port));
            Send(Frame(MpeWire.TypeRsp, MpeWire.FlagHandshake2, seq, body), src);
            Log.Debug("[storm] trav    <- {Src}: RSP(0x41) rvcid=0x{R:x8}", src, peer.Rvcid);
        }
        else if (flags == MpeWire.FlagHandshake2 && type == MpeWire.TypeReq2)
        {
            // REQ2 -> ACK(0x40)
            var body = new List<byte>();
            body.AddRange([0x02, 0x02, 0x00, 0x00]);
            body.AddRange(Le(peer.Cookie));
            body.AddRange(MpeWire.MpeConst);
            body.AddRange([0x00, 0x00, 0x00, 0x00]);
            body.AddRange(Le(peer.Idx));
            body.AddRange(Le(peer.Rvcid));
            Send(Frame(MpeWire.TypeAck, MpeWire.FlagHandshake, seq, body), src);
            Log.Debug("[storm] trav    <- {Src}: ACK(0x40)", src);
        }
        else if (flags is MpeWire.FlagKeepAliveA or MpeWire.FlagKeepAliveB)
        {
            // Keepalive
            int n = Math.Min(MpeWire.ShortFrameLen, inner.Length);
            var echo = new byte[n];
            inner[..n].CopyTo(echo);
            echo[0] = MpeWire.TypeAck;

            if (inner.Length > MpeWire.ShortFrameLen)
            {
                var withCand = new byte[echo.Length + 8];
                echo.CopyTo(withCand, 0);
                MpeWire.CandidateTlv(src.Address, src.Port).CopyTo(withCand, echo.Length);
                Send(MpeWire.WrapIntegrity(withCand), src);
            }
            else
            {
                Send(echo, src);
            }
        }
        else
        {
            Log.Debug("[storm] trav    <- {Src}: unhandled t=0x{T:x2} fl=0x{F:x2}", src, type, flags);
        }

        MaybeIntroduce();
    }

    private void MaybeIntroduce()
    {
        var ready = _peers.Ready();
        if (ready.Count < 2) return;

        foreach (var p in ready)
        {
            if (p.Introduced) continue;
            foreach (var o in _peers.Others(p))
            {
                if (o.TraversalAddr is null || o.Candidates.Count == 0) continue;
                IntroduceTo(p, o);
            }
            p.Introduced = true;
        }
    }

    private void IntroduceTo(StormPeer p, StormPeer o)
    {
        if (p.TraversalAddr is null) return;
        var body = new List<byte>();
        body.AddRange(MpeWire.MpeConst);
        body.AddRange([0x00, 0x00, 0x00, 0x00]);
        body.AddRange(Le(o.Idx));
        body.AddRange(Le(o.Rvcid));
        body.AddRange(MpeWire.MpeConst);
        body.AddRange([0x00, 0x00, 0x00, 0x00]);
        body.AddRange(Le(p.Idx));
        body.AddRange(Le(p.Rvcid));
        // The other peer's FULL candidate list, like the real 6-candidate frame.
        foreach (var c in o.Candidates)
            body.AddRange(MpeWire.CandidateTlv(c.Address, c.Port));

        Send(Frame(MpeWire.TypeRsp, MpeWire.FlagIntroduce, 0x0e, body), p.TraversalAddr);
        Log.Information("[storm] INTRODUCE -> {Dst}: peer rvcid=0x{R:x8} cands={C}",
            p.TraversalAddr, o.Rvcid, string.Join(",", o.Candidates.Select(c => $"{c.Address}:{c.Port}")));
    }

    public void HandleRelay(ReadOnlySpan<byte> data, IPEndPoint src)
    {
        int at = IndexOf(data, _appId);
        if (at < 0)
        {
            Log.Debug("[storm] relay   <- {Src}: no appid, ignoring ({N}B)", src, data.Length);
            return;
        }
        var peer = _peers.Resolve(src);
        uint token32 = peer?.Rvcid ?? 0x5b3dd200u;

        var reply = data.ToArray();
        // Stable per-peer opaque token; the client only ever echoes it back.
        var tok = new byte[16];
        for (int i = 0; i < 4; i++)
            BinaryPrimitives.WriteUInt32BigEndian(tok.AsSpan(i * 4), token32);
        tok.CopyTo(reply.AsSpan(at));
        if (reply[^1] == 0x80) reply[^1] = 0x00;

        Send(reply, src);
        Log.Debug("[storm] relay   <- {Src}: reg ACK token=0x{T:x8} ({N}B)", src, token32, reply.Length);
    }

    private static byte[] Le(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        return b;
    }

    private static byte[] Frame(byte type, byte flags, ushort seq, List<byte> body)
    {
        var f = new byte[4 + body.Count];
        f[0] = type;
        f[1] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(2), seq);
        body.CopyTo(f, 4);
        return f;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
        => haystack.IndexOf(needle);
}
