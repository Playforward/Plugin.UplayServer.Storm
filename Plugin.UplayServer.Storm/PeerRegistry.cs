using System.Net;

namespace Plugin.UplayServer.Storm;

/// <summary>A peer the responder is brokering, keyed by its source IP.</summary>
internal sealed class StormPeer
{
    public required IPAddress Ip { get; init; }
    public required uint Rvcid { get; init; }
    public required uint Idx { get; init; }
    public required uint Cookie { get; init; }

    public IPEndPoint? TraversalAddr { get; set; }
    public bool Introduced { get; set; }


    public List<IPEndPoint> Candidates { get; } = [];

    public void AddCandidate(IPAddress ip, int port)
    {
        if (!Candidates.Any(c => c.Address.Equals(ip) && c.Port == port))
            Candidates.Add(new IPEndPoint(ip, port));
    }
}

internal sealed class PeerRegistry(int gamePort, uint baseRvcid, int maxPeers, IPAddress? hostHint)
{
    private readonly Dictionary<IPAddress, StormPeer> _peers = [];
    private readonly HashSet<uint> _usedSlots = [];
    private readonly object _gate = new();

    public IPAddress? HostHint { get; } = hostHint;

    private uint AllocSlot(IPAddress ip)
    {
        uint slot;
        if (HostHint is not null && ip.Equals(HostHint))
            slot = 0;
        else
        {
            slot = HostHint is not null ? 1u : 0u;
            while (_usedSlots.Contains(slot)) slot++;
        }
        while (_usedSlots.Contains(slot)) slot++;   // hinted host arriving after a squatter
        _usedSlots.Add(slot);
        return slot;
    }

    public StormPeer? Resolve(IPEndPoint src)
    {
        lock (_gate)
        {
            if (_peers.TryGetValue(src.Address, out var existing))
                return existing;

            if (_peers.Count >= maxPeers)
            {
                Log.Warning("[storm] ignoring {Ip} — already tracking {N} peer(s)",
                    src.Address, _peers.Count);
                return null;
            }

            uint slot = AllocSlot(src.Address);
            uint rvcid = baseRvcid + slot;
            var peer = new StormPeer
            {
                Ip = src.Address,
                Rvcid = rvcid,
                Idx = 5 + slot,
                Cookie = rvcid ^ 0x5A5A5A5Au,
            };
            peer.AddCandidate(src.Address, gamePort);
            _peers[src.Address] = peer;
            Log.Information("[storm] registered peer {Ip} rvcid=0x{Rvcid:x8} idx={Idx} ({N}/{Max})",
                src.Address, rvcid, peer.Idx, _peers.Count, maxPeers);
            return peer;
        }
    }

    public List<StormPeer> Others(StormPeer self)
    {
        lock (_gate)
            return _peers.Values.Where(p => !ReferenceEquals(p, self)).ToList();
    }

    public List<StormPeer> Ready()
    {
        lock (_gate)
            return _peers.Values.Where(p => p.TraversalAddr is not null).ToList();
    }

    public void Clear()
    {
        lock (_gate)
        {
            _peers.Clear();
            _usedSlots.Clear();
        }
    }
}
