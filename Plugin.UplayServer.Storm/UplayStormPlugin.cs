using ModdableWebServer.Interfaces;
using ServerShared.Controllers;
using ServerShared.EventArguments;
using ServerShared.Plugins;
using ServerShared.Server;
using System.Net;

namespace Plugin.UplayServer.Storm;

/// <summary>
/// Serves Ubisoft's Storm MPE layer
/// </summary>
public class UplayStormPlugin : ServerPlugin<StormSettings>
{
    public override uint Priority => 0;

    public override string Name => "UplayServer.Storm";

    private StormResponder? _responder;
    private readonly Dictionary<int, Action<ReadOnlyMemory<byte>, IPEndPoint>> _byPort = [];

    public override void Start()
    {
        _responder = new StormResponder(Config)
        {
            Send = SendTo,
        };

        foreach (int p in Config.DetectPorts)
            _byPort[p] = (d, s) => _responder!.HandleDetect(d.Span, s);
        _byPort[Config.TraversalPort] = (d, s) => _responder!.HandleTraversal(d.Span, s);
        _byPort[Config.RelayPort]     = (d, s) => _responder!.HandleRelay(d.Span, s);

        var missing = _byPort.Keys
            .Where(p => !ServerController.Servers.Any(s => s.Port == p && s.IsUdp))
            .ToList();
        if (missing.Count > 0)
        {
            Log.Error("[storm] no UDP server registered for port(s) {Ports} — add them to "
                    + "Configs/ServerAppSettings.json with \"UseUDP\": true, or the game's "
                    + "Storm session will never come up", string.Join(", ", missing));
        }

        CoreUdpSession.OnBytesReceived += OnUdpBytes;
        Log.Information("[storm] MPE responder attached: detect={Detect} traversal={Trav} relay={Relay}, "
                      + "game_port={Game} base_rvcid=0x{Base:x8} max_peers={Max} host_hint={Hint}",
            string.Join("/", Config.DetectPorts), Config.TraversalPort, Config.RelayPort,
            Config.GamePort, Config.BaseRvcid, Config.MaxPeers,
            string.IsNullOrEmpty(Config.HostHint) ? "none" : Config.HostHint);
    }

    public override void Stop()
    {
        CoreUdpSession.OnBytesReceived -= OnUdpBytes;
        _responder?.Reset();
        _byPort.Clear();
    }

    private void OnUdpBytes(object? sender, SessionBytesReceivedEventArgs e)
    {
        if (sender is not CoreUdpSession session) return;
        if (session.EndPoint is not IPEndPoint src) return;
        if (!_byPort.TryGetValue(session.Server.Port, out var handler)) return;

        try
        {
            handler(e.Data, src);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[storm] handler failed for port {Port} from {Src} — "
                        + "this WILL look like the clients not connecting",
                session.Server.Port, src);
        }
    }

    private static void SendTo(byte[] payload, IPEndPoint dst)
    {
        foreach (var model in ServerController.Servers)
        {
            if (!model.IsUdp || model.Server is not CoreUdpServer udp) continue;
            if (udp.Sessions.TryGetValue(dst, out var session))
            {
                session.SendAsync(payload);
                return;
            }
        }
        Log.Warning("[storm] no UDP session for {Dst} — reply dropped", dst);
    }
}
