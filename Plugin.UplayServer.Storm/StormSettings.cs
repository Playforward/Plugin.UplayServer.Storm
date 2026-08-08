namespace Plugin.UplayServer.Storm;

/// <summary>
/// Storm/MPE responder settings
/// </summary>
public sealed class StormSettings
{
    public int[] DetectPorts { get; set; } = [11000, 11001];
    public int TraversalPort { get; set; } = 11005;
    public int RelayPort { get; set; } = 12000;

    public int GamePort { get; set; } = 9000;

    public uint BaseRvcid { get; set; } = 0x00580001;

    public int MaxPeers { get; set; } = 2;

    public string HostHint { get; set; } = string.Empty;
    //TODO remove hardcoded value
    public string AppIdHex { get; set; } = "4eb9089b324e4e65a0555ea05cfeb68f";
}
