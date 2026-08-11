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

    /// <summary>
    /// 16-byte Ubi AppId(s), hex, one per title this box relays for.
    /// </summary>
    public List<string> AppIdHexes { get; set; } =
    [
        "4eb9089b324e4e65a0555ea05cfeb68f", // Far Cry New Dawn
        "e0b29a98ce384bc796ee9d20e793e9e3", // Far Cry 5
    ];
}
