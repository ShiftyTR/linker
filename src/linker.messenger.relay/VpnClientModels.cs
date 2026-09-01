#if LINKER_VPN_CLIENT_ONLY
using linker.libs.extends;
using linker.tunnel.connection;

namespace linker.messenger.relay.server;

// Client wire DTOs normally share the server configuration source. Keep their wire shape
// available in the VPN-only build without referencing linker.messenger.node.
public class RelayServerNodeInfo
{
    private string nodeId = Guid.NewGuid().ToString().ToUpperInvariant();
    public string NodeId { get => nodeId; set => nodeId = value.SubStr(0, 36); }
    private string name = "default";
    public string Name { get => name; set => name = value.SubStr(0, 32); }
    public string Host { get; set; } = string.Empty;
    public TunnelProtocolType Protocol { get; set; } = TunnelProtocolType.All;
    public int Connections { get; set; }
    public int Bandwidth { get; set; }
    public int DataEachMonth { get; set; }
    public long DataRemain { get; set; }
    public string Url { get; set; } = "https://linker.snltty.com";
    public string Logo { get; set; } = "https://linker.snltty.com/img/logo.png";
}

public class RelayServerNodeReportInfo : RelayServerNodeInfo
{
    public string MasterKey { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public int ConnectionsRatio { get; set; }
    public double BandwidthRatio { get; set; }
    public int MasterCount { get; set; }
}

public sealed class RelayServerNodeStoreInfo : RelayServerNodeReportInfo
{
    public int Id { get; set; }
    public int BandwidthEach { get; set; } = 50;
    public bool Public { get; set; }
    public long LastTicks { get; set; }
    public int Delay { get; set; }
    public bool Manageable { get; set; }
    public string ShareKey { get; set; } = string.Empty;
}

public enum RelayMessengerType : byte
{
    Ask = 0,
    Answer = 1
}
#endif
