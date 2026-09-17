using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace linker.libs.diagnostics;

// Additive, versioned diagnostic protocol. No tokens, packet contents or exception text.
public sealed class VpnHealthReport
{
    public int SchemaVersion { get; set; } = 1;
    public string SessionId { get; set; } = "";
    public long Sequence { get; set; }
    public DateTimeOffset ObservedAtUtc { get; set; }
    public DateTimeOffset ReceivedAtUtc { get; set; }
    public string InterfaceState { get; set; } = "unknown";
    public string InterfaceErrorCode { get; set; } = "";
    public string VirtualIp { get; set; } = "";
    public int TotalPeers { get; set; }
    public List<VpnPeerHealth> Peers { get; set; } = new();
    public List<VpnHealthEvent> Events { get; set; } = new();
}

public sealed class VpnPeerHealth
{
    public string PeerId { get; set; } = "";
    public string VirtualIp { get; set; } = "";
    public string State { get; set; } = "idle";
    public string ErrorCode { get; set; } = "";
    public string Stage { get; set; } = "";
    public string Transport { get; set; } = "";
    public string NodeId { get; set; } = "";
    public DateTimeOffset ChangedAtUtc { get; set; }
    public long SentBytes { get; set; }
    public long ReceivedBytes { get; set; }
    public long LastReceiveAgeMs { get; set; }
    public int LatencyMs { get; set; }
}

public sealed class VpnHealthEvent
{
    public DateTimeOffset AtUtc { get; set; }
    public string PeerId { get; set; } = "";
    public string Code { get; set; } = "";
    public string Stage { get; set; } = "";
    public string NodeId { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, MaxDepth = 8)]
[JsonSerializable(typeof(VpnHealthReport))]
public partial class VpnHealthJsonContext : JsonSerializerContext { }
