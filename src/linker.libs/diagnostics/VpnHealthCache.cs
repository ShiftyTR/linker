using System;
using System.Collections.Generic;
using System.Linq;

namespace linker.libs.diagnostics;

// Used on the VPN server and web tier. Diagnostics are ephemeral, never a database migration.
public sealed class VpnHealthCache
{
    private readonly object gate = new();
    private readonly Dictionary<string, VpnHealthReport> reports = new(StringComparer.Ordinal);
    private DateTimeOffset nextPrune;
    public const int MaximumPayloadBytes = 65536;

    public bool TrySet(string id, VpnHealthReport report, DateTimeOffset receivedAt)
    {
        if (!Guid.TryParse(id, out _) || !Valid(report)) return false;
        var now = DateTimeOffset.UtcNow;
        if (receivedAt < now.AddMinutes(-10) || receivedAt > now.AddMinutes(1)) return false;
        lock (gate)
        {
            if (now >= nextPrune)
            {
                foreach (var key in reports.Where(x => x.Value.ReceivedAtUtc < now.AddMinutes(-10)).Select(x => x.Key).ToArray()) reports.Remove(key);
                nextPrune = now.AddMinutes(1);
            }
            if (reports.TryGetValue(id, out var previous))
            {
                if (receivedAt <= previous.ReceivedAtUtc) return false;
                if (report.SessionId == previous.SessionId && report.Sequence <= previous.Sequence) return false;
            }
            else if (reports.Count >= 4096) return false;
            report.ReceivedAtUtc = receivedAt;
            reports[id] = report;
            return true;
        }
    }

    public VpnHealthReport Get(string id)
    {
        lock (gate)
        {
            if (reports.TryGetValue(id, out var report))
            {
                if (DateTimeOffset.UtcNow - report.ReceivedAtUtc < TimeSpan.FromMinutes(10)) return report;
                reports.Remove(id);
            }
            return null;
        }
    }

    private static bool Text(string value) => value != null && value.Length <= 128 && !value.Any(char.IsControl);
    public static bool Valid(VpnHealthReport r) => r != null && r.SchemaVersion == 1 && Guid.TryParse(r.SessionId, out _)
        && r.Sequence > 0 && Text(r.InterfaceState) && Text(r.InterfaceErrorCode) && Text(r.VirtualIp)
        && r.Peers != null && r.Peers.Count <= 64 && r.Events != null && r.Events.Count <= 32
        && r.Peers.All(p => p != null && Text(p.PeerId) && Text(p.VirtualIp) && Text(p.State) && Text(p.ErrorCode)
            && Text(p.Stage) && Text(p.Transport) && Text(p.NodeId))
        && r.Events.All(e => e != null && Text(e.PeerId) && Text(e.Code) && Text(e.Stage) && Text(e.NodeId));
}
