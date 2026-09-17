using System;
using System.Collections.Generic;
using System.Linq;

namespace linker.libs.diagnostics;

public static class VpnHealthJournal
{
    private static readonly object gate = new();
    private static readonly Dictionary<string, VpnPeerHealth> peers = new(StringComparer.Ordinal);
    private static readonly Queue<VpnHealthEvent> events = new();
    private static string session = Guid.NewGuid().ToString("N");
    private static long sequence;

    public static void Reset()
    {
        lock (gate) { peers.Clear(); events.Clear(); session = Guid.NewGuid().ToString("N"); sequence = 0; }
    }

    public static void ResolveRoute(string ip)
    {
        lock (gate)
            if (peers.TryGetValue(ip, out var entry) && entry.Stage == "routing") peers.Remove(ip);
    }

    public static void Record(string transaction, string peer, string state, string code, string stage, string node = "")
    {
        if (transaction != "tuntap" || string.IsNullOrEmpty(peer)) return;
        node ??= "";
        code ??= "";
        stage ??= "";
        lock (gate)
        {
            if (!peers.TryGetValue(peer, out var current))
            {
                if (peers.Count >= 128) peers.Remove(peers.MinBy(x => x.Value.ChangedAtUtc).Key);
                current = peers[peer] = new VpnPeerHealth { PeerId = peer };
            }
            var now = DateTimeOffset.UtcNow;
            if (current.State == state && current.ErrorCode == code && current.Stage == stage && current.NodeId == node) return;
            current.State = state;
            current.ErrorCode = state == "connected" ? "" : code;
            current.Stage = stage;
            current.NodeId = node;
            current.ChangedAtUtc = now;
            events.Enqueue(new VpnHealthEvent { AtUtc = now, PeerId = peer, Code = code, Stage = stage, NodeId = node });
            while (events.Count > 32) events.Dequeue();
        }
    }

    public static VpnHealthReport Capture()
    {
        lock (gate)
        {
            // Snapshots own their collections; network serialization never races with writers.
            return new VpnHealthReport
            {
                SessionId = session, Sequence = ++sequence, ObservedAtUtc = DateTimeOffset.UtcNow,
                TotalPeers = peers.Count,
                Peers = peers.Values.OrderByDescending(x => x.ChangedAtUtc).Take(64).Select(x => new VpnPeerHealth
                {
                    PeerId = x.PeerId, State = x.State, ErrorCode = x.ErrorCode, Stage = x.Stage,
                    NodeId = x.NodeId, ChangedAtUtc = x.ChangedAtUtc
                }).ToList(),
                Events = events.Reverse().Select(x => new VpnHealthEvent
                { AtUtc = x.AtUtc, PeerId = x.PeerId, Code = x.Code, Stage = x.Stage, NodeId = x.NodeId }).ToList()
            };
        }
    }
}
