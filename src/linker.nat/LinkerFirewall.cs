using linker.libs;
using linker.libs.firewall;
using linker.libs.diagnostics;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace linker.nat;

/// <summary>Inbound IPv4 policy with return-flow tracking. Enabled policies default to deny.</summary>
public sealed class LinkerFirewall
{
    private const int MaximumCacheEntries = 65536;
    private readonly object policyGate = new();
    private Policy policy = new([], LinkerFirewallState.Disabled);
    public VersionManager Version { get; } = new();
    public bool VersionChanged(ref ulong version)
    {
        bool changed = Version.Eq(version, out ulong next);
        version = next;
        return changed;
    }
    public void SetState(LinkerFirewallState state)
    {
        lock (policyGate)
        {
            if (policy.State != state) Publish(new Policy(policy.Rules, state));
        }
    }
    public void BuildRules(List<LinkerFirewallRuleInfo> rules)
    {
        var compiled = Compile(rules);
        lock (policyGate) Publish(new Policy(compiled, policy.State));
    }
    // A packet using an old snapshot cannot restore a revoked allow in the new caches.
    public void ApplyRules(List<LinkerFirewallRuleInfo> rules, LinkerFirewallState state)
    {
        var compiled = Compile(rules);
        lock (policyGate) Publish(new Policy(compiled, state));
    }
    public static void ValidateRules(IEnumerable<LinkerFirewallRuleInfo> rules) => Compile(rules);
    private void Publish(Policy next)
    {
        Volatile.Write(ref policy, next);
        Version.Increment();
    }
    private static CompiledRule[] Compile(IEnumerable<LinkerFirewallRuleInfo> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return rules.Select(rule =>
        {
            if (rule == null || rule.Action is not (LinkerFirewallAction.Allow or LinkerFirewallAction.Deny)
                || rule.Protocol == LinkerFirewallProtocolType.None || (rule.Protocol & ~LinkerFirewallProtocolType.AllTraffic) != 0)
                throw new ArgumentException("Invalid firewall action or protocol.");
            if (!FirewallPorts.TryParse(rule.DstPort, out var ports, out var normalized))
                throw new ArgumentException("Invalid firewall ports. Use 1-65535, comma-separated ports or ranges.");
            if ((rule.Protocol & LinkerFirewallProtocolType.ICMP) != 0 && normalized != "0")
                throw new ArgumentException("ICMP rules do not have ports.");
            var cidr = string.IsNullOrWhiteSpace(rule.DstCIDR) || rule.DstCIDR is "0" or "*" ? "0.0.0.0/0" : rule.DstCIDR.Trim();
            var parts = cidr.Split('/');
            byte prefix = 32;
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork
                || (parts.Length == 2 && (!byte.TryParse(parts[1], out prefix) || prefix > 32)))
                throw new ArgumentException("Invalid IPv4 firewall destination.");
            var sources = (string.IsNullOrWhiteSpace(rule.SrcId) ? "*" : rule.SrcId).Split(',').Select(s => s.Trim()).ToHashSet(StringComparer.Ordinal);
            if (sources.Contains("")) throw new ArgumentException("Invalid firewall source device.");
            uint mask = NetworkHelper.ToPrefixValue(prefix);
            return new CompiledRule(sources, NetworkHelper.ToValue(ip) & mask, mask, ports, rule.Protocol, rule.Action);
        }).ToArray();
    }
    public bool Check(string srcId, IPEndPoint dstEP, ProtocolType protocol)
    {
        var current = Volatile.Read(ref policy);
        if (current.State != LinkerFirewallState.Enabled) return true;
        return dstEP.AddressFamily == AddressFamily.InterNetwork && Check(current, srcId, NetworkHelper.ToValue(dstEP.Address), (ushort)dstEP.Port, protocol);
    }
    public bool Check(string srcId, (uint ip, ushort port) dstEP, ProtocolType protocol)
    {
        var current = Volatile.Read(ref policy);
        return current.State != LinkerFirewallState.Enabled || Check(current, srcId, dstEP.ip, dstEP.port, protocol);
    }
    public void AddAllow(ReadOnlyMemory<byte> packet, string remotePeerId)
    {
        var current = Volatile.Read(ref policy);
        if (string.IsNullOrWhiteSpace(remotePeerId) || current.State != LinkerFirewallState.Enabled || !Packet.TryRead(packet.Span, out var data)) return;
        if (data.Protocol == ProtocolType.Icmp && (data.IcmpType != 8 || data.IcmpCode != 0)) return;
        Track(current, new FlowKey(remotePeerId, data.Source, data.SourcePort, data.Destination, data.DestinationPort, data.Protocol), true);
    }
    public bool Check(string srcId, ReadOnlyMemory<byte> packet)
    {
        var current = Volatile.Read(ref policy);
        bool allowed = CheckPacket(current, srcId, packet);
        if (!allowed)
        {
            Interlocked.Increment(ref current.BlockedPackets);
            // Sample once per second; high packet rates must not allocate per denial.
            long now = Environment.TickCount64;
            if (now >= Volatile.Read(ref current.NextBlockSample) && Interlocked.Exchange(ref current.NextBlockSample, now + 1000) <= now)
                Volatile.Write(ref current.LastBlock, new BlockedPacket(srcId ?? "", DateTimeOffset.UtcNow));
        }
        return allowed;
    }
    public VpnFirewallHealth CaptureHealth()
    {
        var current = Volatile.Read(ref policy);
        var last = Volatile.Read(ref current.LastBlock);
        return new VpnFirewallHealth
        {
            Enabled = current.State == LinkerFirewallState.Enabled, ActiveRuleCount = current.Rules.Length,
            BlockedPackets = Interlocked.Read(ref current.BlockedPackets),
            LastBlockedPeerId = last?.PeerId ?? "", LastBlockedAtUtc = last?.AtUtc
        };
    }
    private static bool CheckPacket(Policy current, string srcId, ReadOnlyMemory<byte> packet)
    {
        if (current.State != LinkerFirewallState.Enabled) return true;
        if (!Packet.TryRead(packet.Span, out var data)) return false;
        var key = data.Protocol == ProtocolType.Icmp
            ? new FlowKey(srcId, data.Destination, data.SourcePort, data.Source, data.DestinationPort, data.Protocol)
            : new FlowKey(srcId, data.Destination, data.DestinationPort, data.Source, data.SourcePort, data.Protocol);
        long now = Environment.TickCount64;
        if (current.Flows.TryGetValue(key, out var flow) && now - Volatile.Read(ref flow.LastUsed) <= Lifetime(data.Protocol)
            && flow.Outbound && (data.Protocol != ProtocolType.Icmp || (data.IcmpType == 0 && data.IcmpCode == 0)))
        {
            Volatile.Write(ref flow.LastUsed, now);
            return true;
        }
        bool allowed = Check(current, srcId, data.Destination, data.Protocol == ProtocolType.Icmp ? (ushort)0 : data.DestinationPort, data.Protocol);
        if (allowed && data.Protocol != ProtocolType.Icmp) Track(current, key, false);
        return allowed;
    }
    private static bool Check(Policy current, string source, uint ip, ushort port, ProtocolType protocol)
    {
        var kind = protocol switch
        {
            ProtocolType.Tcp => LinkerFirewallProtocolType.TCP,
            ProtocolType.Udp => LinkerFirewallProtocolType.UDP,
            ProtocolType.Icmp => LinkerFirewallProtocolType.ICMP,
            _ => LinkerFirewallProtocolType.None
        };
        if (kind == LinkerFirewallProtocolType.None) return false;
        var key = new DestinationKey(source, ip, port, protocol);
        if (current.Decisions.TryGetValue(key, out bool cached)) return cached;
        bool allowed = false;
        foreach (var rule in current.Rules)
        {
            if ((rule.Sources.Contains("*") || rule.Sources.Contains(source)) && (ip & rule.Mask) == rule.Network
                && (rule.Protocol & kind) != 0 && rule.Ports.Any(range => range.Contains(port)))
            {
                allowed = rule.Action == LinkerFirewallAction.Allow;
                break;
            }
        }
        if (current.Decisions.Count < MaximumCacheEntries) current.Decisions.TryAdd(key, allowed);
        return allowed;
    }
    private static long Lifetime(ProtocolType protocol) => protocol == ProtocolType.Tcp ? 7_200_000 : protocol == ProtocolType.Udp ? 120_000 : 30_000;
    private static void Track(Policy current, FlowKey key, bool outbound)
    {
        long now = Environment.TickCount64;
        if (now >= Volatile.Read(ref current.NextPrune) && Interlocked.Exchange(ref current.NextPrune, now + 5000) <= now)
            foreach (var entry in current.Flows)
                if (now - Volatile.Read(ref entry.Value.LastUsed) > Lifetime(entry.Key.Protocol)) current.Flows.TryRemove(entry);
        if (current.Flows.TryGetValue(key, out var existing))
        {
            if (now - Volatile.Read(ref existing.LastUsed) <= Lifetime(key.Protocol))
            {
                Volatile.Write(ref existing.LastUsed, now); return;
            }
            current.Flows.TryRemove(new KeyValuePair<FlowKey, Flow>(key, existing));
        }
        if (current.Flows.Count < MaximumCacheEntries) current.Flows.TryAdd(key, new Flow(outbound, now));
    }
    private sealed class Policy(CompiledRule[] rules, LinkerFirewallState state)
    {
        public readonly CompiledRule[] Rules = rules;
        public readonly LinkerFirewallState State = state;
        public readonly ConcurrentDictionary<DestinationKey, bool> Decisions = new();
        public readonly ConcurrentDictionary<FlowKey, Flow> Flows = new();
        public long NextPrune;
        public long BlockedPackets;
        public long NextBlockSample;
        public BlockedPacket LastBlock;
    }
    private sealed record BlockedPacket(string PeerId, DateTimeOffset AtUtc);
    private sealed record CompiledRule(HashSet<string> Sources, uint Network, uint Mask, FirewallPorts.Range[] Ports, LinkerFirewallProtocolType Protocol, LinkerFirewallAction Action);
    private readonly record struct DestinationKey(string Source, uint Ip, ushort Port, ProtocolType Protocol);
    private readonly record struct FlowKey(string PeerId, uint LocalIp, ushort LocalPort, uint RemoteIp, ushort RemotePort, ProtocolType Protocol);
    private sealed class Flow(bool outbound, long now)
    {
        public readonly bool Outbound = outbound;
        public long LastUsed = now;
    }
    private readonly record struct Packet(uint Source, uint Destination, ushort SourcePort, ushort DestinationPort, ProtocolType Protocol, byte IcmpType, byte IcmpCode)
    {
        public static bool TryRead(ReadOnlySpan<byte> bytes, out Packet packet)
        {
            packet = default;
            if (bytes.Length < 20 || bytes[0] >> 4 != 4) return false;
            int header = (bytes[0] & 15) * 4;
            if (header < 20 || header > bytes.Length || BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(2, 2)) != bytes.Length) return false;
            // Without reassembly, interpreting fragment payload as transport ports is unsafe.
            if ((BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(6, 2)) & 0x3fff) != 0) return false;
            var protocol = (ProtocolType)bytes[9];
            var payload = bytes.Slice(header);
            ushort srcPort, dstPort; byte icmpType = 255, icmpCode = 255;
            if (protocol == ProtocolType.Tcp)
            {
                if (payload.Length < 20 || (payload[12] >> 4) * 4 < 20 || (payload[12] >> 4) * 4 > payload.Length) return false;
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(payload); dstPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2));
            }
            else if (protocol == ProtocolType.Udp)
            {
                if (payload.Length < 8) return false;
                int length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4));
                if (length < 8 || length > payload.Length) return false;
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(payload); dstPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2));
            }
            else if (protocol == ProtocolType.Icmp)
            {
                if (payload.Length < 8) return false;
                icmpType = payload[0];
                icmpCode = payload[1];
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4));
                dstPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6));
            }
            else return false;
            packet = new Packet(BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(12)), BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(16)), srcPort, dstPort, protocol, icmpType, icmpCode);
            return true;
        }
    }
}
public class LinkerFirewallRuleInfo
{
    public string SrcId { get; set; } = string.Empty;
    public string DstCIDR { get; set; } = "0.0.0.0/0";
    public string DstPort { get; set; } = "0";
    public LinkerFirewallProtocolType Protocol { get; set; }
    public LinkerFirewallAction Action { get; set; }
}
[Flags]
public enum LinkerFirewallProtocolType : byte
{
    None = 0, TCP = 1, UDP = 2,
    All = TCP | UDP, // Preserve legacy wire value 3 (TCP + UDP).
    ICMP = 4, AllTraffic = All | ICMP
}
public enum LinkerFirewallAction { Allow = 1, Deny = 2, All = Allow | Deny }
public enum LinkerFirewallState { Enabled = 0, Disabled = 1 }
