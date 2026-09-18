using linker.nat;
using linker.tun.hook;
using System.Buffers.Binary;

namespace linker.messenger.firewall.hooks
{
    public sealed class TuntapFirewallHook : ILinkerTunPacketHook
    {
        public string Name => "Firewall";
        public LinkerTunPacketHookLevel ReadLevel => LinkerTunPacketHookLevel.Normal;
        public LinkerTunPacketHookLevel WriteLevel => LinkerTunPacketHookLevel.Normal;

        private readonly LinkerFirewall linkerFirewall;
        // The route owner is an authenticated machine ID, not the packet's claimed IP.
        public Func<uint, string> ResolvePeer { get; set; }
        public TuntapFirewallHook(LinkerFirewall linkerFirewall)
        {
            this.linkerFirewall = linkerFirewall;
        }

        public (LinkerTunPacketHookFlags add, LinkerTunPacketHookFlags del) Read(ReadOnlyMemory<byte> packet)
        {
            if (packet.Length >= 20 && packet.Span[0] >> 4 == 4)
                linkerFirewall.AddAllow(packet, ResolvePeer?.Invoke(BinaryPrimitives.ReadUInt32BigEndian(packet.Span.Slice(16, 4))));
            return (LinkerTunPacketHookFlags.None, LinkerTunPacketHookFlags.None);
        }

        public ValueTask<(LinkerTunPacketHookFlags add, LinkerTunPacketHookFlags del)> WriteAsync(ReadOnlyMemory<byte> packet, uint originDstIp, string srcId)
        {
            if (linkerFirewall.Check(srcId, packet))
            {
                return ValueTask.FromResult((LinkerTunPacketHookFlags.None, LinkerTunPacketHookFlags.None));
            }
            return ValueTask.FromResult((LinkerTunPacketHookFlags.None, LinkerTunPacketHookFlags.Next | LinkerTunPacketHookFlags.Write));
        }
    }
}
