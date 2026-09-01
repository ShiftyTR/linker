using MemoryPack;
using Microsoft.Extensions.DependencyInjection;
using linker.messenger.serializer.memorypack;

namespace linker.messenger.vpn.client;

internal static class VpnClientSerialization
{
    public static ServiceCollection AddVpnClientSerialization(this ServiceCollection services)
    {
        services.AddSingleton<linker.libs.ISerializer, PlusMemoryPackSerializer>();

        MemoryPackFormatterProvider.Register(new IPEndPointFormatter());
        MemoryPackFormatterProvider.Register(new IPAddressFormatter());
        MemoryPackFormatterProvider.Register(new TunnelConnectionFormatter());
        MemoryPackFormatterProvider.Register(new ConnectionFormatter());
        MemoryPackFormatterProvider.Register(new SyncInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelTransportWanPortInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelTransportItemInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelTransportInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelWanPortProtocolInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelRouteLevelInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelNetworkInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelSetRouteLevelInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelInterfaceInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelNetInfoFormatter());
        MemoryPackFormatterProvider.Register(new TunnelTransportItemSetInfoFormatter());
        MemoryPackFormatterProvider.Register(new PortMappingInfoFormatter());
        MemoryPackFormatterProvider.Register(new DecenterSyncInfoFormatter());
        MemoryPackFormatterProvider.Register(new DecenterPullPageInfoFormatter());
        MemoryPackFormatterProvider.Register(new DecenterPullPageResultInfoFormatter());
        MemoryPackFormatterProvider.Register(new TuntapVeaLanIPAddressFormatter());
        MemoryPackFormatterProvider.Register(new TuntapVeaLanIPAddressListFormatter());
        MemoryPackFormatterProvider.Register(new TuntapInfoFormatter());
        MemoryPackFormatterProvider.Register(new TuntapForwardInfoFormatter());
        MemoryPackFormatterProvider.Register(new TuntapForwardTestWrapInfoFormatter());
        MemoryPackFormatterProvider.Register(new TuntapForwardTestInfoFormatter());
        MemoryPackFormatterProvider.Register(new TuntapLanInfoFormatter());
        MemoryPackFormatterProvider.Register(new LeaseInfoFormatter());
        MemoryPackFormatterProvider.Register(new LeaseSubInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallRuleInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallSearchInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallSearchForwardInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallListInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallAddForwardInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallRemoveForwardInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallStateForwardInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallCheckInfoFormatter());
        MemoryPackFormatterProvider.Register(new FirewallCheckForwardInfoFormatter());
        return services;
    }
}
