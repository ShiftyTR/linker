using linker.libs;
using linker.messenger.relay.server;
using linker.messenger.signin;
using linker.messenger.vpn.client;
using linker.tunnel.transport;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Linker.Vpn.Client.Tests;

public sealed class VpnWireTests
{
    private static readonly ISerializer Serializer = CreateSerializer();

    private static ISerializer CreateSerializer()
    {
        var services = new ServiceCollection();
        // Exercise the actual minimal runtime registration, without starting network timers.
        var registration = typeof(VpnClientRuntime).Assembly.GetType("linker.messenger.vpn.client.VpnClientSerialization", true)!;
        registration.GetMethod("AddVpnClientSerialization")!.Invoke(null, [services]);
        return services.BuildServiceProvider().GetRequiredService<ISerializer>();
    }

    [Fact]
    public void GenericControlEnvelopesPreserveAuthenticationCountersAndRelayFlow()
    {
        var key = new KeyValuePair<string, string>("key", "password");
        Assert.Equal(key, Serializer.Deserialize<KeyValuePair<string, string>>(Serializer.Serialize(key)));
        var counter = new List<(string, string, int)> { ("tunnels", "phone", 3) };
        Assert.Equal(counter, Serializer.Deserialize<List<(string, string, int)>>(Serializer.Serialize(counter)));
        var request = ("peer", "tuntap", 42u);
        Assert.Equal(request, Serializer.Deserialize<(string, string, uint)>(Serializer.Serialize(request)));
    }

    [Fact]
    public void PeerDiscoveryPreservesOpaquePayloads()
    {
        var message = new linker.messenger.decenter.DecenterSyncInfo
            { Name = "tuntap", Data = new byte[] { 0, 1, 127, 255 } };
        var copy = Serializer.Deserialize<linker.messenger.decenter.DecenterSyncInfo>(Serializer.Serialize(message));
        Assert.Equal(message.Name, copy.Name);
        Assert.Equal(message.Data.ToArray(), copy.Data.ToArray());
        var page = new List<ReadOnlyMemory<byte>> { copy.Data, new byte[] { 42 } };
        var result = Serializer.Deserialize<List<ReadOnlyMemory<byte>>>(Serializer.Serialize(page));
        Assert.Equal(2, result.Count);
        Assert.Equal(page[0].ToArray(), result[0].ToArray());
        Assert.Equal(page[1].ToArray(), result[1].ToArray());
    }

    [Fact]
    public void SignInPreservesIdentityGroupAndArguments()
    {
        var message = new SignInfo { MachineId = "phone", MachineName = "iPhone", GroupId = "group",
            Version = "1", Args = new() { ["machineKey"] = "installation", ["groupPassword"] = "test" } };
        var copy = Serializer.Deserialize<SignInfo>(Serializer.Serialize(message));
        Assert.Equal(message.MachineId, copy.MachineId);
        Assert.Equal(message.GroupId, copy.GroupId);
        Assert.Equal(message.Args, copy.Args);
    }

    [Fact]
    public void RelayDiscoveryPreservesNestedNodeList()
    {
        var message = new RelayAskResultInfo { MasterId = "master", Nodes =
            [new RelayServerNodeStoreInfo { NodeId = "node", Name = "relay", Host = "127.0.0.1:1802", BandwidthEach = 72, Public = true }] };
        var copy = Serializer.Deserialize<RelayAskResultInfo>(Serializer.Serialize(message));
        Assert.Equal("master", copy.MasterId);
        var node = Assert.Single(copy.Nodes);
        Assert.Equal("node", node.NodeId);
        Assert.Equal("127.0.0.1:1802", node.Host);
        Assert.Equal(72, node.BandwidthEach);
        Assert.True(node.Public);
    }

    [Fact]
    public void RelayHandshakePreservesFlowAndBothPeers()
    {
        var message = new RelayMessageInfo { Type = RelayMessengerType.Answer, FlowId = 123,
            FromId = "phone", ToId = "peer", MasterId = "master" };
        var copy = Serializer.Deserialize<RelayMessageInfo>(Serializer.Serialize(message));
        Assert.Equal(message.Type, copy.Type);
        Assert.Equal(message.FlowId, copy.FlowId);
        Assert.Equal(message.FromId, copy.FromId);
        Assert.Equal(message.ToId, copy.ToId);
        Assert.Equal(message.MasterId, copy.MasterId);
    }

    [Fact]
    public void TransitiveReferencesUseClientOnlyAssemblies()
    {
        Assert.Null(typeof(linker.messenger.decenter.Entry).Assembly.GetType("linker.messenger.decenter.DecenterApiController"));
        Assert.Null(typeof(linker.messenger.signin.Entry).Assembly.GetType("linker.messenger.signin.SignInApiController"));
    }

    [Fact]
    public void DefaultTransportCertificateCanAuthenticateBothRoles()
    {
        var type = typeof(VpnClientRuntime).Assembly.GetType("linker.messenger.vpn.client.InMemoryMessengerStore", true)!;
        using var instance = (IDisposable)Activator.CreateInstance(type, new VpnClientOptions())!;
        var store = (linker.messenger.IMessengerStore)instance;
        var certificate = Assert.IsType<System.Security.Cryptography.X509Certificates.X509Certificate2>(store.Certificate);
        Assert.True(certificate.HasPrivateKey);
        Assert.NotEmpty(certificate.RawData);
        Assert.NotEmpty(store.CertificateExport.GetRawCertData());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NewOrResetPeerInheritsDefaultTransports(bool hasEmptyOverride)
    {
        var type = typeof(VpnClientRuntime).Assembly.GetType("linker.messenger.vpn.client.InMemoryTunnelClientStore", true)!;
        var store = (linker.messenger.tunnel.client.ITunnelClientStore)Activator.CreateInstance(type)!;
        await store.SetTunnelTransports(Helper.GlobalString, new List<TunnelTransportItemInfo>
            { new() { Name = "TcpRelay" } });
        if (hasEmptyOverride) await store.SetTunnelTransports("new-peer", new List<TunnelTransportItemInfo>());
        Assert.Equal("TcpRelay", Assert.Single(await store.GetTunnelTransports("new-peer")).Name);
        await store.SetTunnelTransports("new-peer", new List<TunnelTransportItemInfo>
            { new() { Name = "Udp" } });
        Assert.Equal("Udp", Assert.Single(await store.GetTunnelTransports("new-peer")).Name);
    }
}
