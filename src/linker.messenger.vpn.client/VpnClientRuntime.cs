using Microsoft.Extensions.DependencyInjection;
using linker.messenger.channel;
using linker.messenger.decenter;
using linker.messenger.exroute;
using linker.messenger.firewall;
using linker.messenger.pcp;
using linker.messenger.relay;
using linker.messenger.signin;
using linker.messenger.sync;
using linker.messenger.tunnel;
using linker.messenger.tunnel.client;
using linker.messenger.tuntap;

namespace linker.messenger.vpn.client;

/// <summary>Composes and owns the persistence-free Linker VPN client service graph.</summary>
public sealed class VpnClientRuntime : IDisposable
{
    private readonly ServiceProvider serviceProvider;
    private int started;
    private int disposed;

    public VpnClientRuntime(VpnClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton<ICommonStore, InMemoryCommonStore>();
        services.AddSingleton<IMessengerStore, InMemoryMessengerStore>();
        services.AddSingleton<ISignInClientStore, InMemorySignInClientStore>();
        services.AddSingleton<ITunnelClientStore, InMemoryTunnelClientStore>();
        services.AddSingleton<linker.messenger.relay.client.IRelayClientStore, InMemoryRelayClientStore>();
        services.AddSingleton<IPcpStore, InMemoryPcpStore>();
        services.AddSingleton<linker.messenger.tuntap.client.ITuntapClientStore, InMemoryTuntapClientStore>();
        services.AddSingleton<linker.messenger.tuntap.lease.ILeaseClientStore, InMemoryLeaseClientStore>();
        services.AddSingleton<IFirewallClientStore, InMemoryFirewallClientStore>();
        services.AddVpnClientSerialization();

        services
            .AddMessenger()
            .AddExRoute()
            .AddSignInClient()
            .AddDecenterClient()
            .AddSyncClient()
            .AddTunnelClient()
            .AddRelayClient()
            .AddPcpClient()
            .AddTuntapClient()
            .AddFirewallClient()
            .AddChannelClient();

        serviceProvider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        options.AfterBuild?.Invoke(this);
    }

    public T GetRequiredService<T>() where T : notnull
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return serviceProvider.GetRequiredService<T>();
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Exchange(ref started, 1) != 0) return Task.CompletedTask;

        serviceProvider
            .UseMessenger()
            .UseExRoute()
            .UseDecenterClient()
            .UseSyncClient()
            .UseTunnelClient()
            .UseRelayClient()
            .UsePcpClient()
            .UseTuntapClient()
            .UseFirewallClient()
            .UseChannelClient()
            .UseSignInClient();

        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0) serviceProvider.Dispose();
    }
}
