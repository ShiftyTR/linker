using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics.CodeAnalysis;
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

        // ValidateOnBuild eagerly reflects over every registration; keep it as a debug-only check so
        // the memory-constrained Network Extension starts faster and allocates less.
        serviceProvider = services.BuildServiceProvider(new ServiceProviderOptions
        {
#if DEBUG
            ValidateScopes = true,
            ValidateOnBuild = true,
#endif
        });
        var routes = serviceProvider.GetRequiredService<linker.messenger.tuntap.cidr.TuntapCidrDecenterManager>();
        serviceProvider.GetRequiredService<linker.messenger.firewall.hooks.TuntapFirewallHook>().ResolvePeer = ip =>
            routes.FindValue(ip, out var peer, out _, out _) ? peer : null;
        serviceProvider.GetRequiredService<FirewallTransfer>().Replace(options.FirewallRules, options.FirewallState);
        options.AfterBuild?.Invoke(this);
    }

    public T GetRequiredService<T>() where T : notnull
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        return serviceProvider.GetRequiredService<T>();
    }

    // MessengerResolver dispatches these public handlers by their MessengerId attributes.
    // Keep just the client entry points when the iOS provider is fully trimmed.
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(SignInClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(DecenterClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(SyncClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(TunnelClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(linker.messenger.relay.messenger.RelayClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(PcpClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(linker.messenger.tuntap.messenger.TuntapClientMessenger))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(FirewallClientMessenger))]
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
            .UseRelayClient()
            // UseTunnelClient snapshots the transports; register relay before that snapshot.
            .UseTunnelClient()
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
