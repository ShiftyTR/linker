#if !LINKER_VPN_CLIENT_ONLY
using linker.libs.web;
#endif
using linker.messenger.firewall.hooks;
#if !LINKER_VPN_CLIENT_ONLY
using linker.messenger.forward.proxy;
using linker.messenger.socks5;
#endif
using linker.messenger.sync;
using linker.nat;
using linker.tun.hook;
using linker.tun;
using Microsoft.Extensions.DependencyInjection;

namespace linker.messenger.firewall
{
    public static class Entry
    {
        public static ServiceCollection AddFirewallClient(this ServiceCollection serviceCollection)
        {
            serviceCollection.AddSingleton<LinkerFirewall>();
            serviceCollection.AddSingleton<FirewallClientMessenger>();
            serviceCollection.AddSingleton<FirewallTransfer>();
#if !LINKER_VPN_CLIENT_ONLY
            serviceCollection.AddSingleton<FirewallApiController>();
#endif
            serviceCollection.AddSingleton<FirewallSync>();


            serviceCollection.AddSingleton<TuntapFirewallHook>();
#if !LINKER_VPN_CLIENT_ONLY
            serviceCollection.AddSingleton<Socks5FirewallHook>();
            serviceCollection.AddSingleton<ForwardFirewallHook>();
#endif



            return serviceCollection;
        }
        public static ServiceProvider UseFirewallClient(this ServiceProvider serviceProvider)
        {
            LinkerFirewall linkerFirewall = serviceProvider.GetService<LinkerFirewall>();

            IMessengerResolver messengerResolver = serviceProvider.GetService<IMessengerResolver>();
            messengerResolver.AddMessenger(new List<IMessenger> { serviceProvider.GetService<FirewallClientMessenger>() });

#if !LINKER_VPN_CLIENT_ONLY
            linker.messenger.api.IWebServer apiServer = serviceProvider.GetService<linker.messenger.api.IWebServer>();
            apiServer.AddPlugins(new List<IApiController> { serviceProvider.GetService<FirewallApiController>() });
#endif

            SyncTreansfer syncTransfer = serviceProvider.GetService<SyncTreansfer>();
            syncTransfer.AddSyncs(new List<ISync> { serviceProvider.GetService<FirewallSync>() });


            LinkerTunDeviceAdapter linkerTunDeviceAdapter = serviceProvider.GetService<LinkerTunDeviceAdapter>();
            linkerTunDeviceAdapter.AddHooks(new List<ILinkerTunPacketHook> { serviceProvider.GetService<TuntapFirewallHook>() });

#if !LINKER_VPN_CLIENT_ONLY
            Socks5Proxy socks5Proxy = serviceProvider.GetService<Socks5Proxy>();
            socks5Proxy.AddHooks(new List<ILinkerSocks5Hook> { serviceProvider.GetService<Socks5FirewallHook>() });

            ForwardProxy forwardProxy = serviceProvider.GetService<ForwardProxy>();
            forwardProxy.AddHooks(new List<ILinkerForwardHook> { serviceProvider.GetService<ForwardFirewallHook>() });
#endif

            return serviceProvider;
        }


        public static ServiceCollection AddFirewallServer(this ServiceCollection serviceCollection)
        {
            serviceCollection.AddSingleton<FirewallServerMessenger>();
            return serviceCollection;
        }
        public static ServiceProvider UseFirewallServer(this ServiceProvider serviceProvider)
        {

            IMessengerResolver messengerResolver = serviceProvider.GetService<IMessengerResolver>();
            messengerResolver.AddMessenger(new List<IMessenger> { serviceProvider.GetService<FirewallServerMessenger>() });
            return serviceProvider;
        }
    }
}
