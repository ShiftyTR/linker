#if !LINKER_VPN_CLIENT_ONLY
using linker.libs.web;
#endif
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
namespace linker.messenger.channel
{
    public static class Entry
    {
        public static ServiceCollection AddChannelClient(this ServiceCollection serviceCollection)
        {
#if !LINKER_VPN_CLIENT_ONLY
            serviceCollection.AddSingleton<ChannelApiController>();
#endif
            serviceCollection.AddSingleton<ChannelConnectionCaching>();

            return serviceCollection;
        }
        public static ServiceProvider UseChannelClient(this ServiceProvider serviceProvider, JsonDocument json = default)
        {
#if !LINKER_VPN_CLIENT_ONLY
            linker.messenger.api.IWebServer apiServer = serviceProvider.GetService<linker.messenger.api.IWebServer>();
            apiServer.AddPlugins(new List<IApiController> { serviceProvider.GetService<ChannelApiController>() });
#endif

            return serviceProvider;
        }
    }
}
