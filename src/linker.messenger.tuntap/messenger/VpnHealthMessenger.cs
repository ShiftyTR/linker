using linker.libs.diagnostics;
using linker.messenger.signin;
using System.Text.Json;

namespace linker.messenger.tuntap.messenger;

public sealed class VpnHealthMessenger(SignInServerCaching clients, VpnHealthCache cache) : IMessenger
{
    [MessengerId((ushort)TuntapMessengerIds.HealthReport)]
    public void HealthReport(IConnection connection)
    {
        // Identity always comes from the authenticated, current sign-in connection.
        if (!clients.TryGet(connection.Id, out var client) || !client.Connected || !ReferenceEquals(client.Connection, connection)) return;
        var payload = connection.ReceiveRequestWrap.Payload;
        if (payload.Length == 0 || payload.Length > VpnHealthCache.MaximumPayloadBytes) return;
        var now = DateTimeOffset.UtcNow;
        var previous = cache.Get(client.Id);
        if (previous != null && now - previous.ReceivedAtUtc < TimeSpan.FromSeconds(2)) return;
        try
        {
            var report = JsonSerializer.Deserialize(payload.Span, VpnHealthJsonContext.Default.VpnHealthReport);
            cache.TrySet(client.Id, report, now);
        }
        catch (JsonException) { }
    }
}
