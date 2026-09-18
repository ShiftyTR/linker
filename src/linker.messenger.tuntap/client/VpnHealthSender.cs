using linker.libs;
using linker.libs.diagnostics;
using linker.messenger.tuntap.messenger;
using System.Text.Json;

namespace linker.messenger.tuntap.client;

// One send per control connection at a time. A stuck old socket must not
// prevent reports on a replacement socket or accumulate more pending sends.
public sealed class VpnHealthSender(IMessengerSender sender, TimeSpan? timeout = null)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private IConnection retired;
    private string lastFailure = "";

    public async Task<bool> SendAsync(IConnection connection, VpnHealthReport report, CancellationToken cancellationToken = default)
    {
        if (!await gate.WaitAsync(0, cancellationToken).ConfigureAwait(false)) return false;
        try
        {
            if (connection?.Connected != true || ReferenceEquals(connection, retired)) return false;
            if (!VpnHealthCache.Valid(report)) { WarnOnce("invalid_report"); return false; }
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(report, VpnHealthJsonContext.Default.VpnHealthReport);
            if (payload.Length > VpnHealthCache.MaximumPayloadBytes) { WarnOnce("report_too_large"); return false; }
            Task<bool> pending = sender.SendOnly(new MessageRequestWrap
            {
                Connection = connection, MessengerId = (ushort)TuntapMessengerIds.HealthReport,
                Payload = payload, Timeout = 3000
            });
            try
            {
                bool sent = await pending.WaitAsync(timeout ?? TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
                if (!sent) { WarnOnce("send_failed"); return false; }
                if (lastFailure.Length > 0) LoggerHelper.Instance.Info("vpn health reporting_resumed");
                lastFailure = "";
                return true;
            }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
            {
                // WaitAsync alone does not cancel SendOnly. Close this exact socket
                // so the sign-in supervisor can reconnect; never close its replacement.
                retired = connection;
                _ = pending.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                try { connection.Dispose(); } catch (Exception) { }
                if (cancellationToken.IsCancellationRequested) throw;
                WarnOnce("send_timeout control_connection_retired");
                return false;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { WarnOnce($"send_failed type={ex.GetType().Name}"); return false; }
        finally { gate.Release(); }
    }

    private void WarnOnce(string failure)
    {
        if (lastFailure == failure) return;
        lastFailure = failure;
        LoggerHelper.Instance.Warning($"vpn health {failure}");
    }
}
