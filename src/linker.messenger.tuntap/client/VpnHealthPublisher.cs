using linker.libs;
using linker.libs.diagnostics;
using linker.messenger.signin;

namespace linker.messenger.tuntap.client;

public sealed class VpnHealthPublisher(SignInClientState signIn, TuntapTransfer tun, TuntapConfigTransfer config,
    TuntapProxy proxy, TuntapDecenter decenter, IMessengerSender sender) : IDisposable
{
    private readonly CancellationTokenSource stop = new();
    private readonly VpnHealthSender delivery = new(sender);
    private string lastFailure = "";
    private int started;
    public void Start()
    {
        if (Interlocked.Exchange(ref started, 1) == 0) _ = Run();
    }

    public VpnHealthReport Capture()
    {
        var report = VpnHealthJournal.Capture();
        report.InterfaceState = tun.Status.ToString().ToLowerInvariant();
        report.InterfaceErrorCode = string.IsNullOrWhiteSpace(tun.SetupError) ? "" : "interface_setup_failed";
        report.VirtualIp = config.Info.IP.ToString();
        foreach (var entry in proxy.Connections.Values)
        {
            var peer = report.Peers.FirstOrDefault(p => p.PeerId == entry.RemoteMachineId);
            if (peer == null && report.Peers.Count < 64)
            {
                peer = new VpnPeerHealth { PeerId = entry.RemoteMachineId };
                report.Peers.Add(peer);
            }
            if (peer == null) continue;
            if (entry.Connected)
            {
                peer.State = "connected";
                peer.ErrorCode = "";
            }
            else { peer.State = "disconnected"; peer.ErrorCode = "path_closed"; }
            peer.Transport = entry.TransportName ?? "";
            peer.Stage = entry.Type.ToString().ToLowerInvariant();
            peer.NodeId = entry.NodeId ?? "";
            peer.LatencyMs = entry.Delay;
            peer.LastReceiveAgeMs = entry.LastTicks.Diff();
            peer.SentBytes = (long)entry.SendBytes;
            peer.ReceivedBytes = (long)entry.ReceiveBytes;
        }
        foreach (var peer in report.Peers)
            if (decenter.Infos.TryGetValue(peer.PeerId, out var remote)) peer.VirtualIp = remote.IP?.ToString() ?? "";
        report.TotalPeers = Math.Max(report.TotalPeers, proxy.Connections.Count);
        return report;
    }

    private async Task Run()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            do
            {
                try
                {
                    var connection = signIn.Connection;
                    if (connection?.Connected != true)
                    {
                        WarnOnce("control_disconnected");
                        continue;
                    }
                    if (await delivery.SendAsync(connection, Capture(), stop.Token).ConfigureAwait(false)) lastFailure = "";
                }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
                catch (Exception ex) { WarnOnce($"capture_failed type={ex.GetType().Name}"); }
            } while (await timer.WaitForNextTickAsync(stop.Token).ConfigureAwait(false));
        }
        catch (OperationCanceledException) { }
    }

    private void WarnOnce(string failure)
    {
        if (lastFailure == failure) return;
        lastFailure = failure;
        LoggerHelper.Instance.Warning($"vpn health {failure}");
    }

    public void Dispose() { stop.Cancel(); }
}
