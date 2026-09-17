using linker.libs;
using linker.libs.diagnostics;
using linker.libs.extends;
using linker.libs.timer;
using linker.messenger.pcp;
using linker.messenger.signin;
using linker.tunnel;
using linker.tunnel.connection;
using System.Collections.Concurrent;

namespace linker.messenger.channel
{
    public class Channel
    {
        public VersionManager Version => channelConnectionCaching.Version;
        public ConcurrentDictionary<string, ITunnelConnection> Connections => channelConnectionCaching[TransactionId];

        protected virtual string TransactionId { get; }

        private readonly TunnelTransfer tunnelTransfer;
        private readonly PcpTransfer pcpTransfer;
        private readonly SignInClientTransfer signInClientTransfer;
        private readonly ISignInClientStore signInClientStore;
        private readonly ChannelConnectionCaching channelConnectionCaching;
        private readonly OperatingMultipleManager operatingMultipleManager = new OperatingMultipleManager();

        public Channel(TunnelTransfer tunnelTransfer, PcpTransfer pcpTransfer,
            SignInClientTransfer signInClientTransfer, ISignInClientStore signInClientStore, ChannelConnectionCaching channelConnectionCaching)
        {
            this.tunnelTransfer = tunnelTransfer;
            this.pcpTransfer = pcpTransfer;
            this.signInClientTransfer = signInClientTransfer;
            this.signInClientStore = signInClientStore;
            this.channelConnectionCaching = channelConnectionCaching;

            //监听打洞成功
            tunnelTransfer.SetConnectedCallback(TransactionId, OnConnected);
            //监听节点中继成功回调
            pcpTransfer.SetConnectedCallback(TransactionId, OnConnected);

        }
        public virtual void Add(ITunnelConnection connection)
        {
        }
        protected virtual void Connected(ITunnelConnection connection)
        {
        }
        protected virtual void PrepareConnection(ITunnelConnection connection) => Connected(connection);
        private readonly ConcurrentDictionary<string, ITunnelConnection> candidates = new();
        private readonly object selectionGate = new();
        private readonly linker.tunnel.transport.RelayNodeBackoff retryBackoff = new();

        protected void RemoveConnection(ITunnelConnection connection)
        {
            lock (selectionGate) RemoveConnectionCore(connection);
        }
        private void RemoveConnectionCore(ITunnelConnection connection)
        {
            var restored = channelConnectionCaching.Remove(connection);
            if (restored != null)
            {
                Connected(restored);
                Add(restored);
                VpnHealthJournal.Record(TransactionId, restored.RemoteMachineId, "connected", "fallback_restored", "relay", restored.NodeId);
            }
            else if (!channelConnectionCaching.TryGetValue(connection.RemoteMachineId, TransactionId, out var active) || !active.Connected)
            {
                VpnHealthJournal.Record(TransactionId, connection.RemoteMachineId, "disconnected", "path_closed", "transport");
            }
        }

        private void OnConnected(ITunnelConnection connection)
        {
            lock (selectionGate) OnConnectedCore(connection);
        }
        private void OnConnectedCore(ITunnelConnection connection)
        {
            if (connection == null) return;
            channelConnectionCaching.TryGetValue(connection.RemoteMachineId, TransactionId, out var current);
            if (ReferenceEquals(current, connection)) return;
            pcpTransfer.AddConnection(connection);
            PrepareConnection(connection);
            if (current?.Connected != true)
            {
                if (channelConnectionCaching.TryReplace(current, connection)) Activate(connection);
                else connection.Dispose();
                return;
            }
            if (current.Type == TunnelType.P2P)
            {
                if (connection.Type != TunnelType.P2P) channelConnectionCaching.SetFallback(current, connection);
                else connection.Dispose();
                return;
            }
            if (connection.Type != TunnelType.P2P || !candidates.TryAdd(connection.RemoteMachineId, connection))
            {
                connection.Dispose();
                return;
            }
            // Keep sending over the known working relay until the candidate receives data/heartbeat.
            _ = VerifyCandidate(current, connection);
        }

        private void Activate(ITunnelConnection connection)
        {
            retryBackoff.Succeeded(connection.RemoteMachineId, TransactionId);
            Connected(connection);
            Add(connection);
            VpnHealthJournal.Record(TransactionId, connection.RemoteMachineId, "connected", "path_ready", connection.Type.ToString().ToLowerInvariant(), connection.NodeId);
        }

        private async Task VerifyCandidate(ITunnelConnection previous, ITunnelConnection candidate)
        {
            bool promoted = false;
            try
            {
                for (int i = 0; i < 32 && candidate.Connected; i++)
                {
                    if (candidate.ReceiveBytes > 0 && candidate.LastTicks.DiffLessEqual(5000))
                    {
                        lock (selectionGate)
                        {
                            promoted = channelConnectionCaching.TryReplace(previous, candidate);
                            if (promoted) Activate(candidate);
                        }
                        return;
                    }
                    await Task.Delay(250).ConfigureAwait(false);
                }
                VpnHealthJournal.Record(TransactionId, candidate.RemoteMachineId, "retrying", "p2p_unverified", "p2p");
            }
            catch (Exception ex)
            {
                LoggerHelper.Instance.Warning($"tunnel candidate failed: {ex.GetType().Name}");
            }
            finally
            {
                candidates.TryRemove(new KeyValuePair<string, ITunnelConnection>(candidate.RemoteMachineId, candidate));
                if (!promoted) candidate.Dispose();
            }
        }

        protected async ValueTask<ITunnelConnection> ConnectTunnel(string machineId, TunnelProtocolType denyProtocols)
        {
            //之前这个客户端已经连接过
            if (channelConnectionCaching.TryGetValue(machineId, TransactionId, out ITunnelConnection connection) && connection.Connected)
            {
                return connection;
            }

            if (retryBackoff.Remaining(machineId, TransactionId) > 0) return null;
            //开始失败，说明在操作中。不阻塞数据包线程，后台建立中继+打洞
            if (operatingMultipleManager.StartOperation($"{machineId}@{TransactionId}") == false)
            {
                System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} SKIPPED (already operating)");
                return null;
            }
            System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} START relay+p2p");
            VpnHealthJournal.Record(TransactionId, machineId, "connecting", "", "relay");
            _ = RelayAndP2P(machineId, denyProtocols).ContinueWith((result) =>
            {
                if ((!result.IsCompletedSuccessfully || result.Result == null) &&
                    (!channelConnectionCaching.TryGetValue(machineId, TransactionId, out var active) || !active.Connected))
                {
                    retryBackoff.Failed(machineId, TransactionId);
                    // Keep the more precise node/pair/handshake failure in the event history.
                    VpnHealthJournal.Record(TransactionId, machineId, "retrying", "relay_unavailable", "relay");
                }
                if (result.IsFaulted) _ = result.Exception;
                operatingMultipleManager.StopOperation($"{machineId}@{TransactionId}");
                System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} DONE status={result.Status} result=#{(result.IsCompletedSuccessfully ? result.Result?.GetHashCode() : null)}");
                // Only OnConnected publishes a connection, after transport setup.
                // A late relay result must not replace a newer P2P connection here.
            }).ConfigureAwait(false);

            return null;
        }
        private async Task<ITunnelConnection> RelayAndP2P(string machineId, TunnelProtocolType denyProtocols)
        {
            if (signInClientStore.Id == machineId)
            {
                return null;
            }

            //后台打洞，升级到P2P。延迟1秒开始，最多尝试3次，避免频繁打洞导致连接抖动
            tunnelTransfer.StartBackground(machineId, TransactionId, denyProtocols, () =>
            {
                return channelConnectionCaching.TryGetValue(machineId, TransactionId, out ITunnelConnection _connection)
                && _connection.Connected
                && _connection.Type == TunnelType.P2P;

            }, (_connection) =>
            {
                if (_connection == null && (!channelConnectionCaching.TryGetValue(machineId, TransactionId, out var active) || !active.Connected))
                    VpnHealthJournal.Record(TransactionId, machineId, "error", "peer_unreachable", "transport");
                return Task.CompletedTask;
            }, 3, 1000);

            return await tunnelTransfer.ConnectAsync(machineId, TransactionId, denyProtocols, flag: "relay", tunnelTypes: [TunnelType.Relay]).ConfigureAwait(false);
        }
    }
}
