using linker.libs;
using linker.libs.extends;
using linker.libs.timer;
using linker.messenger.pcp;
using linker.messenger.signin;
using linker.tunnel;
using linker.tunnel.connection;
using System.Collections.Concurrent;

namespace linker.messenger.channel
{
    public sealed class ChannelConnectionCaching
    {
        public VersionManager Version { get; } = new VersionManager();
        public ConcurrentDictionary<string, ConcurrentDictionary<string, ITunnelConnection>> Connections { get; } = new();

        public ConcurrentDictionary<string, ITunnelConnection> this[string transactionId]
        {
            get
            {
                if (Connections.TryGetValue(transactionId, out ConcurrentDictionary<string, ITunnelConnection> _connections) == false)
                {
                    _connections = new ConcurrentDictionary<string, ITunnelConnection>();
                    Connections.TryAdd(transactionId, _connections);
                }
                return _connections;
            }
        }

        public bool TryGetValue(string machineId, string transactionId, out ITunnelConnection connection)
        {
            connection = null;
            if (Connections.TryGetValue(transactionId, out ConcurrentDictionary<string, ITunnelConnection> _connections))
            {
                return _connections.TryGetValue(machineId, out connection);
            }
            return false;
        }
        public ITunnelConnection Add(ITunnelConnection connection)
        {
            if (Connections.TryGetValue(connection.TransactionId, out ConcurrentDictionary<string, ITunnelConnection> _connections) == false)
            {
                _connections = new ConcurrentDictionary<string, ITunnelConnection>();
                Connections.TryAdd(connection.TransactionId, _connections);
            }
            _connections.AddOrUpdate(connection.RemoteMachineId, connection, (a, b) => connection);
            Version.Increment();
            return connection;
        }
        public void Remove(string machineId, string transactionId)
        {
            if (Connections.TryGetValue(transactionId, out ConcurrentDictionary<string, ITunnelConnection> _connections))
            {
                if (_connections.TryRemove(machineId, out ITunnelConnection _connection))
                {
                    try
                    {
                        _connection.Dispose();
                    }
                    catch (Exception)
                    {
                    }
                    Version.Increment();
                }
            }
        }
        /// <summary>
        /// 移除已关闭的连接，仅当缓存中仍是同一个实例时才移除，避免误删已经顶替上来的新连接
        /// </summary>
        public void Remove(ITunnelConnection connection)
        {
            if (connection == null) return;
            if (Connections.TryGetValue(connection.TransactionId, out ConcurrentDictionary<string, ITunnelConnection> _connections) == false) return;
            if (_connections.TryGetValue(connection.RemoteMachineId, out ITunnelConnection _connection) && _connection.Equals(connection))
            {
                _connections.TryRemove(new KeyValuePair<string, ITunnelConnection>(connection.RemoteMachineId, _connection));
                Version.Increment();

                //顶替上来的连接死了，把它顶替掉的那个还活着的旧连接放回去，避免出现无连接的空档
                if (fallbacks.TryRemove(FallbackKey(connection), out ITunnelConnection fallback)
                    && fallback.Equals(connection) == false && fallback.Connected)
                {
                    System.Diagnostics.Debug.WriteLine($"[Chan] restore FALLBACK #{fallback.GetHashCode()} {fallback.TransportName}/{fallback.Type} after #{connection.GetHashCode()} {connection.TransportName}/{connection.Type} closed");
                    Add(fallback);
                }
            }
        }

        private readonly ConcurrentDictionary<string, ITunnelConnection> fallbacks = new();
        private static string FallbackKey(ITunnelConnection connection) => $"{connection.TransactionId}@{connection.RemoteMachineId}";

        /// <summary>
        /// 记录 connection 顶替掉的旧连接，旧连接仍然可用时可以在新连接断开后顶回来
        /// </summary>
        public void SetFallback(ITunnelConnection connection, ITunnelConnection fallback)
        {
            if (connection == null || fallback == null) return;
            fallbacks[FallbackKey(connection)] = fallback;
        }
        public void ClearFallback(ITunnelConnection connection)
        {
            if (connection == null) return;
            fallbacks.TryRemove(FallbackKey(connection), out _);
        }
    }

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
        protected void RemoveConnection(ITunnelConnection connection)
        {
            channelConnectionCaching.Remove(connection);
        }
        private void OnConnected(ITunnelConnection connection)
        {
            if (connection == null) return;

            if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                LoggerHelper.Instance.Warning($"{TransactionId} add connection {connection.GetHashCode()} {connection.ToJson()}");

            channelConnectionCaching.TryGetValue(connection.RemoteMachineId, TransactionId, out ITunnelConnection connectionOld);
            bool replacingOld = connectionOld != null && connection.Equals(connectionOld) == false;

            System.Diagnostics.Debug.WriteLine($"[Chan] +conn #{connection.GetHashCode()} {connection.RemoteMachineId} {connection.TransportName}/{connection.Type} | old=#{connectionOld?.GetHashCode()} {connectionOld?.TransportName}/{connectionOld?.Type} replacing={replacingOld}");

            pcpTransfer.AddConnection(connection);
            connection = channelConnectionCaching.Add(connection);
            Version.Increment();

            //升级到P2P时，确认新连接稳定后再释放旧的中继连接，避免P2P瞬断后无中继可用造成抖动
            if (replacingOld)
            {
                channelConnectionCaching.SetFallback(connection, connectionOld);
                VerifyReplace(connectionOld, connection, 0);
            }

            Connected(connection);
            Add(connection);
        }

        private const int replaceVerifyTimes = 6;
        /// <summary>
        /// 顶替上来的新连接必须真的收发通了才能释放旧连接，握手成功但打洞实际不通的P2P会让流量黑洞60秒
        /// </summary>
        private void VerifyReplace(ITunnelConnection oldConnection, ITunnelConnection newConnection, int times)
        {
            TimerHelper.SetTimeout(() =>
            {
                //中继连接不得释放被它顶替的P2P连接，否则会把可用的P2P也一起丢掉
                bool isDowngrade = oldConnection.Type == TunnelType.P2P && newConnection.Type != TunnelType.P2P;
                bool isCurrent = channelConnectionCaching.TryGetValue(newConnection.RemoteMachineId, TransactionId, out ITunnelConnection current) && current.Equals(newConnection);
                //Connected 只表示60秒内有过数据，实际不通的连接也是true，必须看收发字节和最近活动
                bool alive = newConnection.Connected && newConnection.SendBytes > 0 && newConnection.ReceiveBytes > 0 && newConnection.LastTicks.DiffLessEqual(15000);

                if (isDowngrade || isCurrent == false)
                {
                    System.Diagnostics.Debug.WriteLine($"[Chan] keep OLD #{oldConnection.GetHashCode()} {oldConnection.TransportName}/{oldConnection.Type} downgrade={isDowngrade} current={isCurrent}");
                    return;
                }
                if (alive)
                {
                    System.Diagnostics.Debug.WriteLine($"[Chan] promote NEW #{newConnection.GetHashCode()} {newConnection.TransportName}/{newConnection.Type}, dispose OLD #{oldConnection.GetHashCode()} {oldConnection.TransportName}/{oldConnection.Type}");
                    channelConnectionCaching.ClearFallback(newConnection);
                    try { oldConnection.Dispose(); } catch (Exception) { }
                    return;
                }
                if (times + 1 < replaceVerifyTimes)
                {
                    VerifyReplace(oldConnection, newConnection, times + 1);
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"[Chan] rollback to OLD #{oldConnection.GetHashCode()} {oldConnection.TransportName}/{oldConnection.Type} (NEW #{newConnection.GetHashCode()} {newConnection.TransportName}/{newConnection.Type} recv={newConnection.ReceiveBytes} send={newConnection.SendBytes} idle={newConnection.LastTicks.Diff()}ms) oldConnected={oldConnection.Connected}");
                channelConnectionCaching.ClearFallback(newConnection);
                if (oldConnection.Connected)
                {
                    channelConnectionCaching.Add(oldConnection);
                    Connected(oldConnection);
                    Add(oldConnection);
                }
                try { newConnection.Dispose(); } catch (Exception) { }
            }, 5000);
        }

        protected async ValueTask<ITunnelConnection> ConnectTunnel(string machineId, TunnelProtocolType denyProtocols)
        {
            //之前这个客户端已经连接过
            if (channelConnectionCaching.TryGetValue(machineId, TransactionId, out ITunnelConnection connection) && connection.Connected)
            {
                return connection;
            }

            //开始失败，说明在操作中。不阻塞数据包线程，后台建立中继+打洞
            if (operatingMultipleManager.StartOperation($"{machineId}@{TransactionId}") == false)
            {
                System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} SKIPPED (already operating)");
                return null;
            }
            System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} START relay+p2p");
            _ = RelayAndP2P(machineId, denyProtocols).ContinueWith((result) =>
            {
                operatingMultipleManager.StopOperation($"{machineId}@{TransactionId}");
                System.Diagnostics.Debug.WriteLine($"[Chan] connect {machineId} DONE status={result.Status} result=#{(result.IsCompletedSuccessfully ? result.Result?.GetHashCode() : null)}");
                if (result.IsCompletedSuccessfully && result.Result != null)
                {
                    channelConnectionCaching.Add(result.Result);
                }
            }).ConfigureAwait(false);

            return null;
        }
        private async Task<ITunnelConnection> RelayAndP2P(string machineId, TunnelProtocolType denyProtocols)
        {
            if (signInClientStore.Id == machineId)
            {
                return null;
            }

            //先快速建立中继，立刻可以通信
            ITunnelConnection connection = await tunnelTransfer.ConnectAsync(machineId, TransactionId, denyProtocols, flag: "relay", tunnelTypes: [TunnelType.Relay]).ConfigureAwait(false);
            if (connection != null)
            {
                channelConnectionCaching.Add(connection);
            }

            //后台打洞，升级到P2P。延迟1秒开始，最多尝试3次，避免频繁打洞导致连接抖动
            tunnelTransfer.StartBackground(machineId, TransactionId, denyProtocols, () =>
            {
                return channelConnectionCaching.TryGetValue(machineId, TransactionId, out ITunnelConnection _connection)
                && _connection.Connected
                && _connection.Type == TunnelType.P2P;

            }, (_connection) =>
            {
                return Task.CompletedTask;

            }, 3, 1000);

            return connection;
        }
    }
}
