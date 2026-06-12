using linker.libs;
using linker.libs.extends;
using linker.messenger;
using linker.messenger.relay.messenger;
using linker.messenger.relay.server;
using linker.messenger.signin;
using linker.tunnel.connection;
using linker.tunnel.wanport;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace linker.tunnel.transport
{
    public class TransportRelay : ITunnelTransport
    {
        public string Name => "TcpRelay";

        public string Label => "TCP、服务器中继";

        public TunnelProtocolType ProtocolType => TunnelProtocolType.Tcp;

        public TunnelWanPortProtocolType AllowWanPortProtocolType => TunnelWanPortProtocolType.Other;
        public TunnelType TunnelType => TunnelType.Relay;

        public bool Reverse => false;

        public bool DisableReverse => true;

        public bool SSL => true;

        public bool DisableSSL => false;

        public byte Order => 0;

        public Action<ITunnelConnection,TunnelTransportInfo> OnConnected { get; set; } = (state,info) => { };

        private readonly ICrypto crypto = CryptoFactory.CreateSymmetric(Helper.GlobalString);

        private readonly IMessengerSender messengerSender;
        private readonly ISerializer serializer;
        private readonly SignInClientState signInClientState;
        private readonly IMessengerStore messengerStore;
        private readonly ITunnelMessengerAdapter tunnelMessengerAdapter;

        //各中继节点最新ping延迟(NodeId -> 毫秒)，由 RelayClientTestTransfer 后台测速回写；
        //仅发起方(A)在 ConnectNodeServer 选节点时据此选最近节点，应答方(B)不参与选择，保证双方会合在同一节点
        private readonly ConcurrentDictionary<string, int> nodeDelays = new();

        public TransportRelay(IMessengerSender messengerSender, ISerializer serializer, SignInClientState signInClientState, IMessengerStore messengerStore, ITunnelMessengerAdapter tunnelMessengerAdapter)
        {
            this.messengerSender = messengerSender;
            this.serializer = serializer;
            this.signInClientState = signInClientState;
            this.messengerStore = messengerStore;
            this.tunnelMessengerAdapter = tunnelMessengerAdapter;
        }

        /// <summary>
        /// 后台测速结果回写。建立中继时发起方(A)据此选择最近(最低ping)节点；NodeId为空的项忽略。
        /// </summary>
        /// <param name="delays">NodeId -> ping延迟(毫秒)，-1或0表示不可达/未知</param>
        public void UpdateNodeDelays(IEnumerable<KeyValuePair<string, int>> delays)
        {
            if (delays == null)
            {
                return;
            }
            foreach (KeyValuePair<string, int> item in delays)
            {
                if (string.IsNullOrWhiteSpace(item.Key))
                {
                    continue;
                }
                nodeDelays[item.Key] = item.Value;
            }
        }

        private X509Certificate certificate;
        public void SetSSL(X509Certificate certificate)
        {
            this.certificate = certificate;
        }

        public virtual async Task<ITunnelConnection> ConnectAsync(TunnelTransportInfo tunnelTransportInfo)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(1024);
            try
            {
                //问一下能不能中继
                RelayAskResultInfo ask = await RelayAsk(tunnelTransportInfo).ConfigureAwait(false);
                List<RelayServerNodeStoreInfo> nodes = ask.Nodes;
                if (ask.Nodes.Count == 0)
                {
                    throw new Exception("relay client ask fail,no relay nodes");
                }

                //连接中继节点服务器
                Socket socket = await ConnectNodeServer(tunnelTransportInfo, ask).ConfigureAwait(false);
                if (socket == null)
                {
                    throw new Exception("relay client connect node server fail");
                }
                tunnelTransportInfo.TransactionTag = ask.Info.ToJson();

                //让对方确认中继
                if (await tunnelMessengerAdapter.SendConnectBegin(tunnelTransportInfo).ConfigureAwait(false) == false)
                {
                    throw new Exception("relay client begin fail");
                }

                //成功建立连接，
                SslStream sslStream = null;
                if (tunnelTransportInfo.SSL)
                {
                    sslStream = new SslStream(new NetworkStream(socket, false), false, ValidateServerCertificate, null);
                    await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        ClientCertificates = new X509CertificateCollection { messengerStore.Certificate },
                    }).ConfigureAwait(false);
                }

                await tunnelMessengerAdapter.SendConnectSuccess(tunnelTransportInfo).ConfigureAwait(false);

                return new TunnelConnectionTcp
                {
                    Direction = TunnelDirection.Forward,
                    ProtocolType = TunnelProtocolType.Tcp,
                    RemoteMachineId = tunnelTransportInfo.Remote.MachineId,
                    RemoteMachineName = tunnelTransportInfo.Remote.MachineName,
                    Stream = sslStream,
                    Socket = socket,
                    Mode = TunnelMode.Client,
                    IPEndPoint = (socket.RemoteEndPoint as IPEndPoint).MapToIPv4(),
                    TransactionId = tunnelTransportInfo.TransactionId,
                    TransportName = Name,
                    Type = TunnelType,
                    NodeId = ask.Info.NodeId,
                    SSL = tunnelTransportInfo.SSL,
                    BufferSize = 3
                };
            }
            catch (Exception ex)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                {
                    LoggerHelper.Instance.Error(ex);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
            await tunnelMessengerAdapter.SendConnectFail(tunnelTransportInfo).ConfigureAwait(false);
            return null;
        }
        private async Task<RelayAskResultInfo> RelayAsk(TunnelTransportInfo tunnelTransportInfo)
        {
            RelayInfo relayInfo = new RelayInfo();
            try
            {
                relayInfo = tunnelTransportInfo.TransactionTag.DeJson<RelayInfo>();
            }
            catch (Exception)
            {
            }

            MessageResponeInfo resp = await messengerSender.SendReply(new MessageRequestWrap
            {
                Connection = signInClientState.Connection,
                MessengerId = (ushort)RelayMessengerIds.Ask,
                Payload = serializer.Serialize((tunnelTransportInfo.Remote.MachineId, tunnelTransportInfo.TransactionId, tunnelTransportInfo.FlowId)),
                Timeout = 2000
            }).ConfigureAwait(false);
            if (resp.Code != MessageResponeCodes.OK)
            {
                return new RelayAskResultInfo { Info = relayInfo, Nodes = new List<RelayServerNodeStoreInfo>() };
            }
            RelayAskResultInfo ask = serializer.Deserialize<RelayAskResultInfo>(resp.Data.Span);
            ask.Info = relayInfo;
            ask.Info.MasterId = ask.MasterId;

            return ask;

        }
        private async Task<Socket> ConnectNodeServer(TunnelTransportInfo tunnelTransportInfo, RelayAskResultInfo ask)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(1 * 1024);

            try
            {
                //节点选择只在发起方(A)进行，应答方(B)在OnBegin里只连A通过TransactionTag指定的节点，保证双方落在同一中继节点会合。
                //延迟来自后台测速回写的 nodeDelays（ask.Nodes 自带的 Delay 来自服务器，恒为0不可用）。
                //顺序：服务器指定的会合节点(ask.Info.NodeId)最前 -> 已测速(delay>0)按延迟升序(最近优先) -> 未测速保持原始顺序作为确定性兜底
                IEnumerable<RelayServerNodeStoreInfo> orderedNodes = ask.Nodes
                    .Select((node, index) => (node, index, delay: nodeDelays.TryGetValue(node.NodeId, out int d) ? d : -1))
                    .OrderBy(x => string.IsNullOrEmpty(ask.Info.NodeId) == false && x.node.NodeId == ask.Info.NodeId ? 0 : 1)
                    .ThenBy(x => x.delay > 0 ? 0 : 1)
                    .ThenBy(x => x.delay > 0 ? x.delay : int.MaxValue)
                    .ThenBy(x => x.index)
                    .Select(x => x.node);
                foreach (var node in orderedNodes)
                {
                    try
                    {
                        ask.Info.Host = node.Host;
                        ask.Info.NodeId = node.NodeId;
                        await GetEndpoint(ask.Info).ConfigureAwait(false);

                        //连接中继服务器
                        Socket socket = await ConnectServer(ask.Info.Node).ConfigureAwait(false);
                        if (socket == null)
                        {
                            continue;
                        }

                        if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                        {
                            LoggerHelper.Instance.Debug($"relay client connected {ask.Info.Node}");
                        }

                        //建立关联
                        RelayMessageInfo relayMessage = new RelayMessageInfo
                        {
                            FlowId = tunnelTransportInfo.FlowId,
                            Type = RelayMessengerType.Ask,
                            FromId = tunnelTransportInfo.Local.MachineId,
                            ToId = tunnelTransportInfo.Remote.MachineId,
                            MasterId = ask.MasterId,
                        };
                        if (await SendMessage(socket, relayMessage).ConfigureAwait(false))
                        {
                            //把真正连上的节点的【已解析确定IP】写回 Host，随后 TransactionTag=ask.Info.ToJson() 把这个确定IP发给应答方(B)。
                            //这样 B 在 OnBegin 里不会因为重新解析主机名(DNS轮询)而连到不同IP，保证 A、B 落在同一个节点->同一个master进程会合。
                            if (ask.Info.Node != null)
                            {
                                ask.Info.Host = ask.Info.Node.Address.ToString();
                            }
                            return socket;
                        }
                        socket.SafeClose();
                    }
                    catch (Exception ex)
                    {
                        if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                        {
                            LoggerHelper.Instance.Error(ex);
                        }
                    }
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
            return null;
        }
        private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
            {
                LoggerHelper.Instance.Info($"【Relay】Certificate validation: {certificate?.Subject}");
                LoggerHelper.Instance.Info($"【Relay】SSL Policy Errors: {sslPolicyErrors}");
            }
            return true;
        }

        private async Task<bool> SendMessage(Socket socket, RelayMessageInfo relayMessage)
        {
            using CancellationTokenSource cts = new CancellationTokenSource(5000);
            try
            {
                byte[] sendBytes = crypto.Encode(serializer.Serialize(relayMessage));

                IMemoryOwner<byte> buffer = MemoryPool<byte>.Shared.Rent(sendBytes.Length + 5);

                buffer.Memory.Span[0] = (byte)ResolverType.Relay;

                sendBytes.Length.ToBytes(buffer.Memory.Slice(1));
                sendBytes.CopyTo(buffer.Memory.Slice(5));
                var sendMemory = buffer.Memory.Slice(0, sendBytes.Length + 5);
                await socket.SendAsync(sendMemory).ConfigureAwait(false);

                int length = await socket.ReceiveAsync(buffer.Memory.Slice(0, 1), cts.Token).ConfigureAwait(false);

                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                {
                    LoggerHelper.Instance.Debug($" relay SendMessage recv {length}->{buffer.Memory.Span[0]}");
                }
                return length == 1 && buffer.Memory.Slice(0, 1).Span.SequenceEqual(Helper.TrueArray);
            }
            catch (Exception ex)
            {
                cts.Cancel();
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                {
                    LoggerHelper.Instance.Error(ex);
                }
            }
            return false;
        }

        public virtual async Task OnBegin(TunnelTransportInfo tunnelTransportInfo)
        {
            try
            {
                if (tunnelTransportInfo.SSL && certificate == null)
                {
                    LoggerHelper.Instance.Error($"relay client {Name}->ssl Certificate not found");
                    OnConnected(null, tunnelTransportInfo);
                    await tunnelMessengerAdapter.SendConnectFail(tunnelTransportInfo).ConfigureAwait(false);
                    return;
                }

                RelayInfo relay = tunnelTransportInfo.TransactionTag.DeJson<RelayInfo>();
                await GetEndpoint(relay).ConfigureAwait(false);
                Socket socket = await ConnectServer(relay.Node).ConfigureAwait(false);
                if (socket == null)
                {
                    OnConnected(null, tunnelTransportInfo);
                    await tunnelMessengerAdapter.SendConnectFail(tunnelTransportInfo).ConfigureAwait(false);
                    return;
                }

                RelayMessageInfo relayMessage = new RelayMessageInfo
                {
                    FlowId = tunnelTransportInfo.FlowId,
                    Type = RelayMessengerType.Answer,
                    FromId = tunnelTransportInfo.Local.MachineId,
                    ToId = tunnelTransportInfo.Remote.MachineId,
                    MasterId = relay.MasterId,
                };
                if (await SendMessage(socket, relayMessage).ConfigureAwait(false))
                {
                    ITunnelConnection connection = await WaitSSL(socket, tunnelTransportInfo, relay);
                    OnConnected(connection, tunnelTransportInfo);
                    await tunnelMessengerAdapter.SendConnectSuccess(tunnelTransportInfo).ConfigureAwait(false);
                    return;
                }
                socket.SafeClose();
            }
            catch (Exception ex)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                {
                    LoggerHelper.Instance.Error(ex);
                }
            }
            OnConnected(null, tunnelTransportInfo);
            await tunnelMessengerAdapter.SendConnectFail(tunnelTransportInfo).ConfigureAwait(false);
        }
        private async Task<TunnelConnectionTcp> WaitSSL(Socket socket, TunnelTransportInfo tunnelTransportInfo, RelayInfo relayInfo)
        {
            socket.KeepAlive();
            SslStream sslStream = null;
            try
            {

                if (tunnelTransportInfo.SSL)
                {
                    sslStream = new SslStream(new NetworkStream(socket, false), false, ValidateServerCertificate, null);
                    using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(5000));
                    await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = messengerStore.Certificate,
                        EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        ClientCertificateRequired = OperatingSystem.IsAndroid(),
                    }, cts.Token).ConfigureAwait(false);
                }
                return new TunnelConnectionTcp
                {
                    Direction = TunnelDirection.Reverse,
                    ProtocolType = TunnelProtocolType.Tcp,
                    RemoteMachineId = tunnelTransportInfo.Remote.MachineId,
                    RemoteMachineName = tunnelTransportInfo.Remote.MachineName,
                    Stream = sslStream,
                    Socket = socket,
                    Mode = TunnelMode.Server,
                    IPEndPoint = (socket.RemoteEndPoint as IPEndPoint).MapToIPv4(),
                    TransactionId = tunnelTransportInfo.TransactionId,
                    TransportName = Name,
                    Type = TunnelType,
                    NodeId = relayInfo.NodeId,
                    SSL = tunnelTransportInfo.SSL,
                    BufferSize = 3,
                };
            }
            catch (Exception ex)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                {
                    LoggerHelper.Instance.Error($"relay client wait ssl {ex}");
                }
                socket?.SafeClose();
                sslStream?.Dispose();
            }
            return null;
        }


        public virtual void OnFail(TunnelTransportInfo tunnelTransportInfo)
        {
        }
        public virtual void OnSuccess(TunnelTransportInfo tunnelTransportInfo)
        {
        }

        public async Task<List<RelayServerNodeStoreInfo>> RelayTestAsync()
        {
            try
            {
                MessageResponeInfo resp = await messengerSender.SendReply(new MessageRequestWrap
                {
                    Connection = signInClientState.Connection,
                    MessengerId = (ushort)RelayMessengerIds.Nodes,
                    Timeout = 2000
                }).ConfigureAwait(false);

                if (resp.Code == MessageResponeCodes.OK)
                {
                    return serializer.Deserialize<List<RelayServerNodeStoreInfo>>(resp.Data.Span);
                }
            }
            catch (Exception)
            {
            }
            return new List<RelayServerNodeStoreInfo>();
        }


        private async Task<Socket> ConnectServer(IPEndPoint ep)
        {
            Socket socket = new Socket(ep.AddressFamily, SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            socket.KeepAlive();
            if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                LoggerHelper.Instance.Debug($"relay client connect server {ep}");

            try
            {
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(3000));
                await socket.ConnectAsync(ep, cts.Token).ConfigureAwait(false);
                return socket;
            }
            catch (Exception)
            {
                using CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(5000));
                try
                {
                    using HttpClient httpClient = new HttpClient();
                    string ip = await httpClient.GetStringAsync($"https://linker.snltty.com/ip", cts.Token).ConfigureAwait(false);
                    if (ip == ep.Address.ToString())
                    {
                        socket = new Socket(ep.AddressFamily, SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
                        socket.KeepAlive();
                        await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(ip), ep.Port), cts.Token).ConfigureAwait(false);
                        return socket;
                    }
                }
                catch (Exception)
                {
                }
            }
            return null;
        }
        private async Task GetEndpoint(RelayInfo relay)
        {
            if (string.IsNullOrWhiteSpace(relay.Host) == false)
            {
                //Host 已经是确定IP时(发起方A把连上的节点解析后的IP写进了Host)，直接构造端点，
                //避免重新走DNS(轮询)导致应答方B连到不同IP，也避免IPv6地址被按":"误解析成host:port。
                if (IPAddress.TryParse(relay.Host, out IPAddress ip))
                {
                    relay.Node = new IPEndPoint(ip, 1802);
                }
                else
                {
                    relay.Node = NetworkHelper.GetEndPoint(relay.Host, 1802);
                }
            }
            if (relay.Node == null || relay.Node.Address.Equals(IPAddress.Any) || relay.Node.Address.Equals(IPAddress.Loopback))
            {
                relay.Node = signInClientState.Connection.Address;
            }
        }
    }

    /// <summary>
    /// 中继交换数据
    /// </summary>
    public partial class RelayInfo
    {
        public string NodeId { get; set; }
        public string MasterId { get; set; }
        public IPEndPoint Node { get; set; }

        public string Host { get; set; }
    }
    public partial class RelayAskResultInfo
    {
        public RelayInfo Info { get; set; }
        public string MasterId { get; set; }
        public List<RelayServerNodeStoreInfo> Nodes { get; set; } = new List<RelayServerNodeStoreInfo>();
    }
    public sealed partial class RelayMessageInfo
    {
        public RelayMessengerType Type { get; set; }
        public ulong FlowId { get; set; }
        public string FromId { get; set; }
        public string ToId { get; set; }
        public string MasterId { get; set; }
    }
}
