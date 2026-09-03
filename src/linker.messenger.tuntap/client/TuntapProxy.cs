using linker.libs;
using linker.libs.timer;
using linker.messenger.channel;
using linker.messenger.pcp;
using linker.messenger.signin;
using linker.messenger.tuntap.cidr;
using linker.nat;
using linker.tun.device;
using linker.tunnel;
using linker.tunnel.connection;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;

namespace linker.messenger.tuntap.client
{
    public interface ITuntapProxyCallback
    {
        public ValueTask Close(ITunnelConnection connection);
        public ValueTask Receive(ITunnelConnection connection, ReadOnlyMemory<byte> packet);
    }

    public class TuntapProxy : Channel, ITunnelConnectionReceiveCallback
    {
        public ITuntapProxyCallback Callback { get; set; }
        protected override string TransactionId => "tuntap";

        private readonly TuntapConfigTransfer tuntapConfigTransfer;
        private readonly TuntapCidrConnectionManager tuntapCidrConnectionManager;
        private readonly TuntapCidrDecenterManager tuntapCidrDecenterManager;
        private readonly TuntapDecenter tuntapDecenter;

        //隧道建立期间（先中继后打洞，约2-3秒）到达的数据包先缓存，连接就绪后立即补发，避免首批ping丢包
        private const int PendingMaxIp = 64;
        private const int PendingMaxPacketsPerIp = 8;
        private const long PendingTtlMilliseconds = 5000;
        private readonly ConcurrentDictionary<uint, PendingConnectionPackets> pendingPackets = new();

        public TuntapProxy(ISignInClientStore signInClientStore,
            TunnelTransfer tunnelTransfer, PcpTransfer pcpTransfer,
            SignInClientTransfer signInClientTransfer, TuntapConfigTransfer tuntapConfigTransfer,
            TuntapCidrConnectionManager tuntapCidrConnectionManager, TuntapCidrDecenterManager tuntapCidrDecenterManager,
            TuntapDecenter tuntapDecenter, ChannelConnectionCaching channelConnectionCaching)
            : base(tunnelTransfer, pcpTransfer, signInClientTransfer, signInClientStore, channelConnectionCaching)
        {
            this.tuntapConfigTransfer = tuntapConfigTransfer;
            this.tuntapCidrConnectionManager = tuntapCidrConnectionManager;
            this.tuntapCidrDecenterManager = tuntapCidrDecenterManager;
            this.tuntapDecenter = tuntapDecenter;

#if DEBUG
            TimerHelper.SetIntervalLong(() =>
            {
                foreach (ITunnelConnection item in Connections.Values)
                {
                    if (item == null) continue;
                    System.Diagnostics.Debug.WriteLine($"[Chan stat] #{item.GetHashCode()} {item.RemoteMachineId} {item.TransportName}/{item.Type} connected={item.Connected} delay={item.Delay} recv={item.ReceiveBytes} send={item.SendBytes} recvBuf={item.RecvBufferRemaining} sendBuf={item.SendBufferRemaining} lastTicks={item.LastTicks.Diff()}ms");
                }
            }, 30000);
#endif
        }

        protected override void Connected(ITunnelConnection connection)
        {
            Add(connection);
            connection.BeginReceive(this, null);
            //有哪些目标IP用了相同目标隧道，更新一下
            tuntapCidrConnectionManager.Update(connection);
            //连接就绪，补发隧道建立期间缓存的数据包
            _ = FlushPending(connection);
        }

        /// <summary>
        /// 收到隧道数据，写入网卡
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="buffer"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public async Task Receive(ITunnelConnection connection, ReadOnlyMemory<byte> buffer, object state)
        {
            await Callback.Receive(connection, buffer).ConfigureAwait(false);
        }
        /// <summary>
        /// 隧道关闭
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public async Task Closed(ITunnelConnection connection, object state)
        {
            System.Diagnostics.Debug.WriteLine($"[Chan] -conn CLOSED #{connection?.GetHashCode()} {connection?.RemoteMachineId} {connection?.TransportName}/{connection?.Type}");
            //连接已释放，Connected 在释放后仍可能短暂为true，必须立刻从缓存移除，否则数据包会一直发往已释放的连接
            RemoveConnection(connection);
            tuntapCidrConnectionManager.Remove(connection);
            await Callback.Close(connection).ConfigureAwait(false);
            Version.Increment();
        }

        /// <summary>
        /// 收到网卡数据，发送给对方
        /// </summary>
        /// <param name="packet"></param>
        /// <returns></returns>
        public async Task InputPacket(LinkerTunDevicPacket packet)
        {
            //IPV4广播组播、IPV6 多播
            if ((packet.IPV4Broadcast || packet.IPV6Multicast) && tuntapConfigTransfer.Info.Multicast == false && Connections.IsEmpty == false)
            {
                await Task.WhenAll(Connections.Values.Where(c => c != null && c.Connected).Select(c => c.SendAsync(packet.Buffer, packet.Offset, packet.Length))).ConfigureAwait(false);
                return;
            }

            //IPV4+IPV6 单播
            uint ip = BinaryPrimitives.ReadUInt32BigEndian(packet.DstIp.Span[^4..]);
            if (tuntapCidrConnectionManager.TryGet(ip, out ITunnelConnection connection) && connection.Connected)
            {
                await connection.SendAsync(packet.Buffer, packet.Offset, packet.Length).ConfigureAwait(false);
                return;
            }

            System.Diagnostics.Debug.WriteLine($"[TUN Out] dst={new IPAddress(packet.DstIp.Span[^4..].ToArray())} len={packet.Length} -> NO CONNECTION (found={connection != null} connected={connection?.Connected}), queued + connecting");

            //隧道尚未建立，先把数据包缓存起来，连接就绪后补发，避免首批ping丢包
            EnqueuePending(ip, packet.Buffer, packet.Offset, packet.Length);
            await ConnectTunnel(ip).ConfigureAwait(false);

        }
        public async Task<bool> InputPacket(LinkerSrcProxyReadPacket packet)
        {
            if (tuntapCidrConnectionManager.TryGet(packet.DstAddr, out ITunnelConnection connection) && connection.Connected)
            {
                return  await connection.SendAsync(packet.Buffer, packet.Offset, packet.Length).ConfigureAwait(false);
            }
            await ConnectTunnel(packet.DstAddr).ConfigureAwait(false);
            if (tuntapCidrConnectionManager.TryGet(packet.DstAddr, out connection) && connection.Connected)
            {
                return await connection.SendAsync(packet.Buffer, packet.Offset, packet.Length).ConfigureAwait(false);
            }
            return false;
        }
        public bool TestIp(uint ip)
        {
            if (tuntapCidrConnectionManager.TryGet(ip, out ITunnelConnection connection) && connection.Connected)
            {
                return connection.ProtocolType == TunnelProtocolType.Tcp && tuntapConfigTransfer.Info.SrcProxy && tuntapDecenter.HasSwitchFlag(connection.RemoteMachineId, TuntapSwitch.SrcProxy);
            }
            _ = ConnectTunnel(ip).ConfigureAwait(false);
            return false;
        }


        /// <summary>
        /// 打洞或者中继
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        private async Task ConnectTunnel(uint ip)
        {
            ITunnelConnection connection = null;

            if (tuntapCidrDecenterManager.FindValue(ip, out string machineId,out uint dst,out uint prefix))
            {
                connection = await ConnectTunnel(machineId, TunnelProtocolType.None).ConfigureAwait(false);
            }
            if (connection != null)
            {
                tuntapCidrConnectionManager.Add(ip, connection);
            }
        }

        /// <summary>
        /// 隧道建立期间到达的数据包先缓存，连接就绪后由 FlushPending 补发，避免首批ping丢包
        /// </summary>
        private void EnqueuePending(uint ip, byte[] buffer, int offset, int length)
        {
            if (length <= 0)
            {
                return;
            }
            //整体IP数量超限时丢弃，防止内存膨胀（极端场景下的保护）
            if (pendingPackets.Count >= PendingMaxIp && pendingPackets.ContainsKey(ip) == false)
            {
                return;
            }

            byte[] copy = new byte[length];
            System.Buffer.BlockCopy(buffer, offset, copy, 0, length);

            PendingConnectionPackets queue = pendingPackets.GetOrAdd(ip, _ => new PendingConnectionPackets());
            lock (queue)
            {
                queue.LastTicks = Environment.TickCount64;
                queue.Packets.Enqueue(copy);
                //单IP数量超限时丢弃最旧的，只保留最新的若干个
                while (queue.Packets.Count > PendingMaxPacketsPerIp && queue.Packets.TryDequeue(out _))
                {
                }
            }
        }

        /// <summary>
        /// 连接就绪后补发该连接对应目标IP上缓存的数据包，并清理过期缓存
        /// </summary>
        private async Task FlushPending(ITunnelConnection connection)
        {
            if (pendingPackets.IsEmpty)
            {
                return;
            }

            long now = Environment.TickCount64;
            foreach (uint ip in pendingPackets.Keys)
            {
                if (pendingPackets.TryGetValue(ip, out PendingConnectionPackets queue) == false)
                {
                    continue;
                }
                //过期缓存直接清理，避免数据包陈旧后还补发
                if (now - queue.LastTicks > PendingTtlMilliseconds)
                {
                    pendingPackets.TryRemove(ip, out _);
                    continue;
                }
                //仅补发已就绪连接对应目标IP的数据包
                if (tuntapCidrConnectionManager.TryGet(ip, out ITunnelConnection target) == false
                    || target.Connected == false
                    || target.Equals(connection) == false)
                {
                    continue;
                }

                pendingPackets.TryRemove(ip, out _);
                byte[][] packets;
                lock (queue)
                {
                    packets = queue.Packets.ToArray();
                }
                foreach (byte[] packet in packets)
                {
                    try
                    {
                        await connection.SendAsync(packet, 0, packet.Length).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        break;
                    }
                }
            }
        }

        private sealed class PendingConnectionPackets
        {
            public long LastTicks;
            public ConcurrentQueue<byte[]> Packets { get; } = new();
        }
    }
}
