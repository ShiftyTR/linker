using linker.libs;
using linker.libs.timer;
using linker.messenger.relay.server;
using linker.messenger.signin;
using linker.tunnel.transport;
using System.Net;
using System.Net.NetworkInformation;

namespace linker.messenger.relay.client
{
    /// <summary>
    /// 中继
    /// </summary>
    public sealed class RelayClientTestTransfer
    {
        private readonly TransportRelay transportRelay;
        private readonly SignInClientState signInClientState;

        public List<RelayServerNodeStoreInfo> Nodes { get; private set; } = new List<RelayServerNodeStoreInfo>();

        public RelayClientTestTransfer(TransportRelay transportRelay, SignInClientState signInClientState)
        {
            this.transportRelay = transportRelay;
            this.signInClientState = signInClientState;

            TestTask();
        }


        private readonly LastTicksManager lastTicksManager = new LastTicksManager();
        public void Subscribe()
        {
            lastTicksManager.Update();
        }
        private async Task TaskRelay()
        {
            try
            {
                Nodes = await transportRelay.RelayTestAsync().ConfigureAwait(false);
                var tasks = Nodes.Select(async (c) =>
                {
                    try
                    {
                        IPEndPoint ep = NetworkHelper.GetEndPoint(c.Host, 1802);
                        IPAddress ip = ep.Address.Equals(IPAddress.Any) || ep.Address.Equals(IPAddress.Loopback) ? signInClientState.Connection.Address.Address : ep.Address;

                        using Ping ping = new Ping();
                        var resp = await ping.SendPingAsync(ip, 1000);
                        c.Delay = resp.Status == IPStatus.Success ? (int)resp.RoundtripTime : -1;
                    }
                    catch (Exception)
                    {
                    }
                });
                await Task.WhenAll(tasks).ConfigureAwait(false);

                //把测速结果回写到中继传输层，供发起方(A)在 ConnectNodeServer 选最近节点；
                //应答方(B)不参与选择，只跟随 A 通过 TransactionTag 指定的节点。
                transportRelay.UpdateNodeDelays(Nodes
                    .Where(c => string.IsNullOrWhiteSpace(c.NodeId) == false)
                    .Select(c => new KeyValuePair<string, int>(c.NodeId, c.Delay)));
            }
            catch (Exception)
            {
            }
        }
        private void TestTask()
        {
            TimerHelper.SetIntervalLong(async () =>
            {
                if ((lastTicksManager.DiffLessEqual(3000) || Nodes.Count <= 0) && signInClientState.Connected)
                {
                    await TaskRelay().ConfigureAwait(false);
                }
            }, 3000);
        }

    }
}