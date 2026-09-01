using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using linker.messenger;
using linker.messenger.firewall;
using linker.messenger.pcp;
using linker.messenger.relay.client;
using linker.messenger.signin;
using linker.messenger.tunnel;
using linker.messenger.tunnel.client;
using linker.messenger.tuntap;
using linker.messenger.tuntap.client;
using linker.messenger.tuntap.lease;
using linker.nat;
using linker.tunnel.connection;
using linker.tunnel.transport;

namespace linker.messenger.vpn.client;

internal sealed class InMemoryCommonStore : ICommonStore
{
    public CommonModes Modes { get; private set; } = CommonModes.Client;
    public bool Installed { get; private set; } = true;
    public void SetModes(CommonModes modes) => Modes = modes;
    public void SetInstalled(bool installed) => Installed = installed;
    public void Confirm() { }
}

internal sealed class InMemoryMessengerStore : IMessengerStore, IDisposable
{
    private readonly X509Certificate2 certificate;
    public X509Certificate Certificate => certificate;
    public X509Certificate CertificateExport => certificate;

    public InMemoryMessengerStore(VpnClientOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.CertificatePem))
        {
            certificate = string.IsNullOrWhiteSpace(options.CertificateKeyPem)
                ? X509Certificate2.CreateFromPem(options.CertificatePem)
                : X509Certificate2.CreateFromEncryptedPem(options.CertificatePem, options.CertificatePassword, options.CertificateKeyPem);
        }
        else
        {
            certificate = new X509Certificate2();
        }
    }

    public void Dispose() => certificate.Dispose();
}

internal sealed class InMemorySignInClientStore : ISignInClientStore
{
    private SignInClientServerInfo server;
    private SignInClientGroupInfo[] groups;
    public SignInClientServerInfo Server => server;
    public SignInClientGroupInfo Group => groups[0];
    public SignInClientGroupInfo[] Groups => groups;
    public string Id { get; private set; }
    public string Name { get; private set; }
    public string Avatar { get; private set; } = string.Empty;
    public string[] Hosts => Server.Hosts;

    public InMemorySignInClientStore(VpnClientOptions options)
    {
        Id = options.MachineId;
        Name = options.MachineName;
        groups = [new SignInClientGroupInfo { Id = options.GroupId, Name = options.GroupName, Password = options.GroupPassword }];
        server = new SignInClientServerInfo
        {
            Host = options.Host,
            Host1 = options.BackupHost,
            Hosts = options.Hosts.Length == 0 ? new[] { options.Host, options.BackupHost }.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() : options.Hosts,
            UserId = options.UserId,
            SuperKey = options.SuperKey,
            SuperPassword = options.SuperPassword
        };
    }

    public void SetName(string value) => Name = value;
    public void SetAvatar(string value) => Avatar = value;
    public void SetGroups(SignInClientGroupInfo[] value) { if (value is { Length: > 0 }) groups = value; }
    public void SetGroupPassword(string value) => Group.Password = value;
    public void SetServer(SignInClientServerInfo value) => server = value;
    public void SetSuper(string key, string password) { Server.SuperKey = key; Server.SuperPassword = password; }
    public void SetUserId(string value) => Server.UserId = value;
    public void SetHost(string host, string backupHost) { Server.Host = host; Server.Host1 = backupHost; }
    public void SetHosts(string[] value) => Server.Hosts = value ?? [];
    public void SetId(string value) => Id = value;
    public bool Confirm() => true;
}

internal sealed class InMemoryTunnelClientStore : ITunnelClientStore
{
    private readonly ConcurrentDictionary<string, List<TunnelTransportItemInfo>> transports = new();
    public int TransportMachineIdCount => transports.Count(x => x.Value.Count > 0);
    public int RouteLevelPlus { get; private set; }
    public int PortMapPrivate { get; private set; }
    public int PortMapPublic { get; private set; }
    public IPAddress InIp { get; private set; } = IPAddress.Any;
    public TunnelPublicNetworkInfo Network { get; private set; } = new();
    public Action OnChanged { get; set; } = static () => { };

    public Task<bool> SetRouteLevelPlus(int level) { RouteLevelPlus = level; OnChanged(); return Task.FromResult(true); }
    public Task<bool> SetPortMap(int privatePort, int publicPort) { PortMapPrivate = privatePort; PortMapPublic = publicPort; OnChanged(); return Task.FromResult(true); }
    public Task<List<string>> GetTunnelTransportMachineIds() => Task.FromResult(transports.Keys.ToList());
    public Task<List<TunnelTransportItemInfo>> GetTunnelTransports(string machineId) => Task.FromResult(transports.TryGetValue(machineId, out var value) ? value : []);
    public Task<bool> SetTunnelTransports(string machineId, List<TunnelTransportItemInfo> value) { transports[machineId] = value; OnChanged(); return Task.FromResult(true); }
    public Task<bool> SetTunnelTransports(string machineId, List<ITunnelTransport> value) => SetTunnelTransports(machineId, value.Select(x => new TunnelTransportItemInfo { Name = x.Name, Label = x.Label, ProtocolType = x.ProtocolType.ToString(), Reverse = x.Reverse, DisableReverse = x.DisableReverse, SSL = x.SSL, DisableSSL = x.DisableSSL, Order = x.Order, TunnelType = x.TunnelType }).ToList());
    public Task<bool> SetNetwork(TunnelPublicNetworkInfo value) { Network = value; OnChanged(); return Task.FromResult(true); }
    public Task<bool> SetInIp(IPAddress value) { InIp = value; OnChanged(); return Task.FromResult(true); }
}

internal sealed class InMemoryRelayClientStore : IRelayClientStore
{
    public string DefaultNodeId { get; private set; } = string.Empty;
    public TunnelProtocolType DefaultProtocol { get; private set; }
    public void SetDefaultNodeId(string value) => DefaultNodeId = value;
    public void SetDefaultProtocol(TunnelProtocolType value) => DefaultProtocol = value;
    public bool Confirm() => true;
}

internal sealed class InMemoryPcpStore : IPcpStore
{
    public PcpHistoryInfo PcpHistory { get; } = new();
    public void AddHistory(ITunnelConnection connection)
    {
        var value = connection?.ToString();
        if (!string.IsNullOrWhiteSpace(value)) PcpHistory.History.Add(value);
    }
}

internal sealed class InMemoryTuntapClientStore : ITuntapClientStore
{
    public TuntapConfigInfo Info { get; }
    public InMemoryTuntapClientStore(VpnClientOptions options)
    {
        Info = new TuntapConfigInfo
        {
            IP = options.GetTunAddress(), PrefixLength = options.TunPrefixLength, Name = options.TunName,
            NetworkName = options.TunNetworkName, Mtu = options.TunMtu, MssFix = options.TunMssFix,
            Running = options.TunRunning, Switch = options.TunSwitch, VlsmStatus = options.TunVlsmStatus,
            Lans = options.TunLans, Forwards = options.TunForwards
        };
        Info.Group2IP[options.GroupId] = new TuntapGroup2IPInfo { IP = Info.IP, PrefixLength = Info.PrefixLength, Name = Info.Name, NetworkName = Info.NetworkName, Mtu = Info.Mtu, MssFix = Info.MssFix };
    }
    public void Confirm() { }
}

internal sealed class InMemoryLeaseClientStore : ILeaseClientStore
{
    private readonly ConcurrentDictionary<string, LeaseInfo> values = new();
    public InMemoryLeaseClientStore(VpnClientOptions options) { if (options.Lease is not null) values[options.GroupId] = options.Lease; }
    public LeaseInfo Get(string key) => values.TryGetValue(key, out var value) ? value : new LeaseInfo();
    public bool Set(string key, LeaseInfo info) { values[key] = info; return true; }
    public void Confirm() { }
}

internal sealed class InMemoryFirewallClientStore : IFirewallClientStore
{
    private readonly object gate = new();
    private readonly List<FirewallRuleInfo> rules;
    public LinkerFirewallState State { get; private set; }
    public InMemoryFirewallClientStore(VpnClientOptions options) { State = options.FirewallState; rules = [.. options.FirewallRules]; }
    public void SetState(LinkerFirewallState state) => State = state;
    public IEnumerable<FirewallRuleInfo> GetAll() { lock (gate) return rules.ToArray(); }
    public IEnumerable<FirewallRuleInfo> GetAll(FirewallSearchInfo search) => GetAll().Where(x => (string.IsNullOrEmpty(search.GroupId) || x.GroupId == search.GroupId) && (search.Disabled < 0 || x.Disabled == Convert.ToBoolean(search.Disabled)) && (x.Protocol & search.Protocol) != 0 && (x.Action & search.Action) != 0).OrderBy(x => x.OrderBy);
    public IEnumerable<FirewallRuleInfo> GetEnabled(string groupId) => GetAll().Where(x => !x.Disabled && x.GroupId == groupId).OrderBy(x => x.OrderBy);
    public bool Add(FirewallRuleInfo rule) { lock (gate) { rule.Id = string.IsNullOrWhiteSpace(rule.Id) ? Guid.NewGuid().ToString("N") : rule.Id; rules.RemoveAll(x => x.Id == rule.Id); rules.Add(rule); return true; } }
    public bool Add(List<FirewallRuleInfo> value) { foreach (var rule in value) Add(rule); return true; }
    public bool Remove(string id) { lock (gate) return rules.RemoveAll(x => x.Id == id) > 0; }
    public bool Remove(List<string> ids) { lock (gate) return rules.RemoveAll(x => ids.Contains(x.Id)) > 0; }
    public bool Check(FirewallCheckInfo info) { lock (gate) { foreach (var rule in rules.Where(x => info.Ids.Contains(x.Id))) rule.Checked = info.IsChecked; return true; } }
}
