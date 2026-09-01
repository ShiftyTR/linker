using System.Net;
using linker.messenger.firewall;
using linker.messenger.tuntap;
using linker.messenger.tuntap.lease;
using linker.nat;
using linker.tun.device;

namespace linker.messenger.vpn.client;

/// <summary>Primitive, persistence-free configuration for a Linker VPN client.</summary>
public sealed class VpnClientOptions
{
    public string Host { get; set; } = string.Empty;
    public string BackupHost { get; set; } = string.Empty;
    public string[] Hosts { get; set; } = [];
    public string MachineId { get; set; } = Guid.NewGuid().ToString("N");
    public string MachineName { get; set; } = Environment.MachineName;
    public string UserId { get; set; } = Guid.NewGuid().ToString("N");
    public string GroupId { get; set; } = string.Empty;
    public string GroupName { get; set; } = string.Empty;
    public string GroupPassword { get; set; } = string.Empty;
    public string SuperKey { get; set; } = string.Empty;
    public string SuperPassword { get; set; } = string.Empty;
    public string CertificatePem { get; set; } = string.Empty;
    public string CertificateKeyPem { get; set; } = string.Empty;
    public string CertificatePassword { get; set; } = string.Empty;

    public string TunAddress { get; set; } = "0.0.0.0";
    public byte TunPrefixLength { get; set; } = 24;
    public string TunName { get; set; } = "linker";
    public string TunNetworkName { get; set; } = string.Empty;
    public int TunMtu { get; set; } = 1420;
    public int TunMssFix { get; set; }
    public bool TunRunning { get; set; } = true;
    public TuntapSwitch TunSwitch { get; set; }
    public TuntapVlsmStatus TunVlsmStatus { get; set; } = TuntapVlsmStatus.OneWay;
    public List<TuntapLanInfo> TunLans { get; set; } = [];
    public List<TuntapForwardInfo> TunForwards { get; set; } = [];
    public LeaseInfo? Lease { get; set; }

    public LinkerFirewallState FirewallState { get; set; } = LinkerFirewallState.Disabled;
    public List<FirewallRuleInfo> FirewallRules { get; set; } = [];

    /// <summary>
    /// Called after the service provider is built and before stock client Use flows run.
    /// PacketTunnel can resolve LinkerTunDeviceAdapter and inject its ILinkerTunDevice here.
    /// </summary>
    public Action<VpnClientRuntime>? AfterBuild { get; set; }

    public IPAddress GetTunAddress()
    {
        if (!IPAddress.TryParse(TunAddress, out var address))
            throw new ArgumentException($"Invalid TUN address '{TunAddress}'.", nameof(TunAddress));
        return address;
    }
}

public static class VpnClientRuntimeTunExtensions
{
    public static void InjectTunDevice(this VpnClientRuntime runtime, ILinkerTunDevice device)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(device);
        runtime.GetRequiredService<linker.tun.LinkerTunDeviceAdapter>()
            .Initialize(device, runtime.GetRequiredService<linker.messenger.tuntap.client.TuntapAdapter>());
    }
}
