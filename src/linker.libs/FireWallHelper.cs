using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace linker.libs;

public static class FireWallHelper
{
    private static string vpnRuleState = "unknown";
    public static string VpnRuleState => Volatile.Read(ref vpnRuleState);

    public static void Write(string fileName)
    {
        if (OperatingSystem.IsWindows()) ConfigureWindows(fileName, null, null);
    }

    // Retain the public overload for integrations. LAN subnets must never create broad
    // allow rules on physical interfaces; all decapsulated packets arrive through TUN.
    public static void Write(string fileName, IPAddress ip, byte prefixLength, (IPAddress ip, IPAddress mapIp, byte prefixLength)[] lans)
        => WriteVpn(fileName, ip, null);

    public static void WriteVpn(string fileName, IPAddress ip, string interfaceAlias)
    {
        if (OperatingSystem.IsWindows()) ConfigureWindows(fileName, ip, interfaceAlias);
    }

    // Input travels through environment variables, never interpolated shell commands.
    // Resolve an exact interface before changing any VPN rule; no broad fallback.
    private const string WindowsScript = """
        $ErrorActionPreference = 'Stop'
        try {
            $program = $env:LINKER_FW_PROGRAM
            $name = [IO.Path]::GetFileNameWithoutExtension($program)
            $ruleId = $env:LINKER_FW_RULE_ID
            $vpnAddress = $env:LINKER_FW_VPN_IP
            if ($vpnAddress) {
                $interfaces = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $vpnAddress -ErrorAction Stop |
                    Where-Object { -not $env:LINKER_FW_INTERFACE -or $_.InterfaceAlias -eq $env:LINKER_FW_INTERFACE })
                if ($interfaces.Count -ne 1) { throw 'VPN interface could not be identified uniquely.' }
                $vpnInterface = [System.Management.Automation.WildcardPattern]::Escape($interfaces[0].InterfaceAlias)
            }
            # These exact display names belonged to the old helper, including its broad LAN rules.
            $legacy = @($name, "$name.exe", "$name-any", "$name-tcp", "$name-udp", "$name-icmp")
            Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -cin $legacy } | Remove-NetFirewallRule -ErrorAction Stop
            Get-NetFirewallRule -Name "$ruleId.transport" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
            New-NetFirewallRule -Name "$ruleId.transport" -DisplayName "$name VPN transport" -Group 'Localtonet VPN' -Direction Inbound -Action Allow -Protocol Any -Program $program -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            if ($vpnAddress) {
                Get-NetFirewallRule -Name "$ruleId.tun" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
                New-NetFirewallRule -Name "$ruleId.tun" -DisplayName "$name VPN interface" -Group 'Localtonet VPN' -Direction Inbound -Action Allow -Protocol Any -InterfaceAlias $vpnInterface -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            }
            exit 0
        } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit 1 }
        """;

    private static void ConfigureWindows(string fileName, IPAddress ip, string interfaceAlias)
    {
        try
        {
            var start = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-EncodedCommand");
            start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(WindowsScript)));
            start.Environment["LINKER_FW_PROGRAM"] = Path.GetFullPath(fileName);
            start.Environment["LINKER_FW_RULE_ID"] = "Localtonet.Linker." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(fileName).ToUpperInvariant())))[..16];
            start.Environment["LINKER_FW_VPN_IP"] = ip?.ToString() ?? "";
            start.Environment["LINKER_FW_INTERFACE"] = interfaceAlias ?? "";
            using var process = Process.Start(start) ?? throw new IOException("Firewall helper could not start.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(15_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("Windows firewall setup timed out.");
            }
            output.GetAwaiter().GetResult();
            string failure = error.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new IOException($"Windows firewall setup failed: {failure}");
            if (ip != null) Volatile.Write(ref vpnRuleState, "applied");
        }
        catch (Exception ex)
        {
            if (ip != null) Volatile.Write(ref vpnRuleState, "failed");
            LoggerHelper.Instance.Warning($"vpn firewall os_setup_failed type={ex.GetType().Name}");
        }
    }
}
