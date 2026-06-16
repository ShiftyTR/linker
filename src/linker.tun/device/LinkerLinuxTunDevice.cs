using linker.libs;
using linker.libs.extends;
using Microsoft.Win32.SafeHandles;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace linker.tun.device
{
    internal sealed class LinkerLinuxTunDevice : ILinkerTunDevice
    {
        private string name = string.Empty;
        public string Name => name;
        public bool Running => safeFileHandle != null && !safeFileHandle.IsInvalid && !safeFileHandle.IsClosed;

        private string interfaceLinux = string.Empty;
        private FileStream fsRead = null;
        private FileStream fsWrite = null;
        private SafeFileHandle safeFileHandle;
        private IPAddress address;
        private byte prefixLength = 24;

        public LinkerLinuxTunDevice()
        {
        }

        public bool Setup(LinkerTunDeviceSetupInfo info, out string error)
        {
            error = string.Empty;

            name = info.Name;
            address = info.Address;
            prefixLength = info.PrefixLength;

            if (Running)
            {
                error = "Adapter already exists";
                return false;
            }

            if (!Create(out error))
            {
                return false;
            }

            if (!Open(out error))
            {
                // Open failed: destroy the interface we just created
                DestroyInterface();
                return false;
            }

            fsRead = new FileStream(safeFileHandle, FileAccess.Read, 65 * 1024, true);
            fsWrite = new FileStream(safeFileHandle, FileAccess.Write, 65 * 1024, true);
            interfaceLinux = GetLinuxInterfaceNum();
            return true;
        }

        private bool Create(out string error)
        {
            error = string.Empty;

            // Remove any stale interface left from a previous crash or unclean shutdown.
            // Safe to run even if the interface doesn't exist — commands fail silently.
            DestroyInterface();

            // Create the interface and bring it up
            CommandHelper.Linux(string.Empty, new string[]
            {
                $"ip tuntap add mode tun dev {Name}",
                $"ip addr add {address}/{prefixLength} dev {Name}",
                $"ip link set dev {Name} up"
            }, out string createError);

            // Verify using ip link show — intentionally avoids ifconfig (net-tools
            // is not installed on many minimal Linux distributions)
            string showOutput = CommandHelper.Linux(string.Empty, new string[]
            {
                $"ip link show {Name}"
            });

            if (!showOutput.Contains(Name))
            {
                error = string.IsNullOrWhiteSpace(createError)
                    ? $"Failed to create tun interface '{Name}'"
                    : createError;
                DestroyInterface();
                return false;
            }

            return true;
        }

        private bool Open(out string error)
        {
            error = string.Empty;

            SafeFileHandle handle = File.OpenHandle(
                "/dev/net/tun",
                FileMode.Open,
                FileAccess.ReadWrite,
                FileShare.ReadWrite,
                FileOptions.Asynchronous);

            if (handle.IsInvalid)
            {
                handle.Dispose();
                error = $"Failed to open /dev/net/tun, errno: {Marshal.GetLastWin32Error()}";
                return false;
            }

            int result = LinuxAPI.Ioctl(Name, handle, 1074025674);
            if (result != 0)
            {
                handle.Dispose();
                error = $"setup ioctl(TUNSETIFF) failed: result={result}, errno={Marshal.GetLastWin32Error()}";
                return false;
            }

            safeFileHandle = handle;
            return true;
        }

        // Closes only the file handles — does NOT touch the network interface.
        private void CloseHandles()
        {
            try { safeFileHandle?.Dispose(); } catch { }
            safeFileHandle = null;

            try { fsRead?.Flush(); } catch { }
            try { fsRead?.Close(); fsRead?.Dispose(); } catch { }
            fsRead = null;

            try { fsWrite?.Flush(); } catch { }
            try { fsWrite?.Close(); fsWrite?.Dispose(); } catch { }
            fsWrite = null;
        }

        // Removes the network interface — safe to call even if it doesn't exist.
        private void DestroyInterface()
        {
            CommandHelper.Linux(string.Empty, new string[]
            {
                $"ip link set dev {Name} down",
                $"ip link del {Name}",
                $"ip tuntap del mode tun dev {Name}"
            });
        }

        public void Shutdown()
        {
            CloseHandles();
            DestroyInterface();
            interfaceLinux = string.Empty;
            GC.Collect();
        }

        public void Refresh()
        {
            if (safeFileHandle == null) return;
            try
            {
                CommandHelper.Linux(string.Empty, new string[]
                {
                    $"ip link set dev {Name} up"
                });
            }
            catch { }
        }

        public void SetMssFix(int value = 0)
        {
            CommandHelper.Linux(string.Empty, new string[]
            {
                @$"iptables-save | grep -v -E -- ""-[oi] {Name}\s*.*\s* -j TCPMSS"" | iptables-restore",
            });

            if (value >= 7 && value < 1500)
            {
                string _value = value == 7 ? "--clamp-mss-to-pmtu" : $"--set-mss {value}";

                CommandHelper.Linux(string.Empty, new string[]
                {
                    $"iptables -t mangle -A INPUT -i {Name} -p tcp --syn -j TCPMSS {_value}",
                    $"iptables -t mangle -A INPUT -i {Name} -p tcp --tcp-flags SYN SYN -j TCPMSS {_value}",
                    $"iptables -t mangle -A OUTPUT -o {Name} -p tcp --syn -j TCPMSS {_value}",
                    $"iptables -t mangle -A OUTPUT -o {Name} -p tcp --tcp-flags SYN SYN -j TCPMSS {_value}",
                    $"iptables -t mangle -A FORWARD -i {Name} -o {interfaceLinux} -p tcp --syn -j TCPMSS {_value}",
                    $"iptables -t mangle -A FORWARD -i {Name} -o {interfaceLinux} -p tcp --tcp-flags SYN SYN -j TCPMSS {_value}",
                    $"iptables -t mangle -A FORWARD -i {interfaceLinux} -o {Name} -p tcp --syn -j TCPMSS {_value}",
                    $"iptables -t mangle -A FORWARD -i {interfaceLinux} -o {Name} -p tcp --tcp-flags SYN SYN -j TCPMSS {_value}",
                });
            }
        }

        public void SetMtu(int value)
        {
            string mtu = value > 0 ? value.ToString() : "1420";
            CommandHelper.Linux(string.Empty, new string[]
            {
                $"ip link set dev {Name} mtu {mtu}"
            });
        }

        public void SetNat(out string error)
        {
            error = string.Empty;
            if (address == null || address.Equals(IPAddress.Any)) return;

            try
            {
                IPAddress network = NetworkHelper.ToNetworkIP(address, NetworkHelper.ToPrefixValue(prefixLength));

                CommandHelper.Linux(string.Empty, new string[]
                {
                    $"sysctl -w net.ipv4.ip_forward=1",
                    $"sysctl -w net.ipv4.conf.{Name}.forwarding=1",
                    @$"iptables-save | grep -v -E -- ""-[oi] {Name}\s*.*\s* -j (ACCEPT|MASQUERADE|DROP|REJECT)"" | iptables-restore",
                    $"iptables -I FORWARD -i {Name} -j ACCEPT",
                    $"iptables -I FORWARD -o {Name} -j ACCEPT",
                    $"iptables -t nat -I POSTROUTING -o {Name} -j MASQUERADE",
                    $"iptables -t nat -I POSTROUTING ! -o {Name} -s {network}/{prefixLength} -j MASQUERADE",
                });
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        public void RemoveNat(out string error)
        {
            error = string.Empty;
            if (address == null || address.Equals(IPAddress.Any)) return;

            try
            {
                CommandHelper.Linux(string.Empty, new string[]
                {
                    @$"iptables-save | grep -v -E -- ""-[oi] {Name}\s*.*\s* -j (ACCEPT|MASQUERADE|DROP|REJECT)"" | iptables-restore",
                    @$"iptables-save | grep -v -E -- ""-[oi] {Name}\s*.*\s* -j TCPMSS"" | iptables-restore",
                });
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        public List<LinkerTunDeviceForwardItem> GetForward()
        {
            string str = CommandHelper.Linux(string.Empty, new string[] { $"iptables -t nat -L PREROUTING" });
            IEnumerable<LinkerTunDeviceForwardItem> lines = str.Split(Environment.NewLine)
                .Select(c => Regex.Replace(c, @"\s+", " ").Split(' '))
                .Where(c => c.Length > 0 && c[0] == "DNAT" && c[1] == "tcp")
                .Select(c =>
                {
                    IPEndPoint dist = IPEndPoint.Parse(c[^1].Replace("to:", ""));
                    int port = int.Parse(c[^2].Replace("dpt:", ""));
                    return new LinkerTunDeviceForwardItem
                    {
                        ListenAddr = IPAddress.Any,
                        ListenPort = port,
                        ConnectAddr = dist.Address,
                        ConnectPort = dist.Port
                    };
                });
            return lines.ToList();
        }

        public void AddForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            string[] commands = forwards.Where(c => c != null && c.Enable).SelectMany(c => new string[]
            {
                $"sysctl -w net.ipv4.ip_forward=1",
                $"iptables -t nat -A PREROUTING -p tcp --dport {c.ListenPort} -j DNAT --to-destination {c.ConnectAddr}:{c.ConnectPort}",
                $"iptables -t nat -A POSTROUTING -p tcp --dport {c.ConnectPort} -j MASQUERADE",
                $"iptables -t nat -A PREROUTING -p udp --dport {c.ListenPort} -j DNAT --to-destination {c.ConnectAddr}:{c.ConnectPort}",
                $"iptables -t nat -A POSTROUTING -p udp --dport {c.ConnectPort} -j MASQUERADE",
            }).ToArray();

            if (commands.Length > 0)
                CommandHelper.Linux(string.Empty, commands);
        }

        public void RemoveForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            string[] commands = forwards.Where(c => c != null && c.Enable).SelectMany(c => new string[]
            {
                $"sysctl -w net.ipv4.ip_forward=1",
                $"iptables -t nat -D PREROUTING -p tcp --dport {c.ListenPort} -j DNAT --to-destination {c.ConnectAddr}:{c.ConnectPort}",
                $"iptables -t nat -D POSTROUTING -p tcp --dport {c.ConnectPort} -j MASQUERADE",
                $"iptables -t nat -D PREROUTING -p udp --dport {c.ListenPort} -j DNAT --to-destination {c.ConnectAddr}:{c.ConnectPort}",
                $"iptables -t nat -D POSTROUTING -p udp --dport {c.ConnectPort} -j MASQUERADE",
            }).ToArray();

            if (commands.Length > 0)
                CommandHelper.Linux(string.Empty, commands);
        }

        public void AddRoute(LinkerTunDeviceRouteItem[] ips)
        {
            string[] commands = ips.Select(item =>
            {
                uint prefixValue = NetworkHelper.ToPrefixValue(item.PrefixLength);
                IPAddress network = NetworkHelper.ToNetworkIP(item.Address, prefixValue);
                return $"ip route add {network}/{item.PrefixLength} via {address} dev {Name} metric 1";
            }).ToArray();

            if (commands.Length > 0)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                    LoggerHelper.Instance.Warning($"tuntap linux add route:\r\n{string.Join("\r\n", commands)}");
                CommandHelper.Linux(string.Empty, commands);
            }
        }

        public void RemoveRoute(LinkerTunDeviceRouteItem[] ip)
        {
            string[] commands = ip.Select(item =>
            {
                uint prefixValue = NetworkHelper.ToPrefixValue(item.PrefixLength);
                IPAddress network = NetworkHelper.ToNetworkIP(item.Address, prefixValue);
                return $"ip route del {network}/{item.PrefixLength}";
            }).ToArray();

            if (commands.Length > 0)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                    LoggerHelper.Instance.Warning($"tuntap linux del route:\r\n{string.Join("\r\n", commands)}");
                CommandHelper.Linux(string.Empty, commands);
            }
        }

        private readonly byte[] buffer = new byte[128 * 1024];
        private readonly object writeLockObj = new object();

        public byte[] Read(out int length)
        {
            length = 0;
            if (safeFileHandle == null) return Helper.EmptyArray;

            length = fsRead.Read(buffer.AsSpan(4));
            length.ToBytes(buffer.AsSpan());
            length += 4;

            return buffer;
        }

        public bool Write(ReadOnlyMemory<byte> buffer)
        {
            if (safeFileHandle == null) return true;

            lock (writeLockObj)
            {
                try
                {
                    fsWrite.Write(buffer.Span);
                    fsWrite.Flush();
                }
                catch (Exception ex)
                {
                    if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                    {
                        LoggerHelper.Instance.Error(ex.Message);
                        LoggerHelper.Instance.Error(string.Join(",", buffer.ToArray()));
                    }
                }
                return true;
            }
        }

        private string GetLinuxInterfaceNum()
        {
            return CommandHelper.Linux(string.Empty, new string[]
            {
                "ip route show default | awk '{print $5}'"
            }).TrimNewLineAndWhiteSapce();
        }

        public Task<bool> CheckAvailable(bool order = false)
        {
            string output = CommandHelper.Linux(string.Empty, new string[] { $"ip link show {Name}" });
            return Task.FromResult(output.Contains("state UP"));
        }
    }
}