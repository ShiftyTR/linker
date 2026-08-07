using linker.libs;
using Microsoft.Win32.SafeHandles;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace linker.tun.device
{
    /// <summary>
    /// macOS network adapter implementation
    /// </summary>
    internal sealed class LinkerOsxTunDevice : ILinkerTunDevice
    {
        private string name = string.Empty;
        public string Name => name;
        public bool Running => safeFileHandle != null;

        private string interfaceMac = string.Empty;
        private SafeFileHandle safeFileHandle;
        private int rawFd = -1;
        private IPAddress address;
        private byte prefixLength = 24;
        private int tunUnit = -1;

        public LinkerOsxTunDevice()
        {
        }

        public bool Setup(LinkerTunDeviceSetupInfo info, out string error)
        {
            error = string.Empty;

            System.Diagnostics.Debug.WriteLine($"[TUN Setup] name={info.Name} addr={info.Address} prefix={info.PrefixLength} mtu={info.Mtu}");

            this.name = info.Name;
            this.address = info.Address;
            this.prefixLength = info.PrefixLength;

            if (Running)
            {
                error = ($"Adapter already exists");
                System.Diagnostics.Debug.WriteLine($"[TUN Setup] FAIL: already running");
                return false;
            }

            if (OpenUtunDevice(out error) == false)
            {
                System.Diagnostics.Debug.WriteLine($"[TUN Setup] FAIL OpenUtun: {error}");
                return false;
            }

            System.Diagnostics.Debug.WriteLine($"[TUN Setup] utun opened: {interfaceMac} unit={tunUnit}");

            if (ConfigureInterface(out error) == false)
            {
                System.Diagnostics.Debug.WriteLine($"[TUN Setup] FAIL ConfigureInterface: {error}");
                Shutdown();
                return false;
            }

            error = string.Empty;
            System.Diagnostics.Debug.WriteLine($"[TUN Setup] SUCCESS: {interfaceMac} running with {address}/{prefixLength}");
            return true;
        }

        private bool OpenUtunDevice(out string error)
        {
            error = string.Empty;

            try
            {
                // On macOS, utun devices are created automatically with unit numbers
                // Using -1 lets the system assign a free unit
                IntPtr ifnameBuffer = Marshal.AllocHGlobal(256);

                try
                {
                    int fd = OsxAPI.open_utun(-1, ifnameBuffer, new UIntPtr(256), out int errno);

                    if (fd < 0)
                    {
                        error = $"Failed to open utun device. Error: {errno}";
                        return false;
                    }

                    // Retrieve interface name
                    interfaceMac = Marshal.PtrToStringAnsi(ifnameBuffer);
                    if (string.IsNullOrEmpty(interfaceMac))
                    {
                        error = "Failed to get interface name";
                        return false;
                    }

                    // Extract unit number (e.g. utun5 -> 5)
                    var match = Regex.Match(interfaceMac, @"utun(\d+)");
                    if (match.Success)
                    {
                        tunUnit = int.Parse(match.Groups[1].Value);
                    }

                    // Create SafeFileHandle
                    safeFileHandle = new SafeFileHandle(new IntPtr(fd), true);
                    rawFd = fd;

                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(ifnameBuffer);
                }
            }
            catch (Exception ex)
            {
                error = $"Exception opening utun device: {ex.Message}";
                return false;
            }
        }

        private bool ConfigureInterface(out string error)
        {
            error = string.Empty;

            try
            {
                Span<byte> gatewayBytes = stackalloc byte[4];
                address.TryWriteBytes(gatewayBytes, out _);

                // On macOS, the TUN interface gateway IP (usually .1)
                gatewayBytes[3] = 1; // Set last octet to 1 (e.g., 10.18.18.1)
                IPAddress gatewayAddr = new IPAddress(gatewayBytes);

                IPAddress networkAddr = NetworkHelper.ToNetworkIP(address, NetworkHelper.ToPrefixValue(prefixLength));

                string[] commands = new string[]
                {
                    // Configure interface - use gateway as destination (point-to-point)
                    // "inet" is required on some macOS versions for explicit address family
                    $"sudo ifconfig {interfaceMac} inet {address} {gatewayAddr} netmask 255.255.255.255 up",
                    $"sudo ifconfig {interfaceMac} mtu 1420",
                    
                    // Enable IP forwarding
                    "sudo sysctl -w net.inet.ip.forwarding=1",
                    "sudo sysctl -w net.inet.ip.redirect=0",
                    
                    // Remove old routes (ignore errors)
                    $"sudo route delete -net {networkAddr}/{prefixLength} 2>/dev/null || true",
                    
                    // Add network route via interface
                    $"sudo route add -net {networkAddr}/{prefixLength} -interface {interfaceMac}",
                    
                    // Add host route for self
                    $"sudo route add -host {address} -interface {interfaceMac}",
                    
                    // Add gateway route
                    $"sudo route add -host {gatewayAddr} -interface {interfaceMac}"
                };

                string result = CommandHelper.Osx(string.Empty, commands, out error);
                System.Diagnostics.Debug.WriteLine($"[TUN Config] commands output ({result.Length} chars): {result.Substring(0, Math.Min(result.Length, 500))}");
                if (!string.IsNullOrEmpty(error))
                    System.Diagnostics.Debug.WriteLine($"[TUN Config] commands stderr: {error.Substring(0, Math.Min(error.Length, 500))}");

                // stderr here is diagnostic only (route/sysctl/ifconfig noise). Any non-empty error would be
                // treated as a setup failure by LinkerTunDeviceAdapter and would silently stop the read loop,
                // so the real verdict comes from the ifconfig verification below.
                error = string.Empty;

                // Verify interface is UP AND has the assigned IP address
                result = CommandHelper.Osx(string.Empty, new string[] { $"ifconfig {interfaceMac}" });
                System.Diagnostics.Debug.WriteLine($"[TUN Config] ifconfig {interfaceMac}: {result.Substring(0, Math.Min(result.Length, 500))}");
                
                bool isUp = result.Contains("UP");
                bool hasAddress = result.Contains(address.ToString());

                if (!isUp)
                {
                    System.Diagnostics.Debug.WriteLine($"[TUN Config] FAIL: interface not UP");
                    error = "Failed to bring interface up";
                    return false;
                }
                if (!hasAddress)
                {
                    System.Diagnostics.Debug.WriteLine($"[TUN Config] FAIL: address {address} not assigned to {interfaceMac}");
                    error = $"Failed to assign IP {address} to {interfaceMac}. sudo may have failed — ensure the process runs as root or has passwordless sudo configured.";
                    return false;
                }

                System.Diagnostics.Debug.WriteLine($"[TUN Config] OK: {interfaceMac} UP with {address}");

                // Verify routes
                string routeCheck = CommandHelper.Osx(string.Empty, new string[] { $"netstat -rn -f inet | grep {interfaceMac}" });
                System.Diagnostics.Debug.WriteLine($"[TUN Config] routes for {interfaceMac}: {routeCheck.Substring(0, Math.Min(routeCheck.Length, 500))}");

                // Verify forwarding
                string fwdCheck = CommandHelper.Osx(string.Empty, new string[] { "sysctl net.inet.ip.forwarding" });
                System.Diagnostics.Debug.WriteLine($"[TUN Config] ip.forwarding: {fwdCheck.Trim()}");

                return true;
            }
            catch (Exception ex)
            {
                error = $"Exception configuring interface: {ex.Message}";
                return false;
            }
        }

        public void Shutdown()
        {
            System.Diagnostics.Debug.WriteLine($"[TUN Shutdown] if={interfaceMac} fd={Volatile.Read(ref rawFd)}");
            try
            {
                if (!string.IsNullOrEmpty(interfaceMac))
                {
                    // Bring interface down
                    CommandHelper.Osx(string.Empty, new string[] { $"sudo ifconfig {interfaceMac} down" });
                }

                // utun is a kernel-control socket: close() alone does not wake a thread parked in read().
                int fd = Interlocked.Exchange(ref rawFd, -1);
                if (fd >= 0) shutdown(fd, SHUT_RDWR);

                safeFileHandle?.Dispose();
                safeFileHandle = null;
            }
            catch (Exception)
            {
            }

            interfaceMac = string.Empty;
            tunUnit = -1;
            GC.Collect();
        }

        public void Refresh()
        {
            if (safeFileHandle == null) return;
            System.Diagnostics.Debug.WriteLine($"[TUN Refresh] ifconfig {interfaceMac} up");
            try
            {
                CommandHelper.Osx(string.Empty, new string[] {
                    $"sudo ifconfig {interfaceMac} up"
                });
            }
            catch (Exception)
            {
            }
        }

        public void SetMssFix(int value = 0)
        {

        }
        public void SetMtu(int value)
        {
            if (!string.IsNullOrEmpty(interfaceMac))
            {
                CommandHelper.Osx(string.Empty, new string[] { $"sudo ifconfig {interfaceMac} mtu {value}" });
            }
        }

        private string GetDefaultInterface()
        {
            return CommandHelper.Osx(string.Empty, new string[] { "route get default | grep interface | awk '{print $2}'" });
        }

        public void SetNat(out string error)
        {
            error = string.Empty;
            if (address == null || address.Equals(IPAddress.Any)) return;

            try
            {
                IPAddress network = NetworkHelper.ToNetworkIP(address, NetworkHelper.ToPrefixValue(prefixLength));
                string defaultInterface = GetDefaultInterface().Trim();

                System.Diagnostics.Debug.WriteLine($"[TUN NAT] network={network}/{prefixLength} defaultIf={defaultInterface} tunIf={interfaceMac}");

                if (string.IsNullOrEmpty(defaultInterface))
                {
                    defaultInterface = "en0";
                    System.Diagnostics.Debug.WriteLine($"[TUN NAT] fallback to en0");
                }

                // Check pfctl status
                string pfStatus = CommandHelper.Osx(string.Empty, new string[] { "sudo pfctl -s info" });
                System.Diagnostics.Debug.WriteLine($"[TUN NAT] pfctl status: {pfStatus.Substring(0, Math.Min(pfStatus.Length, 300))}");

                // Basic NAT rules
                string pfRules = $@"# VPN NAT Rules
# Enable packet forwarding
set skip on lo0

# NAT outgoing traffic from VPN network
nat on {defaultInterface} from {network}/{prefixLength} to any -> ({defaultInterface})

# Allow traffic on TUN interface  
pass on {interfaceMac} all

# Allow forwarding from VPN network
pass from {network}/{prefixLength} to any keep state
pass from any to {network}/{prefixLength} keep state

# Allow ICMP (for ping)
pass inet proto icmp all
";

                string tempFile = "/tmp/vpn_pf_rules";
                File.WriteAllText(tempFile, pfRules);

                // Enable IP forwarding
                CommandHelper.Osx(string.Empty, new string[] {
                    "sudo sysctl -w net.inet.ip.forwarding=1"
                });

                // Load pfctl rules
                string pfResult = CommandHelper.Osx(string.Empty, new string[] {
                    $"sudo pfctl -f {tempFile}",
                    "sudo pfctl -e"
                }, out error);

                System.Diagnostics.Debug.WriteLine($"[TUN NAT] pfctl -f result ({pfResult.Length} chars): {pfResult.Substring(0, Math.Min(pfResult.Length, 300))}");
                if (!string.IsNullOrEmpty(error))
                    System.Diagnostics.Debug.WriteLine($"[TUN NAT] pfctl stderr: {error.Substring(0, Math.Min(error.Length, 300))}");

                try { File.Delete(tempFile); } catch { }

                // Verify pfctl state
                string rules = CommandHelper.Osx(string.Empty, new string[] { "sudo pfctl -s nat" });
                System.Diagnostics.Debug.WriteLine($"[TUN NAT] pfctl -s nat: {rules.Substring(0, Math.Min(rules.Length, 300))}");
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        public void RemoveNat(out string error)
        {
            error = string.Empty;
            try
            {
                // Disable pfctl
                CommandHelper.Osx(string.Empty, new string[] {
                    "sudo pfctl -d"
                }, out error);
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
        }

        public List<LinkerTunDeviceForwardItem> GetForward()
        {
            // On macOS, port forwarding is generally handled with pfctl
            // Simple implementation - real-world parsing may be more complex
            var forwards = new List<LinkerTunDeviceForwardItem>();

            try
            {
                string result = CommandHelper.Osx(string.Empty, new string[] { "sudo pfctl -s nat" });
                // Could parse pfctl output using regex if needed
            }
            catch (Exception)
            {
            }

            return forwards;
        }

        public void AddForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            if (forwards == null || forwards.Count == 0) return;

            try
            {
                string defaultInterface = GetDefaultInterface().Trim();
                List<string> rules = new List<string>();

                foreach (var forward in forwards.Where(f => f != null && f.Enable))
                {
                    rules.Add($"rdr on {defaultInterface} inet proto tcp from any to any port {forward.ListenPort} -> {forward.ConnectAddr} port {forward.ConnectPort}");
                }

                if (rules.Count > 0)
                {
                    string tempFile = "/tmp/vpn_forward_rules";
                    File.WriteAllText(tempFile, string.Join("\n", rules));

                    CommandHelper.Osx(string.Empty, new string[] {
                        $"sudo pfctl -f {tempFile}",
                        "sudo pfctl -e"
                    });

                    try { File.Delete(tempFile); } catch { }
                }
            }
            catch (Exception)
            {
            }
        }

        public void RemoveForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            // Removing pfctl rules usually requires reloading configuration
            try
            {
                CommandHelper.Osx(string.Empty, new string[] { "sudo pfctl -F nat" });
            }
            catch (Exception)
            {
            }
        }

        public void AddRoute(LinkerTunDeviceRouteItem[] routes)
        {
            if (routes == null || routes.Length == 0) return;

            string[] commands = routes.Select(route =>
            {
                uint prefixValue = NetworkHelper.ToPrefixValue(route.PrefixLength);
                IPAddress network = NetworkHelper.ToNetworkIP(route.Address, prefixValue);
                return $"sudo route add -net {network}/{route.PrefixLength} -interface {interfaceMac}";
            }).ToArray();

            if (commands.Length > 0)
            {
                CommandHelper.Osx(string.Empty, commands);
            }
        }

        public void RemoveRoute(LinkerTunDeviceRouteItem[] routes)
        {
            if (routes == null || routes.Length == 0) return;

            string[] commands = routes.Select(route =>
            {
                uint prefixValue = NetworkHelper.ToPrefixValue(route.PrefixLength);
                IPAddress network = NetworkHelper.ToNetworkIP(route.Address, prefixValue);
                return $"sudo route delete -net {network}/{route.PrefixLength}";
            }).ToArray();

            if (commands.Length > 0)
            {
                CommandHelper.Osx(string.Empty, commands);
            }
        }

        private readonly byte[] buffer = new byte[65 * 1024];
        private readonly object writeLockObj = new object();
        // Reusable write buffer to avoid per-packet allocation on the data path.
        // Largest standard frame: AF_BE(4) + max IP packet (65KB).
        private readonly byte[] writeBuffer = new byte[4 + 65 * 1024];

        [DllImport("libSystem.dylib", SetLastError = true)]
        private static extern IntPtr write(int fd, byte[] buf, IntPtr count);

        [DllImport("libSystem.dylib", SetLastError = true)]
        private static extern IntPtr read(int fd, byte[] buf, IntPtr count);

        [DllImport("libSystem.dylib", SetLastError = true)]
        private static extern int poll([In, Out] PollFd[] fds, uint nfds, int timeout);

        [DllImport("libSystem.dylib", SetLastError = true, EntryPoint = "shutdown")]
        private static extern int shutdown(int fd, int how);

        [StructLayout(LayoutKind.Sequential)]
        private struct PollFd
        {
            public int fd;
            public short events;
            public short revents;
        }

        private const short POLLIN = 0x0001;
        private const short POLLERR = 0x0008;
        private const short POLLHUP = 0x0010;
        private const short POLLNVAL = 0x0020;
        private const int SHUT_RDWR = 2;
        private const int EINTR = 4;

        private readonly PollFd[] pollFds = new PollFd[1];
        private int idlePolls;

        public byte[] Read(out int length)
        {
            length = 0;

            // A blocking read() on the utun socket cannot be interrupted by close(), which would wedge the
            // adapter's read loop forever across a Setup/Shutdown cycle. Poll with a timeout instead.
            int fd;
            while (true)
            {
                fd = Volatile.Read(ref rawFd);
                if (fd < 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[TUN Read] fd closed (rawFd={fd}) if={interfaceMac}");
                    return Helper.EmptyArray;
                }

                pollFds[0].fd = fd;
                pollFds[0].events = POLLIN;
                pollFds[0].revents = 0;

                int ready = poll(pollFds, 1, 200);
                if (ready < 0)
                {
                    if (Marshal.GetLastWin32Error() == EINTR) continue;
                    System.Diagnostics.Debug.WriteLine($"[TUN Read] poll failed errno={Marshal.GetLastWin32Error()} fd={fd} if={interfaceMac}");
                    return Helper.EmptyArray;
                }
                if (ready == 0)
                {
                    //空闲心跳，用来区分"读循环卡死"和"确实没有数据到达"
                    if (++idlePolls >= 150)
                    {
                        idlePolls = 0;
                        System.Diagnostics.Debug.WriteLine($"[TUN Read] idle 30s, loop alive fd={fd} if={interfaceMac}");
                    }
                    continue;
                }
                idlePolls = 0;
                if ((pollFds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[TUN Read] poll error revents=0x{pollFds[0].revents:X} fd={fd} if={interfaceMac}");
                    return Helper.EmptyArray;
                }
                break;
            }

            // UTUN: [AF(4) | IP(...)]
            int n = (int)read(fd, buffer, (IntPtr)buffer.Length);
            if (n < 5)
            {
                System.Diagnostics.Debug.WriteLine($"[TUN Read] short read n={n} errno={Marshal.GetLastWin32Error()} if={interfaceMac}");
                return Helper.EmptyArray;
            }

            // AF header BIG-ENDIAN
            uint af = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(0, 4));
            if (af != 2u && af != 30u)  // AF_INET=2, AF_INET6=30
            {
                System.Diagnostics.Debug.WriteLine($"[TUN Read] unexpected AF={af} n={n} if={interfaceMac}");
                return Helper.EmptyArray;
            }

            int payloadLen = n - 4;

            // Replace AF header with pipeline format: [LEN_LE(4) | IP]
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(0, 4), payloadLen);

            length = payloadLen + 4;
            return buffer;
        }

        public bool Write(ReadOnlyMemory<byte> packet)
        {
            int fd = Volatile.Read(ref rawFd);
            if (fd < 0)
            {
                System.Diagnostics.Debug.WriteLine($"[TUN Write] guard fail: device not open");
                return false;
            }

            lock (writeLockObj)
            {
                try
                {
                    var span = packet.Span;
                    if (span.Length < 1) return false;

                    ReadOnlySpan<byte> ipSpan;
                    string format;
                    IntPtr written;
                    int errno;

                    // 1) UTUN frame? (AF header big-endian: 0x00000002 or 0x0000001E)
                    if (span.Length >= 5)
                    {
                        uint afBe = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(0, 4));
                        if (afBe == 2u || afBe == 30u)
                        {
                            format = "UTUN";
                            written = write(fd, packet.ToArray(), (IntPtr)span.Length);
                            errno = Marshal.GetLastWin32Error();
                            return (long)written == span.Length;
                        }
                    }

                    // 2) Raw IP packet (first nibble 4 or 6)
                    byte v = (byte)(span[0] >> 4);
                    if (v == 4 || v == 6)
                    {
                        format = "rawIP";
                        ipSpan = span; // [IP]
                    }
                    else
                    {
                        // 3) [LEN_LE][IP] frame
                        format = "LEN_LE";
                        if (span.Length < 5) return false;
                        int payloadLen = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0, 4));
                        if (payloadLen <= 0 || payloadLen > span.Length - 4) return false;

                        ipSpan = span.Slice(4, payloadLen);

                        // Safety check
                        byte v2 = (byte)(ipSpan[0] >> 4);
                        if (v2 != 4 && v2 != 6) return false;
                        v = v2;
                    }

                    uint af = (v == 6) ? 30u : 2u; // AF_INET6 / AF_INET

                    // Create UTUN frame: [AF_BE(4)] + [IP]
                    int frameLen = 4 + ipSpan.Length;
                    if (frameLen > writeBuffer.Length) return false;

                    BinaryPrimitives.WriteUInt32BigEndian(writeBuffer.AsSpan(0, 4), af);
                    ipSpan.CopyTo(writeBuffer.AsSpan(4));

                    written = write(fd, writeBuffer, (IntPtr)frameLen);
                    errno = Marshal.GetLastWin32Error();
                    if ((long)written != frameLen)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TUN Write] {format} raw-write fd={fd} if={interfaceMac} frameLen={frameLen} -> wrote={(long)written} errno={errno}");
                    }
                    return (long)written == frameLen;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"TUN macOS Write failed: {ex.Message}");
                    return false;
                }
            }
        }

        public Task<bool> CheckAvailable(bool order = false)
        {
            if (string.IsNullOrEmpty(interfaceMac))
                return Task.FromResult(false);

            try
            {
                string output = CommandHelper.Osx(string.Empty, new string[] { $"ifconfig {interfaceMac}" });
                return Task.FromResult(output.Contains("UP") && output.Contains(address.ToString()));
            }
            catch (Exception)
            {
                return Task.FromResult(false);
            }
        }
    }


}
