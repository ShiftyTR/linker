using linker.libs;
using linker.libs.timer;
using linker.nat;
using linker.tun.device;
using linker.tun.hook;
using System.Buffers.Binary;
using System.Net;
using static linker.nat.LinkerDstMapping;

namespace linker.tun
{
    /// <summary>
    /// linker tun网卡适配器，自动选择不同平台的实现
    /// </summary>
    public sealed class LinkerTunDeviceAdapter : ILinkerSrcProxyCallback
    {
        private ILinkerTunDevice linkerTunDevice;
        private ILinkerTunDeviceCallback linkerTunDeviceCallback;
        private CancellationTokenSource cancellationTokenSource;

        private string setupError = string.Empty;
        public string SetupError => setupError;

        private string natError = string.Empty;
        public string NatError => natError;
        public bool AppNat => lanDstProxy.Running;

        private IPAddress address;
        private byte prefixLength;
        private readonly LinkerTunPacketHookLanMap lanMap = new LinkerTunPacketHookLanMap();
        private readonly LinkerTunPacketHookLanSrcProxy lanSrcProxy = new LinkerTunPacketHookLanSrcProxy();
        private readonly LinkerTunPacketHookLanDstProxy lanDstProxy = new LinkerTunPacketHookLanDstProxy();


        private readonly OperatingManager operatingManager = new OperatingManager();
        public LinkerTunDeviceStatus Status
        {
            get
            {
                if (linkerTunDevice == null) return LinkerTunDeviceStatus.Normal;

                return operatingManager.Operating
                    ? LinkerTunDeviceStatus.Operating
                    : linkerTunDevice.Running
                        ? LinkerTunDeviceStatus.Running
                        : LinkerTunDeviceStatus.Normal;
            }
        }

        private ILinkerTunPacketHook[] readHooks = [];
        private ILinkerTunPacketHook[] writeHooks = [];

        public LinkerTunDeviceAdapter()
        {
            var hooks = new ILinkerTunPacketHook[] {
                lanMap,
                lanSrcProxy,
                lanDstProxy
            };
            readHooks = [.. hooks.OrderBy(c => c.ReadLevel)];
            writeHooks = [.. hooks.OrderBy(c => c.WriteLevel)];
        }

        /// <summary>
        /// 初始化
        /// </summary>
        /// <param name="linkerTunDeviceCallback">读取数据回调</param>
        public bool Initialize(ILinkerTunDeviceCallback linkerTunDeviceCallback)
        {
            this.linkerTunDeviceCallback = linkerTunDeviceCallback;
            if (linkerTunDevice == null)
            {
                if (OperatingSystem.IsWindows())
                {
                    linkerTunDevice = new LinkerWinTunDevice();
                    return true;
                }
                else if (OperatingSystem.IsLinux())
                {
                    linkerTunDevice = new LinkerLinuxTunDevice();
                    return true;
                }

                else if (OperatingSystem.IsMacOS())
                {
                    linkerTunDevice = new LinkerOsxTunDevice();
                    return true;
                }

            }
            return false;
        }
        /// <summary>
        /// 初始化
        /// </summary>
        /// <param name="linkerTunDevice">网卡实现</param>
        /// <param name="linkerTunDeviceCallback">读取数据回调</param>
        /// <returns></returns>
        public bool Initialize(ILinkerTunDevice linkerTunDevice, ILinkerTunDeviceCallback linkerTunDeviceCallback)
        {
            this.linkerTunDevice = linkerTunDevice;
            this.linkerTunDeviceCallback = linkerTunDeviceCallback;
            return true;
        }

        public async Task<bool> Callback(LinkerSrcProxyReadPacket packet)
        {
            return await linkerTunDeviceCallback.Callback(packet);
        }
        public bool Callback(uint ip)
        {
            return linkerTunDeviceCallback.Callback(ip);
        }

        /// <summary>
        /// 开启网卡
        /// </summary>
        /// <param name="info">网卡信息</param>
        public bool Setup(LinkerTunDeviceSetupInfo info)
        {
            if (operatingManager.StartOperation() == false)
            {
                setupError = $"setup are operating";
                return false;
            }
            try
            {
                if (linkerTunDevice == null)
                {
                    setupError = $"{System.Runtime.InteropServices.RuntimeInformation.OSDescription} not support";
                    return false;
                }
                this.address = info.Address;
                this.prefixLength = info.PrefixLength;
                bool established = linkerTunDevice.Setup(info, out setupError);
                if (!established || !linkerTunDevice.Running || string.IsNullOrWhiteSpace(setupError) == false)
                {
                    if (string.IsNullOrWhiteSpace(setupError)) setupError = "The VPN device did not establish an interface.";
                    return false;
                }
                linkerTunDevice.SetMtu(info.Mtu);
                lanSrcProxy.Setup(address, prefixLength, this, ref natError);
                Read();

                return true;
            }
            catch (Exception ex)
            {
                if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                    LoggerHelper.Instance.Warning($"tuntap setup Exception {ex}");
                setupError = ex.Message;
            }
            finally
            {
                operatingManager.StopOperation();
            }
            return false;
        }
        /// <summary>
        /// 关闭网卡
        /// </summary>
        public bool Shutdown()
        {
            if (linkerTunDevice == null)
            {
                return false;
            }
            if (operatingManager.StartOperation() == false)
            {
                setupError = $"shutdown are operating";
                return false;
            }
            try
            {
                cancellationTokenSource?.Cancel();
                linkerTunDevice.Shutdown();
                lanSrcProxy.Shutdown();
            }
            catch (Exception)
            {
            }
            finally
            {
                operatingManager.StopOperation();
            }
            setupError = string.Empty;
            return true;
        }
        /// <summary>
        /// 刷新网卡
        /// </summary>
        public void Refresh()
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            linkerTunDevice.Refresh();
        }

        /// <summary>
        /// 设置系统层NAT
        /// </summary>
        public void SetNat(LinkerTunAppNatItemInfo[] items)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            if (linkerTunDevice.Running)
            {
                linkerTunDevice.SetNat(out natError);
                lanDstProxy.Setup(address, prefixLength, items, ref natError);
            }
        }
        /// <summary>
        /// 移除NAT
        /// </summary>
        public void RemoveNat()
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            natError = string.Empty;
            linkerTunDevice.RemoveNat(out string error);
            lanDstProxy.Shutdown();
        }

        public void SetMssFix(int mss)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            if (linkerTunDevice.Running)
            {
                linkerTunDevice.SetMssFix(mss);
            }

        }

        /// <summary>
        /// 获取端口转发
        /// </summary>
        /// <returns></returns>
        public List<LinkerTunDeviceForwardItem> GetForward()
        {
            if (linkerTunDevice == null)
            {
                return [];
            }
            return linkerTunDevice.GetForward();
        }
        /// <summary>
        /// 添加端口转发
        /// </summary>
        /// <param name="forwards"></param>
        public void AddForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            linkerTunDevice.AddForward(forwards);
        }
        /// <summary>
        /// 移除端口转发
        /// </summary>
        /// <param name="forwards"></param>
        public void RemoveForward(List<LinkerTunDeviceForwardItem> forwards)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            linkerTunDevice.RemoveForward(forwards);
        }

        /// <summary>
        /// 添加路由
        /// </summary>
        /// <param name="ips"></param>
        public void AddRoute(LinkerTunDeviceRouteItem[] ips)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            if (linkerTunDevice.Running)
                linkerTunDevice.AddRoute(ips);
        }
        /// <summary>
        /// 删除路由
        /// </summary>
        /// <param name="ips"></param>
        public void RemoveRoute(LinkerTunDeviceRouteItem[] ips)
        {
            if (linkerTunDevice == null)
            {
                return;
            }
            linkerTunDevice.RemoveRoute(ips);
        }

        public void AddHooks(List<ILinkerTunPacketHook> hooks)
        {
            hooks = hooks.UnionBy(this.readHooks, c => c.Name).ToList();

            readHooks = [.. hooks.OrderBy(c => c.ReadLevel)];
            writeHooks = [.. hooks.OrderBy(c => c.WriteLevel)];
        }


        private readonly SemaphoreSlim slm = new SemaphoreSlim(1);
        private void Read()
        {
            TimerHelper.Async(async () =>
            {
                cancellationTokenSource?.Cancel();
                await slm.WaitAsync().ConfigureAwait(false);
                cancellationTokenSource = new CancellationTokenSource();
                LinkerTunDevicPacket packet = new LinkerTunDevicPacket();
                while (cancellationTokenSource.IsCancellationRequested == false)
                {
                    try
                    {
                        byte[] buffer = linkerTunDevice.Read(out int length);
                        if (length == 0 || length <= 4)
                        {
                            await Task.Delay(1000);
                            continue;
                        }

                        packet.Unpacket(buffer, 0, length);
                        if (packet.DstIp.Length == 0 || packet.Version != 4) continue;

                        LinkerTunPacketHookFlags flags = ExecReadHook(packet.RawPacket);
                        if ((flags & LinkerTunPacketHookFlags.WriteBack) == LinkerTunPacketHookFlags.WriteBack)
                        {
                            linkerTunDevice.Write(packet.RawPacket);
                        }
                        if ((flags & LinkerTunPacketHookFlags.Send) == LinkerTunPacketHookFlags.Send)
                        {
                            await linkerTunDeviceCallback.Callback(packet).ConfigureAwait(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                            LoggerHelper.Instance.Warning($"tuntap read buffer Exception {ex}");
                        setupError = ex.Message;
                        await Task.Delay(1000);
                    }
                }
                slm.Release();
            });
        }
        private LinkerTunPacketHookFlags ExecReadHook(Memory<byte> rawPacket)
        {
            LinkerTunPacketHookFlags flags = LinkerTunPacketHookFlags.Next | LinkerTunPacketHookFlags.Send;
            for (int i = 0; i < readHooks.Length; i++)
            {
                (LinkerTunPacketHookFlags addFlags, LinkerTunPacketHookFlags delFlags) = readHooks[i].Read(rawPacket);
                flags |= addFlags;
                flags &= ~delFlags;
                if ((flags & LinkerTunPacketHookFlags.Next) != LinkerTunPacketHookFlags.Next)
                {
                    break;
                }
            }
            ChecksumHelper.ChecksumWithZero(rawPacket);
            return flags;
        }

        /// <summary>
        /// 写入一个TCP/IP数据包
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public async ValueTask<bool> Write(string srcId, ReadOnlyMemory<byte> buffer)
        {
            uint dstIp = VerifyPacket(buffer, out int ipOffset);

            if (Status != LinkerTunDeviceStatus.Running)
            {
                System.Diagnostics.Debug.WriteLine($"TUN Write blocked: Status={Status}, not Running");
                return false;
            }
            if (dstIp == 0)
            {
                System.Diagnostics.Debug.WriteLine($"TUN Write blocked: VerifyPacket returned 0, len={buffer.Length}");
                return false;
            }

            ReadOnlyMemory<byte> ipPacket = ipOffset > 0 ? buffer.Slice(ipOffset) : buffer;

            LinkerTunPacketHookFlags flags = await ExecWriteHook(ipPacket, dstIp, srcId).ConfigureAwait(false);
            if ((flags & LinkerTunPacketHookFlags.Write) != LinkerTunPacketHookFlags.Write)
            {
                System.Diagnostics.Debug.WriteLine($"TUN Write blocked: hook removed Write flag, flags={flags}");
                return false;
            }

            bool ok = linkerTunDevice.Write(ipPacket);
            if (!ok)
                System.Diagnostics.Debug.WriteLine($"TUN Write blocked: linkerTunDevice.Write returned false, len={ipPacket.Length}");
            return ok;
        }
        private uint VerifyPacket(ReadOnlyMemory<byte> buffer, out int ipOffset)
        {
            ipOffset = 0;
            var packet = buffer.Span;
            if (IsIpv4Packet(packet))
                return BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(16, 4));

            if (packet.Length >= 24 && BinaryPrimitives.ReadInt32LittleEndian(packet) == packet.Length - 4
                && IsIpv4Packet(packet.Slice(4)))
            {
                ipOffset = 4;
                return BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(20, 4));
            }
            return 0;
        }

        private static bool IsIpv4Packet(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 20 || (packet[0] >> 4) != 4) return false;
            int headerLength = (packet[0] & 15) * 4;
            return headerLength >= 20 && headerLength <= packet.Length
                && BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2)) == packet.Length;
        }
        private async ValueTask<LinkerTunPacketHookFlags> ExecWriteHook(ReadOnlyMemory<byte> rawPacket, uint dstIp, string srcId)
        {
            LinkerTunPacketHookFlags flags = LinkerTunPacketHookFlags.Next | LinkerTunPacketHookFlags.Write;
            for (int i = 0; i < writeHooks.Length; i++)
            {
                (LinkerTunPacketHookFlags addFlags, LinkerTunPacketHookFlags delFlags) = await writeHooks[i].WriteAsync(rawPacket, dstIp, srcId).ConfigureAwait(false);
                flags |= addFlags;
                flags &= ~delFlags;
                if ((flags & LinkerTunPacketHookFlags.Next) != LinkerTunPacketHookFlags.Next)
                {
                    break;
                }
            }
            ChecksumHelper.ChecksumWithZero(rawPacket);
            return flags;
        }

        /// <summary>
        /// 设置IP映射列表
        /// </summary>
        /// <param name="maps"></param>
        public void SetMap(DstMapInfo[] maps)
        {
            lanMap.SetMap(maps);
        }
        /// <summary>
        /// 移除映射
        /// </summary>
        public void RemoveMap()
        {
            lanMap.SetMap([]);
        }

        public async Task<bool> CheckAvailable(bool order = false)
        {
            if (linkerTunDevice == null)
            {
                return false;
            }
            return await linkerTunDevice.CheckAvailable(order);
        }

    }
}
