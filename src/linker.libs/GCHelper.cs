using linker.libs.timer;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace linker.libs
{
    public static class GCHelper
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetProcessWorkingSetSize(IntPtr proc, int min, int max);
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EmptyWorkingSet(IntPtr hProcess);
        public static void FlushMemory()
        {
            // Mobile runtimes coordinate managed and Java/native peers themselves.
            // A desktop working-set trim must not force full collections during VPN sign-in.
            if (OperatingSystem.IsAndroid() || OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
                return;

            try
            {
                GC.RefreshMemoryLimit();
            }
            catch (Exception)
            {
            }

            GC.Collect();
            GC.Collect(2, GCCollectionMode.Aggressive);

            GC.WaitForPendingFinalizers();
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, -1, -1);
                EmptyWorkingSet(Process.GetCurrentProcess().Handle);
            }
            if (LoggerHelper.Instance.LoggerLevel <= LoggerTypes.DEBUG)
                LoggerHelper.Instance.Debug($"Flush Memory");
        }
        public static void EmptyWorkingSet()
        {
            TimerHelper.SetIntervalLong(() =>
            {
                Process process = Process.GetCurrentProcess();
                if (process.WorkingSet64 / 1024 / 1024 > 200)
                {
                    FlushMemory();
                }

            }, 30000);
        }
    }
}
