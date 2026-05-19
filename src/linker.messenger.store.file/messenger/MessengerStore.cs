using linker.libs;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace linker.messenger.store.file.messenger
{
    public class MessengerStore : IMessengerStore
    {
        public X509Certificate Certificate => certificate;
        public X509Certificate CertificateExport => certificateExport;

        private readonly FileConfig fileConfig;

        private X509Certificate2 certificate;
        private X509Certificate2 certificateExport;

        public MessengerStore(FileConfig fileConfig)
        {
            this.fileConfig = fileConfig;

            using Stream stream =
                Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream(
                        "linker.messenger.store.file.cert.pfx");

            using MemoryStream ms = new();
            stream.CopyTo(ms);

            byte[] pfxBytes = ms.ToArray();

            X509KeyStorageFlags flags =
                X509KeyStorageFlags.Exportable |
                X509KeyStorageFlags.EphemeralKeySet;

            if (OperatingSystem.IsAndroid())
            {
                flags = X509KeyStorageFlags.Exportable;
            }

            certificate = new X509Certificate2(
                pfxBytes,
                "123456",
                flags);

            certificateExport = certificate;
        }
    }
}