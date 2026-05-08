using linker.libs;
using Org.BouncyCastle.Vless.Crypto;
using Org.BouncyCastle.Vless.OpenSsl;
using Org.BouncyCastle.Vless.Pkcs;
using Org.BouncyCastle.Vless.Security;
using Org.BouncyCastle.Vless.X509;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace linker.messenger.store.file.messenger
{
    public class MessengerStore : IMessengerStore
    {
        public System.Security.Cryptography.X509Certificates.X509Certificate Certificate => certificate;
        public System.Security.Cryptography.X509Certificates.X509Certificate CertificateExport => certificateExport;

        private readonly FileConfig fileConfig;

        private X509Certificate2 certificate;
        private X509Certificate2 certificateExport;

        public MessengerStore(FileConfig fileConfig)
        {
            this.fileConfig = fileConfig;

            using var streamPublic = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("linker.messenger.store.file.publickey.pem");
            using var streamPrivate = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("linker.messenger.store.file.privatekey.pem");

            string publicPem = new StreamReader(streamPublic).ReadToEnd();
            string privatePem = new StreamReader(streamPrivate).ReadToEnd();

            byte[] pfx = BuildPfxWithBouncyCastle(publicPem, privatePem, "temp");

            certificate = LoadCertificate(pfx, "temp");
            certificateExport = certificate;
        }

        private static X509Certificate2 LoadCertificate(byte[] pfx, string password)
        {
            X509KeyStorageFlags flags;

            if (OperatingSystem.IsAndroid() || OperatingSystem.IsIOS())
            {
                // Android/iOS: PersistKeySet desteklenmiyor, EphemeralKeySet zorunlu
                flags = X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
            }
            else if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS())
            {
                // Windows/macOS: TLS server için PersistKeySet şart
                flags = X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable;
            }
            else
            {
                // Linux ve diğerleri
                flags = X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
            }

            return new X509Certificate2(pfx, password, flags);
        }

        private static byte[] BuildPfxWithBouncyCastle(string certPem, string keyPem, string password)
        {
            var certParser = new X509CertificateParser();
            var bcCert = certParser.ReadCertificate(
                System.Text.Encoding.UTF8.GetBytes(certPem)
            );

            AsymmetricKeyParameter privateKey;
            using (var keyReader = new StringReader(keyPem))
            {
                var pemReader = new PemReader(keyReader);
                var obj = pemReader.ReadObject();
                privateKey = obj switch
                {
                    AsymmetricCipherKeyPair kp => kp.Private,
                    AsymmetricKeyParameter key => key,
                    _ => throw new InvalidOperationException($"Unexpected PEM object: {obj.GetType()}")
                };
            }

            AsymmetricKeyParameter publicKey = bcCert.GetPublicKey();
            var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

            var store = new Pkcs12StoreBuilder().Build();
            var certEntry = new X509CertificateEntry(bcCert);
            store.SetCertificateEntry("cert", certEntry);
            store.SetKeyEntry("cert", new AsymmetricKeyEntry(keyPair.Private), new[] { certEntry });

            using var ms = new MemoryStream();
            store.Save(ms, password.ToCharArray(), new SecureRandom());
            return ms.ToArray();
        }
    }
}