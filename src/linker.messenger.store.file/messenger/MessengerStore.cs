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

            // BouncyCastle ile PFX oluştur — NCrypt'e hiç dokunmaz
            byte[] pfx = BuildPfxWithBouncyCastle(publicPem, privatePem, "temp");

            certificate = new X509Certificate2(
                pfx,
                "temp",
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable
            );
            certificateExport = certificate;
        }

        private static byte[] BuildPfxWithBouncyCastle(string certPem, string keyPem, string password)
        {
            // Cert parse
            var certParser = new X509CertificateParser();
            var bcCert = certParser.ReadCertificate(
                System.Text.Encoding.UTF8.GetBytes(certPem)
            );

            // Private key parse
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

            // Public key'i direkt cert'ten al — GetEncoded yok
            AsymmetricKeyParameter publicKey = bcCert.GetPublicKey();

            var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

            // PKCS12 store oluştur
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
