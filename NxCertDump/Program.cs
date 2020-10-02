using System;
using System.IO;
using System.Linq;
using LibHac;
using LibHac.FsSystem;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace NxCertDump
{
    class Program
    {
        private const string ProdKeysName = "prod.keys";

        private static readonly DirectoryInfo UserHomeInfo = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        private static readonly DirectoryInfo WorkingDirectoryInfo = new DirectoryInfo(Directory.GetCurrentDirectory());
        private static readonly DirectoryInfo SwitchHomeInfo = UserHomeInfo.GetDirectory(".switch");

        private static readonly FileInfo GlobalProdSwitchKeysInfo = SwitchHomeInfo.GetFile(ProdKeysName);
        private static readonly FileInfo LocalProdSwitchKeysInfo = WorkingDirectoryInfo.GetFile(ProdKeysName);
        private static readonly FileInfo OutputPfxInfo = WorkingDirectoryInfo.GetFile("nx_tls_client_cert.pfx");


        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Pass the path to PRODINFO as the only argument");
                return;
            }

            FileInfo prodinfoPath = new FileInfo(args[0]);
            if (!prodinfoPath.Exists)
            {
                Console.WriteLine($"Provided path \"{prodinfoPath.FullName}\" doesn't exist.");
                return;
            }

            if (OutputPfxInfo.Exists)
            {
                Console.WriteLine($"Output file {OutputPfxInfo.Name} already exists.");
                return;
            }

            Keyset k;
            if (GlobalProdSwitchKeysInfo.Exists)
                k = ExternalKeyReader.ReadKeyFile(GlobalProdSwitchKeysInfo.FullName);
            else if (LocalProdSwitchKeysInfo.Exists)
                k = ExternalKeyReader.ReadKeyFile(LocalProdSwitchKeysInfo.FullName);
            else
            {
                Console.WriteLine("Keys couldn't be found. Add to ~/.switch or working directory.");
                return;
            }
            k.DeriveKeys();

            if (k.SslRsaKek.IsEmpty())
            {
                Console.WriteLine("You are missing SslRsaKek in your keys file.");
                return;
            }

            Calibration cal0;
            byte[] certBytes;
            using (Stream prodinfoFile = prodinfoPath.OpenRead())
            {
                prodinfoFile.Seek(0, SeekOrigin.Begin);
                cal0 = new Calibration(prodinfoFile);

                prodinfoFile.Seek(0x0AD0, SeekOrigin.Begin);  // seek to certificate length
                byte[] buffer = new byte[0x4];
                prodinfoFile.Read(buffer, 0, buffer.Length); // read cert length
                uint certLength = BitConverter.ToUInt32(buffer, 0);

                certBytes = new byte[certLength];
                prodinfoFile.Seek(0x0AE0, SeekOrigin.Begin); // seek to cert (should be redundant?)
                prodinfoFile.Read(certBytes, 0, (int)certLength); // read actual cert
            }

            // extract enc private modulus
            byte[] counter = cal0.SslExtKey.Take(0x10).ToArray();
            byte[] privateModulus = cal0.SslExtKey.Skip(0x10).ToArray();

            // decrypt private modulus
            new Aes128CtrTransform(k.SslRsaKek, counter).TransformBlock(privateModulus); 

            // import raw cert
            var certificate = new X509CertificateParser().ReadCertificate(certBytes);
            // import private modulus
            var privateParameter = certificate.RecoverPrivateParameter(privateModulus);

            // build PFX and add cert
            var store = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(certificate.SubjectDN.ToString(), certEntry);

            // add private key params to PFX
            AsymmetricKeyEntry privateKeyEntry = new AsymmetricKeyEntry(privateParameter);
            store.SetKeyEntry($"{certificate.SubjectDN}_key", privateKeyEntry, new[] { certEntry });

            // output PFX with password
            using (Stream pfxStream = OutputPfxInfo.Create())
                store.Save(pfxStream, "switch".ToCharArray(), new SecureRandom());

            Console.WriteLine($"Wrote to {OutputPfxInfo.FullName}");
        }
    }
}
