using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace X509ChainBug
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        /// <summary>
        /// This is a helper class used to create the certificates involved in the issue.
        /// </summary>
        private class CertificateWithKey
        {
            private readonly byte[] rawData;

            private readonly RSAParameters privateKey;

            private CertificateWithKey(byte[] rawData, RSAParameters privateKey)
            {
                this.rawData = rawData;
                this.privateKey = privateKey;
            }

            public byte[] RawData => this.rawData;

            public static CertificateWithKey CreateSelfSigned(string name)
            {
                var subjectName = new X500DistinguishedName(name);
                var notBefore = DateTimeOffset.UtcNow;
                var notAfter = DateTimeOffset.MaxValue;
                using (var rsa = new RSACryptoServiceProvider())
                {
                    var privateKey = rsa.ExportParameters(true);
                    var request = new CertificateRequest(
                        subjectName,
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                    using (var cert = request.CreateSelfSigned(notBefore, notAfter))
                    {
                        return new CertificateWithKey(cert.RawData, privateKey);
                    }
                }
            }

            public CertificateWithKey CreateCert(
                string name,
                int serialNumber)
            {
                var subjectName = new X500DistinguishedName(name);
                var notBefore = DateTimeOffset.UtcNow;
                var notAfter = DateTimeOffset.MaxValue;

                using (var certRsa = new RSACryptoServiceProvider())
                {
                    var request = new CertificateRequest(
                        subjectName,
                        certRsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    // Can only correctly handle serial numbers up 127.
                    var serialNumberArray = new [] { (byte)serialNumber };

                    using (var rootCertRsa = new RSACryptoServiceProvider())
                    {
                        rootCertRsa.ImportParameters(this.privateKey);
                        using (var rootCertificate = new X509Certificate2(this.rawData))
                        using (var rootCertWithPrivateKey = rootCertificate.CopyWithPrivateKey(rootCertRsa))
                        {
                            var cert = request.Create(rootCertWithPrivateKey, notBefore, notAfter, serialNumberArray);
                            var privateKey = certRsa.ExportParameters(true);
                            return new CertificateWithKey(cert.RawData, privateKey);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// This test reproduces the issue.
        /// </summary>
        [Test]
        public void TestReproduceSubjectNameMixup()
        {
            bool Validate(X509Certificate2 cert, params X509Certificate2[] rootCerts)
            {
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = 
                        X509VerificationFlags.AllowUnknownCertificateAuthority |
                        X509VerificationFlags.IgnoreNotTimeValid;
                    chain.ChainPolicy.ExtraStore.AddRange(rootCerts);
                    return chain.Build(cert);
                }
            }

            // We create two self signed certificates with the same subject name.
            // In practice this situation occurs when a new root certificate is created
            // because the first one has expired.
            var rootCertWithKey1 = CertificateWithKey.CreateSelfSigned("CN=test");
            var rootCertWithKey2 = CertificateWithKey.CreateSelfSigned("CN=test");

            // Create a certificate from each of the root certificates.
            var endCertWithKey1 = rootCertWithKey1.CreateCert("CN=user1", 1);
            var endCertWithKey2 = rootCertWithKey2.CreateCert("CN=user2", 2);

            using (var rootCert1 = new X509Certificate2(rootCertWithKey1.RawData))
            using (var rootCert2 = new X509Certificate2(rootCertWithKey2.RawData))
            using (var cert1 = new X509Certificate2(endCertWithKey1.RawData))
            using (var cert2 = new X509Certificate2(endCertWithKey2.RawData))
            {
                // It works to verify the certificates if the root certificates
                // that we add to the extra store is listed in a particular order
                Assert.IsTrue(Validate(cert1, rootCert1, rootCert2));
                Assert.IsTrue(Validate(cert2, rootCert2, rootCert1));

                // But switching the order of the root certificates that are added to the extra store makes it fail.
                Assert.IsTrue(Validate(cert1, rootCert2, rootCert1));
                Assert.IsTrue(Validate(cert2, rootCert1, rootCert2));
            }
        }
    }
}