using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;


namespace CreateTestDirectoryEntries
{
    internal class Program
    {
        private static void Main()
        {
            var certCount = 0;

            // The locations we will create the users in
            var baseDNs = new List<string> {"OU = Test Users1", "OU = Test Users2"};

            var reportWriter = new ReportWriter(Constants.WarningPeriodInDays);

            reportWriter.RemoveReportFile();
            reportWriter.WriteHeader();

            using (var rootDnEntry =
                new DirectoryEntry("LDAP://" + Constants.Server + "/" + Constants.RootDn))
            {
                rootDnEntry.Username = "CN=admin,O=Red Kestrel";
                rootDnEntry.Password = "Top111Secret";
                rootDnEntry.AuthenticationType = AuthenticationTypes.None;

                rootDnEntry.RefreshCache();

                foreach (var baseDn in baseDNs)
                    // Remove entries from previous run. I do this by deleting the baseDN container
                    // and all its children. I then recreate the baseDN container.
                    // Would be easier to delete only the children, but I'm not sure how to do that.
                {
                    using (var baseDnEntry =
                        new DirectoryEntry("LDAP://" + Constants.Server + "/" + baseDn + "," + Constants.RootDn))
                    {
                        baseDnEntry.Username = "CN=admin,O=Red Kestrel";
                        baseDnEntry.Password = "Top111Secret";
                        baseDnEntry.AuthenticationType = AuthenticationTypes.None;

                        baseDnEntry.DeleteTree();
                        baseDnEntry.CommitChanges();

                        // Recreate the baseDN.
                        try
                        {
                            var objOu = rootDnEntry.Children.Add(baseDn,
                                "OrganizationalUnit");
                            objOu.CommitChanges();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Error: Create failed.");
                            Console.WriteLine("{0}", e.Message);
                            return;
                        }

                        for (var i = 0; i < Constants.NumberOfCertsToWriteInEachBase; i++)
                        {
                            try
                            {
                                var name = GenerateRandomName();

                                var r = new Random();
                                var validityPeriodInDays = r.Next(Constants.MinValidityInDays, Constants.MaxValidityDays);

                                var cert = GenerateSelfSignedCertificate(name, name, validityPeriodInDays);
                                var data = cert.RawData;

                                var userEntry = baseDnEntry.Children.Add($"CN=Test--{name}-{i}", "user");
                                userEntry.Properties["userCertificate"].Insert(0, data);
                                userEntry.CommitChanges();
                                certCount += 1;
                                reportWriter.WriteRecord(userEntry.Name, cert);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex);
                            }
                        }
                    }
                }
            }
            Console.WriteLine($"Wrote {certCount} certs to AD");
            Console.WriteLine($"{reportWriter.ExpiredCerts} EXPIRED CERTS");
            Console.WriteLine($"{reportWriter.ExpiringCerts} EXPIRING CERTS");
        }


        /// <summary>
        /// Generates a self-signed certificate that has the values passed in.
        /// </summary>
        /// <param name="subjectName">The requested subject for the certificate</param>
        /// <param name="issuerName">The requested subject for the certificate</param>
        /// <param name="validityPeriodInDays">The requested validity period for the certificate</param>
        /// <returns>An X509 certificate as an X509Certificate2 object</returns>
        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName,
            int validityPeriodInDays)

        {
            Console.WriteLine($"requested validityPeriodInDays: {validityPeriodInDays}");
            const string signatureAlgorithm = "SHA256withRSA";

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var subjectKeyPair = GeneratePublicPrivateKeyPair();
            var issuerKeyPair = subjectKeyPair;

            ISignatureFactory signatureFactory =
                new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            var certificateGenerator = new X509V3CertificateGenerator();
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, true,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            var serialNumber =
                BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            var subjectDn = new X509Name("CN=" + subjectName);
            var issuerDn = new X509Name("CN=" + issuerName);
            certificateGenerator.SetIssuerDN(issuerDn);
            certificateGenerator.SetSubjectDN(subjectDn);

            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddDays(validityPeriodInDays);

            // Add 2 hours so we still have the same validity status when we calculate it in ReportWriter;
            // and also so the counts displayed by this app match the counts when we run DirectoryCertChecker, 
            // at least for a couple of hours after running this.
            notAfter = notAfter.AddMinutes(120.0);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);
            var certificate = certificateGenerator.Generate(signatureFactory);
            var x509 = new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            x509.FriendlyName = subjectName;
            return x509;
        }

        internal static AsymmetricCipherKeyPair GeneratePublicPrivateKeyPair()
        {
            var keyGenerationParameters =
                new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048);
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(keyGenerationParameters);
            var keyPair = rsaKeyPairGenerator.GenerateKeyPair();
            return keyPair;
        }

        /// <summary>
        /// Generates a silly name by combining a randomly selected a first and second name.
        /// </summary>
        /// <returns>A silly name</returns>
        internal static string GenerateRandomName()
        {
            var random = new Random();

            var givenName = new List<string>();
            givenName.Add("Paul");
            givenName.Add("Mikhail");
            givenName.Add("Alexander");
            givenName.Add("Jose");
            givenName.Add("Wilhelm");
            givenName.Add("Emanuel");
            givenName.Add("Albert");
            givenName.Add("Otto");
            givenName.Add("Jimmy");
            givenName.Add("Ada");

            var surname = new List<string>();
            surname.Add("Turtle");
            surname.Add("Eagle");
            surname.Add("Rattlebag");
            surname.Add("Cornfoot");
            surname.Add("Good");
            surname.Add("Piggs");
            surname.Add("Duck");
            surname.Add("Dublin");
            surname.Add("Dwyer");
            surname.Add("Smart");

            return $"{givenName[random.Next(0, givenName.Count)]} {surname[random.Next(0, givenName.Count)]}";
        }
    }
}