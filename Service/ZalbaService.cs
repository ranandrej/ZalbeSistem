using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceModel;
using System.Threading;
using System.Xml.Serialization;
using Common;
using Common.Models;
using Manager;
using Manager.Audit;
// using Manager.Cryptography;  // KOMENTARISANO zbog konflikta sa System.Security.Cryptography
using Manager.Security;
using System.IdentityModel;
using Manager.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Service
{
    public class ZalbaService : IZalbaService
    {
        private const string ZALBE_FILE = "zalbe.xml";
        private const string SECRET_KEY = "ZalbeSecretKey123456789012345678";
        private static readonly object fileLock = new object();

        public bool PosaljiZalbu(byte[] encryptedZalba, byte[] digitalSignature)
        {
            string userName = GetCurrentUserName();

            try
            {
                Console.WriteLine($"[SERVICE] Received complaint from {userName}");

                // 1. Dekriptuj žalbu
                Zalba zalba = AESHelper.Decrypt(encryptedZalba, SECRET_KEY);
                zalba.PosiljaoKorisnik = userName;

                // 2. Validuj digitalni potpis
                if (!ValidateDigitalSignature(encryptedZalba, digitalSignature, userName))
                {
                    Audit.ZalbaSubmissionFailed(userName, "Invalid digital signature");
                    return false;
                }

                // 3. Proveri sadržaj žalbe - samo članovi grupe Korisnik šalju žalbe
                CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
                if (principal == null || (!principal.IsInRole("Korisnik") && !principal.IsInRole("Nadzor")))
                {
                    zalba.NedozvoljenaSadrzaj = true;
                    Audit.ZalbaSubmissionFailed(userName, "User not authorized to send complaints");
                }
                else if (ContainsForbiddenContent(zalba.Sadrzaj))
                {
                    zalba.NedozvoljenaSadrzaj = true;
                    Audit.ZalbaSubmissionFailed(userName, "Forbidden content detected");
                }

                // 4. Sačuvaj žalbu (čak i ako je nedozvoljena, za audit)
                SaveZalba(zalba);

                // 5. Pokušaj replikaciju na backup
                ReplicateToBackup(zalba);

                if (!zalba.NedozvoljenaSadrzaj)
                {
                    Audit.ZalbaSubmissionSuccess(userName);
                    Console.WriteLine($"[SERVICE] Complaint from {userName} processed successfully");
                    return true;
                }
                else
                {
                    Console.WriteLine($"[SERVICE] Complaint from {userName} rejected (forbidden content)");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Audit.ZalbaSubmissionFailed(userName, ex.Message);
                Console.WriteLine($"[SERVICE] Error processing complaint: {ex.Message}");
                return false;
            }
        }

       

     public List<string> GetZalbeZaNadzor()
    {
        string userName = GetCurrentUserName();

        try
        {
            CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
            if (principal == null || !principal.IsInRole("Nadzor"))
            {
                Audit.AuthorizationFailed(userName, "GetZalbeZaNadzor", "User not in Nadzor group");
                // Baci specifičan fault da klijent zna da nije autorizovan
                throw new FaultException("Niste autorizovani za pristup ovom resursu.");
            }

            Audit.AuthorizationSuccess(userName, "GetZalbeZaNadzor");

            List<Zalba> zalbe = LoadZalbe();
            List<string> result = new List<string>();

            foreach (var zalba in zalbe)
            {
                string status = zalba.NedozvoljenaSadrzaj ? "[NEDOZVOLJENA]" : "[OK]";
                result.Add($"{status} {zalba}");
            }

            Console.WriteLine($"[SERVICE] Returned {result.Count} complaints to {userName}");
            return result;
        }
        catch (FaultException)  // prosto samo prosledi FaultException dalje
        {
            throw;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SERVICE] Error retrieving complaints: {ex.Message}");
            // Možeš vratiti generic grešku u faultu:
            throw new FaultException("Došlo je do greške prilikom dohvatanja žalbi.");
        }
    }


    public string TestConnection()
        {
            string userName = GetCurrentUserName();
            Console.WriteLine($"[SERVICE] Test connection from {userName}");
            return $"[BACKUP-SERVICE] Test connection from {userName}";
        }

        public List<string> PretraziZalbe(string kljucnaRec)
        {
            string userName = GetCurrentUserName();

            try
            {
                CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
                if (principal == null || !principal.IsInRole("Nadzor"))
                {
                    Audit.AuthorizationFailed(userName, "PretraziZalbe", "User not in Nadzor group");
                    throw new FaultException("Niste autorizovani za pristup ovom resursu.");
                }

                Audit.AuthorizationSuccess(userName, "PretraziZalbe");

                List<Zalba> zalbe = LoadZalbe();
                IEnumerable<Zalba> filtered = zalbe;

                if (!string.IsNullOrWhiteSpace(kljucnaRec))
                {
                    string lower = kljucnaRec.ToLower();
                    filtered = zalbe.Where(z =>
                        (!string.IsNullOrEmpty(z.Sadrzaj) && z.Sadrzaj.ToLower().Contains(lower)) ||
                        (!string.IsNullOrEmpty(z.PosiljaoKorisnik) && z.PosiljaoKorisnik.ToLower().Contains(lower)));
                }

                return filtered
                    .Select(z => $"{(z.NedozvoljenaSadrzaj ? "[NEDOZVOLJENA]" : "[OK]")} {z}")
                    .ToList();
            }
            catch (FaultException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVICE] Error searching complaints: {ex.Message}");
                throw new FaultException("Došlo je do greške prilikom pretrage žalbi.");
            }
        }

        public string GetStatistikaZalbi()
        {
            string userName = GetCurrentUserName();

            try
            {
                CustomPrincipal principal = Thread.CurrentPrincipal as CustomPrincipal;
                if (principal == null || !principal.IsInRole("Nadzor"))
                {
                    Audit.AuthorizationFailed(userName, "GetStatistikaZalbi", "User not in Nadzor group");
                    throw new FaultException("Niste autorizovani za pristup ovom resursu.");
                }

                Audit.AuthorizationSuccess(userName, "GetStatistikaZalbi");

                List<Zalba> zalbe = LoadZalbe();
                int ukupno = zalbe.Count;
                int blokirane = zalbe.Count(z => z.NedozvoljenaSadrzaj);
                int dozvoljene = ukupno - blokirane;

                return $"Ukupno: {ukupno}, Dozvoljene: {dozvoljene}, Odbijene: {blokirane}";
            }
            catch (FaultException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SERVICE] Error building statistics: {ex.Message}");
                throw new FaultException("Došlo je do greške prilikom preuzimanja statistike.");
            }
        }

        private bool ValidateDigitalSignature(byte[] data, byte[] signature, string userName)
        {
            try
            {
                var serviceContext = ServiceSecurityContext.Current;
                if (serviceContext?.AuthorizationContext?.ClaimSets != null)
                {
                    foreach (var claimSet in serviceContext.AuthorizationContext.ClaimSets)
                    {
                        if (claimSet is System.IdentityModel.Claims.X509CertificateClaimSet certClaimSet)
                        {
                            var certificate = certClaimSet.X509Certificate;

                            // Koristi tvoju HashAlgorithm klasu (Manager.Cryptography)
                            return DigitalSignature.Verify(data, Manager.Cryptography.HashAlgorithm.SHA256, signature, certificate);
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SIGNATURE-VALIDATION] Error: {ex.Message}");
                return false;
            }
        }


        private bool ContainsForbiddenContent(string sadrzaj)
        {
            string[] forbiddenWords = { "bomb", "kill", "hate", "threat","ubica" };
            string lowerContent = sadrzaj.ToLower();

            foreach (string word in forbiddenWords)
            {
                if (lowerContent.Contains(word))
                {
                    return true;
                }
            }
            return false;
        }

        private void SaveZalba(Zalba zalba)
        {
            lock (fileLock)
            {
                try
                {
                    List<Zalba> zalbe = LoadZalbe();
                    zalbe.Add(zalba);

                    XmlSerializer serializer = new XmlSerializer(typeof(List<Zalba>));
                    using (FileStream fs = new FileStream(ZALBE_FILE, FileMode.Create))
                    {
                        serializer.Serialize(fs, zalbe);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SAVE-ZALBA] Error: {ex.Message}");
                    throw;
                }
            }
        }

        private List<Zalba> LoadZalbe()
        {
            try
            {
                if (!File.Exists(ZALBE_FILE))
                {
                    return new List<Zalba>();
                }

                XmlSerializer serializer = new XmlSerializer(typeof(List<Zalba>));
                using (FileStream fs = new FileStream(ZALBE_FILE, FileMode.Open))
                {
                    return (List<Zalba>)serializer.Deserialize(fs);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOAD-ZALBE] Error: {ex.Message}");
                return new List<Zalba>();
            }
        }

        private void ReplicateToBackup(Zalba zalba)
        {
            IBackupService backupClient = null;

            try
            {
                backupClient = CreateBackupClient();

                if (backupClient != null && backupClient.IsAvailable())
                {
                    byte[] encrypted = AESHelper.Encrypt(zalba, SECRET_KEY);
                    backupClient.ReplicateZalbe(new List<byte[]> { encrypted });
                    Audit.BackupReplicationSuccess(zalba.Id);
                    Console.WriteLine($"[BACKUP] Complaint {zalba.Id} replicated successfully");
                }
                else
                {
                    Audit.BackupServerDown();
                }

                // Ako je WCF proxy, zatvori konekciju pravilno
                (backupClient as ICommunicationObject)?.Close();
            }
            catch (Exception ex)
            {
                // Ako je došlo do greške, abortiraj konekciju
                (backupClient as ICommunicationObject)?.Abort();
                Audit.BackupReplicationFailed(zalba.Id);
                Console.WriteLine($"[BACKUP] Replication failed: {ex.Message}");
            }
        }
        private X509Certificate2 GetClientCertificate()
        {
            // Otvori lokalni cert store i pronađi sertifikat po imenu
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);

                // Pronađi sertifikat čije ime je CN=Korisnik (ili kako si već nazvao svoj sertifikat)
                var certs = store.Certificates.Find(X509FindType.FindBySubjectName, "Korisnik", false);

                if (certs.Count > 0)
                    return certs[0];
                else
                    throw new Exception("Client certificate not found");
            }
        }

        private IBackupService CreateBackupClient()
        {
            try
            {
                var binding = new NetTcpBinding();
                binding.Security.Mode = SecurityMode.Transport;
                binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;
                var address = new EndpointAddress(
                    new Uri("net.tcp://localhost:8002/BackupService"),
                    new DnsEndpointIdentity("backupserver") // <-- ovde navodiš CN iz sertifikata
);

                var factory = new ChannelFactory<IBackupService>(binding,
                    address);
                factory.Credentials.ClientCertificate.Certificate = GetClientCertificate();
                factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode =
                System.ServiceModel.Security.X509CertificateValidationMode.PeerOrChainTrust;

                factory.Credentials.ServiceCertificate.Authentication.RevocationMode =
                    X509RevocationMode.NoCheck;

                return factory.CreateChannel();
            }
            catch
            {
                return null;
            }
        }

        private string GetCurrentUserName()
        {
            try
            {
                return Manager.Formatter.ParseName(Thread.CurrentPrincipal.Identity.Name);
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}
