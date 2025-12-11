using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Xml.Serialization;
using Common;
using Common.Models;
using Manager.Cryptography;
using Manager.Audit;
using Manager;
using Manager.Security;
using System.ServiceModel;

namespace BackupService
{
    public class BackupService : IBackupService
    {
        private const string BACKUP_ZALBE_FILE = "backup_zalbe.xml";
        private const string SECRET_KEY = "ZalbeSecretKey123456789012345678";
        private static readonly object fileLock = new object();

        public void ReplicateZalbe(List<byte[]> encryptedZalbe)
        {
            string userName = GetCurrentUserName();

            try
            {
                Console.WriteLine($"[BACKUP-SERVICE] Received {encryptedZalbe.Count} complaints for replication");

                lock (fileLock)
                {
                    List<Zalba> existingZalbe = LoadBackupZalbe();

                    foreach (byte[] encryptedZalba in encryptedZalbe)
                    {
                        try
                        {
                            Zalba zalba = AESHelper.Decrypt(encryptedZalba, SECRET_KEY);

                            // Proveri da li već postoji
                            bool exists = existingZalbe.Exists(z => z.Id == zalba.Id);
                            if (!exists)
                            {
                                existingZalbe.Add(zalba);
                                Console.WriteLine($"[BACKUP-SERVICE] Replicated complaint {zalba.Id}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[BACKUP-SERVICE] Error processing complaint: {ex.Message}");
                        }
                    }

                    SaveBackupZalbe(existingZalbe);
                }

                Console.WriteLine($"[BACKUP-SERVICE] Replication completed successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BACKUP-SERVICE] Replication failed: {ex.Message}");
                throw;
            }
        }

        public bool IsAvailable()
        {
            Console.WriteLine("[BACKUP-SERVICE] Health check - server is available");
            return true;
        }

        public string TestConnection()
        {
            string userName = GetCurrentUserName();
            Console.WriteLine($"[BACKUP-SERVICE] Test connection from {userName}");
            return $"[BACKUP-SERVICE] Test connection from {userName}";
        }

        private List<Zalba> LoadBackupZalbe()
        {
            try
            {
                if (!File.Exists(BACKUP_ZALBE_FILE))
                {
                    return new List<Zalba>();
                }

                XmlSerializer serializer = new XmlSerializer(typeof(List<Zalba>));
                using (FileStream fs = new FileStream(BACKUP_ZALBE_FILE, FileMode.Open))
                {
                    return (List<Zalba>)serializer.Deserialize(fs);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BACKUP-LOAD] Error: {ex.Message}");
                return new List<Zalba>();
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


        private void SaveBackupZalbe(List<Zalba> zalbe)
        {
            try
            {
                XmlSerializer serializer = new XmlSerializer(typeof(List<Zalba>));
                using (FileStream fs = new FileStream(BACKUP_ZALBE_FILE, FileMode.Create))
                {
                    serializer.Serialize(fs, zalbe);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BACKUP-SAVE] Error: {ex.Message}");
                throw;
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
                    throw new FaultException("Niste autorizovani za pristup ovom resursu.");
                }

                Audit.AuthorizationSuccess(userName, "GetZalbeZaNadzor");

                List<Zalba> zalbe = LoadBackupZalbe();
                List<string> result = new List<string>();

                foreach (var zalba in zalbe)
                {
                    string status = zalba.NedozvoljenaSadrzaj ? "[NEDOZVOLJENA]" : "[OK]";
                    result.Add($"{status} {zalba}");
                }

                return result;
            }
            catch (FaultException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BACKUP-SERVICE] Error retrieving complaints: {ex.Message}");
                throw new FaultException("Došlo je do greške prilikom dohvatanja žalbi.");
            }
        }
        private bool ContainsForbiddenContent(string sadrzaj)
        {
            string[] forbiddenWords = { "bomb", "kill", "hate", "threat", "ubica" };
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
                    List<Zalba> zalbe = LoadBackupZalbe();
                    zalbe.Add(zalba);

                    XmlSerializer serializer = new XmlSerializer(typeof(List<Zalba>));
                    using (FileStream fs = new FileStream(BACKUP_ZALBE_FILE, FileMode.Create))
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

                List<Zalba> zalbe = LoadBackupZalbe();
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
                Console.WriteLine($"[BACKUP-SERVICE] Error searching complaints: {ex.Message}");
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

                List<Zalba> zalbe = LoadBackupZalbe();
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
                Console.WriteLine($"[BACKUP-SERVICE] Error building statistics: {ex.Message}");
                throw new FaultException("Došlo je do greške prilikom preuzimanja statistike.");
            }
        }
    }
}