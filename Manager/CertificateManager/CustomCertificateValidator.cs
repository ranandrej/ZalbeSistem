using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;
using Common.Models;
using Manager.Audit;

namespace Manager.CertificateManager
{
    public class CustomCertificateValidator : X509CertificateValidator
    {
        private const string BANNED_CERTS_FILE = "banned_certs.xml";

        public override void Validate(X509Certificate2 certificate)
        {
            try
            {
                // 1. Učitaj banned sertifikate
                List<BannedCertificate> bannedCerts = LoadBannedCertificates();

                // 2. Proveri da li je sertifikat na banned listi
                foreach (var banned in bannedCerts)
                {
                    if (banned.SerialNumber == certificate.SerialNumber)
                    {
                        Audit.Audit.BannedCertificateDetected(certificate.Subject);
                        throw new Exception($"Certificate {certificate.Subject} is banned. Reason: {banned.Reason}");
                    }
                }

                // 3. Standardna validacija - ne dozvoljavaj self-signed
                if (certificate.Subject.Equals(certificate.Issuer))
                {
                    // Dodaj na banned listu
                    AddToBannedList(certificate.SerialNumber, certificate.Subject, "Self-signed certificate");
                    throw new Exception("Self-signed certificates are not allowed");
                }

                // 4. Proveri da li je sertifikat istekao
                if (DateTime.Now < certificate.NotBefore || DateTime.Now > certificate.NotAfter)
                {
                    AddToBannedList(certificate.SerialNumber, certificate.Subject, "Certificate expired or not yet valid");
                    throw new Exception("Certificate is expired or not yet valid");
                }

                Console.WriteLine($"[CERT-VALIDATION] Certificate {certificate.Subject} is valid");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CERT-VALIDATION-ERROR] {ex.Message}");
                throw;
            }
        }

        private List<BannedCertificate> LoadBannedCertificates()
        {
            try
            {
                if (!File.Exists(BANNED_CERTS_FILE))
                {
                    return new List<BannedCertificate>();
                }

                XmlSerializer serializer = new XmlSerializer(typeof(List<BannedCertificate>));
                using (FileStream fs = new FileStream(BANNED_CERTS_FILE, FileMode.Open))
                {
                    return (List<BannedCertificate>)serializer.Deserialize(fs);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BANNED-CERTS] Error loading banned certificates: {ex.Message}");
                return new List<BannedCertificate>();
            }
        }

        private void AddToBannedList(string serialNumber, string subject, string reason)
        {
            try
            {
                List<BannedCertificate> bannedCerts = LoadBannedCertificates();

                // Proveri da li već postoji
                bool exists = bannedCerts.Exists(bc => bc.SerialNumber == serialNumber);
                if (!exists)
                {
                    bannedCerts.Add(new BannedCertificate(serialNumber, subject, reason));
                    SaveBannedCertificates(bannedCerts);
                    Console.WriteLine($"[BANNED-CERTS] Added {subject} to banned list");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BANNED-CERTS] Error adding to banned list: {ex.Message}");
            }
        }

        private void SaveBannedCertificates(List<BannedCertificate> bannedCerts)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(List<BannedCertificate>));
            using (FileStream fs = new FileStream(BANNED_CERTS_FILE, FileMode.Create))
            {
                serializer.Serialize(fs, bannedCerts);
            }
        }
    }
}