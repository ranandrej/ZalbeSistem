using System;
using System.Security.Cryptography.X509Certificates;

namespace Manager.CertificateManager
{
    public class CertManager
    {
        public static X509Certificate2 GetCertificateFromStorage(StoreName storeName, StoreLocation storeLocation, string subjectName)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, true);

            foreach (X509Certificate2 c in certCollection)
            {
                if (c.SubjectName.Name.StartsWith(string.Format("CN={0}", subjectName)))
                {
                    return c;
                }
            }

            store.Close();
            return null;
        }

        public static string ExtractOUFromCertificate(X509Certificate2 certificate)
        {
            try
            {
                string subject = certificate.Subject;
                string[] parts = subject.Split(',');

                foreach (string part in parts)
                {
                    string trimmedPart = part.Trim();
                    if (trimmedPart.StartsWith("OU="))
                    {
                        return trimmedPart.Substring(3);
                    }
                }
                return "Korisnik"; // Default
            }
            catch
            {
                return "Korisnik";
            }
        }
    }
}