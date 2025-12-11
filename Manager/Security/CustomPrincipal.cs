using System;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using Manager.CertificateManager;
using System.ServiceModel;
using System.IdentityModel.Claims;

namespace Manager.Security
{
    public class CustomPrincipal : IPrincipal
    {
        private IIdentity identity;
        private string userGroup;

        public CustomPrincipal(X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            // Napravi GenericIdentity sa Subject-om sertifikata
            this.identity = new GenericIdentity(certificate.Subject);

            // Izvuci rolu iz sertifikata (OU polje ili slično)
            this.userGroup = CertManager.ExtractOUFromCertificate(certificate) ?? "Korisnik";
        }
        public CustomPrincipal(WindowsIdentity windowsIdentity)
        {
            identity = windowsIdentity;
            userGroup = DetermineUserGroup();
        }

        public IIdentity Identity
        {
            get { return identity; }
        }

        public bool IsInRole(string role)
        {
            return userGroup.Equals(role, StringComparison.OrdinalIgnoreCase);
        }

        private string DetermineUserGroup()
        {
            try
            {
                // Pokušaj da dobiješ sertifikat iz current context-a
                var serviceContext = ServiceSecurityContext.Current;
                if (serviceContext?.AuthorizationContext?.ClaimSets != null)
                {
                    foreach (var claimSet in serviceContext.AuthorizationContext.ClaimSets)
                    {
                        if (claimSet is X509CertificateClaimSet certClaimSet)
                        {
                            var certificate = certClaimSet.X509Certificate;
                            return CertManager.ExtractOUFromCertificate(certificate);
                        }
                    }
                }

                // Ako je WindowsIdentity, proveri grupe
                if (identity is WindowsIdentity windowsIdentity)
                {
                    foreach (IdentityReference group in windowsIdentity.Groups)
                    {
                        SecurityIdentifier sid = (SecurityIdentifier)group.Translate(typeof(SecurityIdentifier));
                        var name = sid.Translate(typeof(NTAccount));
                        string groupName = name.ToString();

                        if (groupName.Contains("Nadzor"))
                            return "Nadzor";
                        else if (groupName.Contains("Korisnik"))
                            return "Korisnik";
                    }
                }

                return "Korisnik"; // Default
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PRINCIPAL] Error determining user group: {ex.Message}");
                return "Korisnik";
            }
        }
    }

    }