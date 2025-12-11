using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;

namespace Manager.Security
{
    public class CustomAuthorizationPolicy : IAuthorizationPolicy
    {
        public CustomAuthorizationPolicy()
        {
            Id = Guid.NewGuid().ToString();
        }

        public ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        public string Id { get; private set; }

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            if (!evaluationContext.Properties.TryGetValue("Identities", out object list))
                return false;

            IList<IIdentity> identities = list as IList<IIdentity>;
            if (identities == null || identities.Count == 0)
                return false;

            var identity = identities[0];

            // Izvuci sertifikat iz claimSets
            X509Certificate2 cert = null;
            foreach (var claimSet in evaluationContext.ClaimSets)
            {
                if (claimSet is X509CertificateClaimSet x509ClaimSet)
                {
                    cert = x509ClaimSet.X509Certificate;
                    break;
                }
            }

            if (cert != null)
            {
                evaluationContext.Properties["Principal"] = new CustomPrincipal(cert);
            }
            else if (identity is WindowsIdentity windowsIdentity)
            {
                evaluationContext.Properties["Principal"] = new CustomPrincipal(windowsIdentity);
            }
            else
            {
                // Odbij ili napravi fallback koji neće odobriti pristup
                evaluationContext.Properties["Principal"] = new GenericPrincipal(identity,null);
            }

            return true;
        }


          
        
    }
}