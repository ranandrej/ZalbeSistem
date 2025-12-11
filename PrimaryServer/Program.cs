using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using Common;
using Manager;
using Manager.Audit;
using Manager.CertificateManager;
using Manager.Security;
using Service;

namespace PrimaryServer
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string serverName = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
                Console.WriteLine($"[PRIMARY-SERVER] Starting server as: {serverName}");

                // Certificate binding za klijente
                NetTcpBinding clientBinding = new NetTcpBinding();
                clientBinding.Security.Mode = SecurityMode.Transport;
                clientBinding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;
                clientBinding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                string clientAddress = "net.tcp://localhost:8001/ZalbaService";
                ServiceHost clientHost = new ServiceHost(typeof(ZalbaService));
                clientHost.AddServiceEndpoint(typeof(IZalbaService), clientBinding, clientAddress);

                // Podesi server sertifikat
                X509Certificate2 serverCert = CertManager.GetCertificateFromStorage(
                    StoreName.My, StoreLocation.LocalMachine, "zalbaserver");

                if (serverCert == null)
                {
                    Console.WriteLine("[ERROR] Server certificate 'zalbaserver' not found!");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

                clientHost.Credentials.ServiceCertificate.Certificate = serverCert;

                // Custom certificate validation
                clientHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode =
                    X509CertificateValidationMode.Custom;
                clientHost.Credentials.ClientCertificate.Authentication.CustomCertificateValidator =
                    new CustomCertificateValidator();
                clientHost.Credentials.ClientCertificate.Authentication.RevocationMode =
                    X509RevocationMode.NoCheck;

                // Custom authorization sa RBAC
                clientHost.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Custom;
                List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>();
                policies.Add(new CustomAuthorizationPolicy());
                clientHost.Authorization.ExternalAuthorizationPolicies = policies.AsReadOnly();

                // Dodaj Custom Authorization Manager
               // clientHost.Authorization.ServiceAuthorizationManager = new CustomAuthorizationManager();

                // Audit behavior
                ServiceSecurityAuditBehavior auditBehavior = new ServiceSecurityAuditBehavior();
                auditBehavior.AuditLogLocation = AuditLogLocation.Application;
                auditBehavior.ServiceAuthorizationAuditLevel = AuditLevel.SuccessOrFailure;
                auditBehavior.MessageAuthenticationAuditLevel = AuditLevel.SuccessOrFailure;

                clientHost.Description.Behaviors.Remove<ServiceSecurityAuditBehavior>();
                clientHost.Description.Behaviors.Add(auditBehavior);

                clientHost.Open();
                Console.WriteLine($"[PRIMARY-SERVER] Service endpoint opened at: {clientAddress}");

                Audit.AuthenticationSuccess("Primary Server Started");

                Console.WriteLine("\n=== ŽALBE SYSTEM - PRIMARY SERVER ===");
                Console.WriteLine("Certificate-based authentication enabled");
                Console.WriteLine("Custom certificate validation active");
                Console.WriteLine("RBAC authorization implemented");
                Console.WriteLine("banned_certs.xml monitoring active");
                Console.WriteLine("Press ENTER to stop the server...");
                Console.ReadLine();

                clientHost.Close();
                Console.WriteLine("[PRIMARY-SERVER] Server stopped");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PRIMARY-SERVER] Error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}
