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

namespace BackupServer
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string serverName = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
                Console.WriteLine($"[BACKUP-SERVER] Starting backup server as: {serverName}");

                // Certificate binding
                NetTcpBinding binding = new NetTcpBinding();
                binding.Security.Mode = SecurityMode.Transport;
                binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;
                binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                string address = "net.tcp://localhost:8002/BackupService";
                ServiceHost host = new ServiceHost(typeof(BackupService.BackupService));
                host.AddServiceEndpoint(typeof(IBackupService), binding, address);


                // Podesi server sertifikat
                X509Certificate2 serverCert = CertManager.GetCertificateFromStorage(
                    StoreName.My, StoreLocation.LocalMachine, "backupserver");

                if (serverCert == null)
                {
                    Console.WriteLine("[ERROR] Backup server certificate 'backupserver' not found!");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    return;
                }

              
                host.Credentials.ServiceCertificate.Certificate = serverCert;

                host.Credentials.ClientCertificate.Authentication.CertificateValidationMode =
                    X509CertificateValidationMode.Custom;
                host.Credentials.ClientCertificate.Authentication.CustomCertificateValidator =
                    new CustomCertificateValidator();
                host.Credentials.ClientCertificate.Authentication.RevocationMode =
                    X509RevocationMode.NoCheck;

                host.Authorization.PrincipalPermissionMode = PrincipalPermissionMode.Custom;
                List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>();
                policies.Add(new CustomAuthorizationPolicy());
                host.Authorization.ExternalAuthorizationPolicies = policies.AsReadOnly();


                // Certificate validation
                host.Credentials.ClientCertificate.Authentication.CertificateValidationMode =
                    X509CertificateValidationMode.ChainTrust;
                host.Credentials.ClientCertificate.Authentication.RevocationMode =
                    X509RevocationMode.NoCheck;

                // Audit behavior
                ServiceSecurityAuditBehavior auditBehavior = new ServiceSecurityAuditBehavior();
                auditBehavior.AuditLogLocation = AuditLogLocation.Application;
                auditBehavior.ServiceAuthorizationAuditLevel = AuditLevel.SuccessOrFailure;

                host.Description.Behaviors.Remove<ServiceSecurityAuditBehavior>();
                host.Description.Behaviors.Add(auditBehavior);

                host.Open();
                Console.WriteLine($"[BACKUP-SERVER] Service endpoint opened at: {address}");

                Console.WriteLine("\n=== ŽALBE SYSTEM - BACKUP SERVER ===");
                Console.WriteLine("Waiting for replication requests...");
                Console.WriteLine("Press ENTER to stop the backup server...");
                Console.ReadLine();

                host.Close();
                Console.WriteLine("[BACKUP-SERVER] Backup server stopped");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BACKUP-SERVER] Error: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}