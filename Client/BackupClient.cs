using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using Common;
using Manager;
using Manager.Audit;
using Manager.CertificateManager;
using Manager.Cryptography;

namespace Client
{
    public class BackupClient : ChannelFactory<IBackupService>, IBackupService, IDisposable,IZalba
    {
        private IBackupService factory;
        private X509Certificate2 clientCertificate;

        public BackupClient(NetTcpBinding binding, EndpointAddress address) : base(binding, address)
        {
            try
            {
                string clientName = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
                Console.WriteLine($"[CLIENT] Initializing client for: {clientName}");

                // Učitaj klijentski sertifikat
                clientCertificate = CertManager.GetCertificateFromStorage(
                    StoreName.My, StoreLocation.LocalMachine, "nadzorclient");

                if (clientCertificate == null)
                {
                    throw new Exception($"Client certificate for '{clientName}' not found!");
                }

                // Podesi sertifikate
                this.Credentials.ServiceCertificate.Authentication.CertificateValidationMode =
                    X509CertificateValidationMode.ChainTrust;
                this.Credentials.ServiceCertificate.Authentication.RevocationMode =
                    X509RevocationMode.NoCheck;
                this.Credentials.ClientCertificate.Certificate = clientCertificate;

                factory = this.CreateChannel();
                Console.WriteLine($"[CLIENT] Successfully connected with certificate: {clientCertificate.Subject}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error initializing: {ex.Message}");
                throw;
            }
        }

        public bool PosaljiZalbu(byte[] encryptedZalba, byte[] digitalSignature)
        {
            try
            {
                return factory.PosaljiZalbu(encryptedZalba, digitalSignature);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error sending complaint: {ex.Message}");
                return false;
            }
        }

        public System.Collections.Generic.List<string> GetZalbeZaNadzor()
        {
            try
            {
                return factory.GetZalbeZaNadzor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error getting complaints: {ex.Message}");
                throw;
            }
        }

        public System.Collections.Generic.List<string> PretraziZalbe(string kljucnaRec)
        {
            try
            {
                return factory.PretraziZalbe(kljucnaRec);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error searching complaints: {ex.Message}");
                throw;
            }
        }

        public string GetStatistikaZalbi()
        {
            try
            {
                return factory.GetStatistikaZalbi();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error getting statistics: {ex.Message}");
                throw;
            }
        }

        public string TestConnection()
        {
            try
            {
                factory.TestConnection();
                //Console.WriteLine("[BACKUP-CLIENT] Test connection successful");
                return "[BACKUP-CLIENT] Test connection successful";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Test connection failed: {ex.Message}");
                throw; // VAŽNO: prosleđuje izuzetak dalje
            }
        }

        public bool PosaljiZalbuText(string sadrzajZalbe)
        {
            try
            {
                string userName = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
                Console.WriteLine($"[CLIENT] Sending complaint from: {userName}");

                // 1. Kreiraj žalbu
                var zalba = new Common.Models.Zalba(sadrzajZalbe, userName);

                // 2. Enkriptuj AES ECB
                byte[] encryptedZalba = AESHelper.Encrypt(zalba, "ZalbeSecretKey123456789012345678");

                // 3. Digitalno potpiši
                byte[] signature = DigitalSignature.Create(encryptedZalba, HashAlgorithm.SHA256, clientCertificate);

                // 4. Pošalji na server
                bool result = PosaljiZalbu(encryptedZalba, signature);

                if (result)
                {
                    Console.WriteLine("[CLIENT] Complaint sent successfully!");
                }
                else
                {
                    Console.WriteLine("[CLIENT] Failed to send complaint.");
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Error processing complaint: {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            if (factory != null)
            {
                try
                {
                    if (factory is ICommunicationObject comm && comm.State == CommunicationState.Opened)
                    {
                        comm.Close();
                    }
                }
                catch
                {
                    // Ignore cleanup errors
                }
                factory = null;
            }

            this.Close();
        }
        public void ReplicateZalbe(List<byte[]> encryptedZalbe)
        {
            
        }

        public bool IsAvailable()
        {
            try
            {
                return factory.IsAvailable();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CLIENT] Backup availability check failed: {ex.Message}");
                return false;
            }
        }
    }
}
