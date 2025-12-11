using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using Manager;
using Manager.CertificateManager;

namespace Client
{
    using System;
    using System.Collections.Generic;
    using System.Security.Principal;
    using System.ServiceModel;
    using System.Security.Cryptography.X509Certificates;
    using Common;
    using System.Net.Security;
    using System.Threading;

    namespace ZalbaClientApp
    {
        class Program
        {
            static void Main(string[] args)
            {
                try
                {
                    string clientName = Formatter.ParseName(WindowsIdentity.GetCurrent().Name);
                    Console.WriteLine($"[CLIENT-APP] Starting client as: {clientName}");

                    // Setup binding
                    NetTcpBinding binding = new NetTcpBinding();
                    binding.Security.Mode = SecurityMode.Transport;
                    binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;
                    binding.Security.Transport.ProtectionLevel = ProtectionLevel.EncryptAndSign;

                    // Primarni endpoint
                    X509Certificate2 serverCert1 = CertManager.GetCertificateFromStorage(
                        StoreName.TrustedPeople, StoreLocation.LocalMachine, "zalbaserver");

                    EndpointAddress primaryAddress = new EndpointAddress(
                        new Uri("net.tcp://localhost:8001/ZalbaService"),
                        new X509CertificateEndpointIdentity(serverCert1));

                    // Backup endpoint
                    X509Certificate2 backupCert = CertManager.GetCertificateFromStorage(
                        StoreName.TrustedPeople, StoreLocation.LocalMachine, "backupserver");

                    EndpointAddress backupAddress = new EndpointAddress(
                        new Uri("net.tcp://localhost:8002/BackupService"),
                        new X509CertificateEndpointIdentity(backupCert));

                    IZalba primaryClient = new ZalbaClient(binding, primaryAddress);
                    IZalba backupClient = new BackupClient(binding, backupAddress);
                    IZalba proxy = null;
                    bool connectedToPrimary = false;

                    void ConnectToPrimary()
                    {
                        try
                        {
                            primaryClient.TestConnection();
                            proxy = primaryClient;
                            connectedToPrimary = true;
                            Console.WriteLine("[INFO] Povezan na PRIMARNI server.");
                        }
                        catch
                        {
                            throw;
                        }
                    }

                    void ConnectToBackup()
                    {
                        try
                        {
                            backupClient.TestConnection();
                            proxy = backupClient;
                            connectedToPrimary = false;
                            Console.WriteLine("[INFO] Povezan na BACKUP server.");
                        }
                        catch
                        {
                            throw;
                        }
                    }

                    // Prvo inicijalno povezivanje
                    try
                    {
                        ConnectToPrimary();
                    }
                    catch
                    {
                        Console.WriteLine("[WARN] Neuspešna konekcija na PRIMARNI. Pokušavam BACKUP...");
                        try
                        {
                            ConnectToBackup();
                        }
                        catch
                        {
                            Console.WriteLine("[ERROR] Nije moguće povezati se ni na jedan server.");
                            Console.ReadKey();
                            return;
                        }
                    }

                    bool lastConnectedToPrimary = connectedToPrimary;

                    var healthCheckThread = new Thread(() =>
                    {
                        while (true)
                        {
                            try
                            {
                                if (connectedToPrimary)
                                {
                                    primaryClient.TestConnection();
                                }
                                else
                                {
                                    backupClient.TestConnection();
                                }

                                // Ako se stanje veze promenilo u odnosu na prethodno
                                if (connectedToPrimary != lastConnectedToPrimary)
                                {
                                    lastConnectedToPrimary = connectedToPrimary;

                                    Console.WriteLine(connectedToPrimary
                                        ? "[INFO] Povezan na PRIMARNI server."
                                        : "[INFO] Povezan na BACKUP server.");
                                }
                            }
                            catch
                            {
                                if (connectedToPrimary)
                                {
                                    Console.WriteLine("[WARN] Veza sa PRIMARNIM serverom je pala. Prelazim na BACKUP...");
                                    try
                                    {
                                        ConnectToBackup();
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[ERROR] Nije moguće povezati se na BACKUP server.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("[WARN] Veza sa BACKUP serverom je pala. Pokušavam ponovo na PRIMARNI...");
                                    try
                                    {
                                        ConnectToPrimary();
                                    }
                                    catch
                                    {
                                        Console.WriteLine("[ERROR] Nije moguće povezati se na PRIMARNI server.");
                                    }
                                }
                            }
                            Thread.Sleep(6000);
                        }
                    });
                    healthCheckThread.IsBackground = true;
                    healthCheckThread.Start();



                    // Glavni meni
                    while (true)
                    {
                        Console.WriteLine("\n=== ŽALBE SYSTEM - CLIENT ===");
                        Console.WriteLine("1. Pošalji žalbu");
                        Console.WriteLine("2. Prikaži žalbe (samo Nadzor)");
                        Console.WriteLine("3. Pretraži žalbe (samo Nadzor)");
                        Console.WriteLine("4. Prikaži statistiku žalbi (samo Nadzor)");
                        Console.WriteLine("5. Test konekcije");
                        Console.WriteLine("6. Izlaz");
                        Console.Write("Izaberite opciju: ");

                        string choice = Console.ReadLine();

                        switch (choice)
                        {
                            case "1":
                                PosaljiZalbu(proxy);
                                break;
                            case "2":
                                PrikaziZalbe(proxy);
                                break;
                            case "3":
                                PretraziZalbe(proxy);
                                break;
                            case "4":
                                PrikaziStatistiku(proxy);
                                break;
                            case "5":
                                TestKonekcija(proxy);
                                break;
                            case "6":
                                Console.WriteLine("Izlazim...");
                                return;
                            default:
                                Console.WriteLine("Nevaljan izbor!");
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[CLIENT-APP] Error: {ex.Message}");
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                }
            }

            private static void PosaljiZalbu(IZalba proxy)
            {
                try
                {
                    Console.Write("Unesite sadržaj žalbe: ");
                    string sadrzaj = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(sadrzaj))
                    {
                        Console.WriteLine("Sadržaj žalbe ne može biti prazan!");
                        return;
                    }

                    bool success = proxy.PosaljiZalbuText(sadrzaj);

                    Console.WriteLine(success
                        ? "✓ Žalba je uspešno poslata!"
                        : "✗ Slanje žalbe nije uspelo!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Greška pri slanju žalbe: {ex.Message}");
                }
            }

            private static void PrikaziZalbe(IZalba proxy)
            {
                try
                {
                    var zalbe = proxy.GetZalbeZaNadzor();

                    Console.WriteLine($"\n=== LISTA ŽALBI ({zalbe.Count}) ===");

                    if (zalbe.Count == 0)
                    {
                        Console.WriteLine("Nema žalbi u sistemu.");
                    }
                    else
                    {
                        for (int i = 0; i < zalbe.Count; i++)
                        {
                            Console.WriteLine($"{i + 1}. {zalbe[i]}");
                        }
                    }
                }
                catch (FaultException)
                {
                    Console.WriteLine("✗ Nemate dozvolu za pristup ovoj funkciji. (Niste član grupe Nadzor)");
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine($"✗ Nemate dozvolu: {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Greška pri preuzimanju žalbi: {ex.Message}");
                }
            }

            private static void PretraziZalbe(IZalba proxy)
            {
                try
                {
                    Console.Write("Unesite ključnu reč za pretragu: ");
                    string kljucnaRec = Console.ReadLine();

                    var rezultati = proxy.PretraziZalbe(kljucnaRec);

                    Console.WriteLine($"\n=== REZULTATI PRETRAGE ({rezultati.Count}) ===");
                    if (rezultati.Count == 0)
                    {
                        Console.WriteLine("Nema pronađenih žalbi.");
                    }
                    else
                    {
                        for (int i = 0; i < rezultati.Count; i++)
                        {
                            Console.WriteLine($"{i + 1}. {rezultati[i]}");
                        }
                    }
                }
                catch (FaultException)
                {
                    Console.WriteLine("✗ Nemate dozvolu za pristup ovoj funkciji. (Niste član grupe Nadzor)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Greška pri pretrazi žalbi: {ex.Message}");
                }
            }

            private static void PrikaziStatistiku(IZalba proxy)
            {
                try
                {
                    string statistika = proxy.GetStatistikaZalbi();
                    Console.WriteLine($"\n=== STATISTIKA ŽALBI ===\n{statistika}");
                }
                catch (FaultException)
                {
                    Console.WriteLine("✗ Nemate dozvolu za pristup ovoj funkciji. (Niste član grupe Nadzor)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Greška pri preuzimanju statistike: {ex.Message}");
                }
            }

            private static void TestKonekcija(IZalba proxy)
            {
                try
                {
                    proxy.TestConnection();
                    Console.WriteLine("✓ Test konekcija uspešna.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✗ Konekcija neuspešna: {ex.Message}");
                }
            }
        }
    }
}
