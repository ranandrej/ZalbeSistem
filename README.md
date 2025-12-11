
---

# Žalbe Sistem

Distributed, certificate-secured WCF system for submitting and supervising complaints with primary/backup servers, AES encryption, digital signatures, and role-based access (Korisnik/Nadzor). Includes client, primary service, backup service, and a backup replication server.

## Table of Contents
- Features
- Architecture
- Security Model
- Project Structure
- Data Model
- Client Menu / Usage
- Endpoints & Contracts
- Build & Run
- Operational Notes
- Troubleshooting
- Extending

## Features
- Complaint submission with AES encryption and X.509 digital signatures.
- Role-gated supervision: only Nadzor can list/search/inspect stats.
- Primary/backup servers with replication of encrypted complaints.
- Health-check and automatic failover client that switches between primary/backup.
- Content filtering (forbidden words) with audit logging of blocked attempts.
- New client functions:
  - Search complaints by keyword (Nadzor).
  - View complaint statistics summary (Nadzor).

## Architecture
- **Client**: WCF consumer that holds dual proxies (primary & backup). Performs health checks, failover, and exposes a console menu.
- **PrimaryServer / Service (ZalbaService)**: Main WCF service; validates signatures, decrypts AES payloads, enforces roles, stores complaints, replicates to backup.
- **BackupServer / BackupService**: Secondary WCF service; receives replication, can serve reads (Nadzor) and health checks.
- **Common**: Shared interfaces, models, and contracts.
- **Manager**: Certificates, crypto helpers (AES, signatures), formatter, authorization helpers, and audit utilities.

Data flow:
1) Client builds complaint → AES encrypt → sign with client cert → send to service.
2) Service validates signature (client cert), decrypts, enforces authorization/content rules, persists XML.
3) Service attempts replication to backup via backup WCF endpoint.
4) Supervisors (Nadzor) can list/search/stats via either endpoint.

## Security Model
- Transport: `NetTcpBinding` with `SecurityMode.Transport`, `ClientCredentialType.Certificate`, `ProtectionLevel.EncryptAndSign`.
- Certificates:
  - Service certs: `zalbaserver` (primary), `backupserver` (backup) in TrustedPeople/LocalMachine.
  - Client cert: `nadzorclient` (and/or Korisnik) in My/LocalMachine.
- Authorization:
  - Complaint send: roles Korisnik or Nadzor.
  - Supervision (list/search/stats): role Nadzor.
- Integrity: DigitalSignature.Verify on encrypted payloads (X.509).
- Confidentiality: AES encryption with shared secret key.

## Project Structure
- `Client/`
  - `Program.cs` – console UX, menu, failover logic, health check loop.
  - `ZalbaClient.cs` – primary proxy implementing `IZalba`.
  - `BackupClient.cs` – backup proxy implementing `IZalba`.
- `Service/`
  - `ZalbaService.cs` – primary service implementation.
- `BackupService/`
  - `BackupService.cs` – backup service implementation (replication + reads).
- `Common/`
  - `IZalbaService.cs`, `IBackupService.cs`, `IZalba.cs` – contracts.
  - `Models/Zalba.cs` – complaint DTO.
- `Manager/`
  - `Cryptography/` (AESHelper, DigitalSignature), `CertificateManager/`, `Security/`, `Audit/`, etc.
- `PrimaryServer/`, `BackupServer/`
  - Hosts for the services.
- `ZalbeSistem.sln` – solution.

## Data Model
`Common.Models.Zalba`
- `Id: Guid`
- `Sadrzaj: string`
- `PosiljaoKorisnik: string`
- `DatumSlanja: DateTime`
- `NedozvoljenaSadrzaj: bool`
- `ToString()` → `[yyyy-MM-dd HH:mm] user: content`

## Client Menu / Usage
Console menu (Client):
- `1` Pošalji žalbu (Korisnik/Nadzor)
- `2` Prikaži žalbe (Nadzor)
- `3` Pretraži žalbe (Nadzor)
- `4` Prikaži statistiku žalbi (Nadzor)
- `5` Test konekcije (current endpoint)
- `6` Izlaz

Behavior:
- On start: attempts primary; on failure switches to backup. Background health thread retries and switches when an endpoint fails/recovers.
- Forbidden content is stored but flagged and reported as rejected.

## Endpoints & Contracts
Interfaces:
- `IZalbaService` (primary) & `IBackupService` (backup): `PosaljiZalbu`, `GetZalbeZaNadzor`, `PretraziZalbe`, `GetStatistikaZalbi`, `TestConnection`, plus backup-only `ReplicateZalbe`, `IsAvailable`.
- `IZalba` (client-facing abstraction) mirrors usable operations.

Addresses (defaults in code):
- Primary: `net.tcp://localhost:8001/ZalbaService` with cert `zalbaserver`.
- Backup: `net.tcp://localhost:8002/BackupService` with cert `backupserver`.

## Build & Run
Prereqs:
- .NET Framework/WCF capable environment (Windows).
- Certificates installed:
  - `zalbaserver` (TrustedPeople/LocalMachine)
  - `backupserver` (TrustedPeople/LocalMachine)
  - `nadzorclient` (My/LocalMachine) for Nadzor; equivalent Korisnik cert for standard user.
- Matching CNs for endpoint identity.

Build (from solution root):
```powershell
# Build all
msbuild ZalbeSistem.sln /p:Configuration=Debug

# Run services (each in separate shell)
cd PrimaryServer && bin\Debug\PrimaryServer.exe
cd BackupServer && bin\Debug\BackupServer.exe

# Run client
cd Client && bin\Debug\Client.exe
```

## Operational Notes
- Storage: primary persists to `zalbe.xml`; backup to `backup_zalbe.xml`. Both are simple XML lists of `Zalba`.
- Replication: primary encrypts and sends to backup via `ReplicateZalbe`; backup deduplicates by `Id`.
- Health/Fallover: client background thread calls `TestConnection` on the active endpoint; on failure it switches to the other.
- Content filter: simple keyword match; blocked items are still stored but flagged.
- Auditing: authorization failures, send failures, replication status are logged via `Manager.Audit` (implementation-dependent).

## Troubleshooting
- **Handshake/Cert errors**: verify cert store location, CN matches endpoint identity, and ChainTrust/PeerOrChainTrust settings.
- **Authorization fault**: ensure caller is in AD/group `Nadzor` for supervision ops.
- **Replication issues**: check backup availability (`IsAvailable`), endpoint 8002, and backup cert trust.
- **Forbidden content rejected**: content matched forbidden words list; see service console/audit.

## Extending
- Add richer search (date ranges, user filters) in `PretraziZalbe`.
- Add pagination for large complaint sets.
- Swap XML storage for a DB; keep contracts unchanged.
- Introduce more detailed audit sinks (file/DB/ELK).
- Harden key management (move AES key to secure store).
