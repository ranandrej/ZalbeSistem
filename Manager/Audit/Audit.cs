using System;
using System.Diagnostics;

namespace Manager.Audit
{
    public class Audit : IDisposable
    {
        private static EventLog customLog = null;
        const string SourceName = "ZalbeSystem.Audit";
        const string LogName = "ZalbeSystemAudit";

        static Audit()
        {
            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    EventLog.CreateEventSource(SourceName, LogName);
                }
                customLog = new EventLog(LogName, Environment.MachineName, SourceName);
                Console.WriteLine("[AUDIT] EventLog created successfully.");
            }
            catch (Exception e)
            {
                customLog = null;
                Console.WriteLine($"[AUDIT] Error creating log handle: {e.Message}");
            }
        }

        public static void AuthenticationSuccess(string userName)
        {
            WriteEvent($"User {userName} is successfully authenticated.");
        }

        public static void AuthenticationFailed(string userName)
        {
            WriteEvent($"User {userName} failed authentication.");
        }

        public static void AuthorizationSuccess(string userName, string action)
        {
            WriteEvent($"User {userName} successfully accessed {action}.");
        }

        public static void AuthorizationFailed(string userName, string action, string reason)
        {
            WriteEvent($"User {userName} failed to access {action}. Reason: {reason}.");
        }

        public static void ZalbaSubmissionSuccess(string userName)
        {
            WriteEvent($"User {userName} successfully submitted a complaint.");
        }

        public static void ZalbaSubmissionFailed(string userName, string reason)
        {
            WriteEvent($"User {userName} failed to submit complaint. Reason: {reason}.");
        }

        public static void BannedCertificateDetected(string certificateSubject)
        {
            WriteEvent($"Banned certificate detected: {certificateSubject}.");
        }

        public static void BackupReplicationSuccess(string zalbaId)
        {
            WriteEvent($"Complaint {zalbaId} successfully replicated to backup server.");
        }

        public static void BackupReplicationFailed(string zalbaId)
        {
            WriteEvent($"Failed to replicate complaint {zalbaId} to backup server.");
        }

        public static void BackupServerDown()
        {
            WriteEvent("Backup server is not available. Operating in standalone mode.");
        }

        private static void WriteEvent(string message)
        {
            try
            {
                if (customLog != null)
                {
                    customLog.WriteEntry(message);
                }
                Console.WriteLine($"[AUDIT] {message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AUDIT-ERROR] Failed to write event: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (customLog != null)
            {
                customLog.Dispose();
                customLog = null;
            }
        }
    }
}