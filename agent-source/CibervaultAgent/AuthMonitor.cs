// ═══════════════════════════════════════════════════════════════════════════
// Cibervault EDR Agent — Windows Auth Monitor
// Reads Windows Security Event Log for authentication events:
//   4624 - Successful logon
//   4625 - Failed logon
//   4634 - Logoff
//   4648 - Explicit credentials (runas, network)
//   4720 - User account created
//   4722 - User account enabled
//   4724 - Password reset attempt
//   4726 - User account deleted
//   4732 - Member added to security-enabled local group
//   4672 - Special privileges assigned (admin logon)
// ═══════════════════════════════════════════════════════════════════════════

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CibervaultAgent
{
    public class AuthEvent
    {
        public string EventType { get; set; } = "";
        public int EventId { get; set; }
        public string User { get; set; } = "";
        public string Domain { get; set; } = "";
        public string SourceIp { get; set; } = "";
        public int LogonType { get; set; }
        public string LogonTypeName { get; set; } = "";
        public string TargetUser { get; set; } = "";
        public string GroupName { get; set; } = "";
        public string Status { get; set; } = "";
        public string SubStatus { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "info";
        public int RiskScore { get; set; } = 0;
        public string MitreId { get; set; } = "";
        public string MitreTactic { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public bool IsSuspicious { get; set; }
    }

    public class AuthMonitor : IDisposable
    {
        private const string SECURITY_LOG = "Security";
        private EventLogWatcher? _watcher;
        private readonly Action<AuthEvent> _onEvent;
        private readonly Action<string> _log;
        private bool _disposed;

        // Brute force tracking: IP → list of failure timestamps
        private readonly ConcurrentDictionary<string, List<DateTime>> _failTracker = new();

        // Logon type mapping
        private static readonly Dictionary<int, string> LogonTypes = new()
        {
            { 2, "Interactive" }, { 3, "Network" }, { 4, "Batch" },
            { 5, "Service" }, { 7, "Unlock" }, { 8, "NetworkCleartext" },
            { 9, "NewCredentials" }, { 10, "RemoteInteractive" },
            { 11, "CachedInteractive" },
        };

        // Service accounts to ignore
        private static readonly HashSet<string> IgnoreUsers = new(StringComparer.OrdinalIgnoreCase)
        {
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2",
            "UMFD-0", "UMFD-1", "ANONYMOUS LOGON", "-", "",
        };

        public AuthMonitor(Action<AuthEvent> onEvent, Action<string> log)
        {
            _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public void Start()
        {
            try
            {
                // Subscribe to Security event log for specific event IDs
                var query = new EventLogQuery(SECURITY_LOG, PathType.LogName,
                    "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 " +
                    "or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 " +
                    "or EventID=4732 or EventID=4672)]]");

                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += OnSecurityEvent;
                _watcher.Enabled = true;
                _log("[AuthMonitor] Started — watching Security event log");
            }
            catch (Exception ex)
            {
                _log($"[AuthMonitor] Failed to start: {ex.Message}");
                _log("[AuthMonitor] Ensure running as Administrator/SYSTEM");
            }
        }

        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnSecurityEvent;
            }
        }

        private void OnSecurityEvent(object? sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                var evt = e.EventRecord;
                var eventId = evt.Id;

                switch (eventId)
                {
                    case 4624: HandleLogonSuccess(evt); break;
                    case 4625: HandleLogonFailure(evt); break;
                    case 4634: HandleLogoff(evt); break;
                    case 4648: HandleExplicitCreds(evt); break;
                    case 4720: HandleUserCreated(evt); break;
                    case 4722: HandleUserEnabled(evt); break;
                    case 4724: HandlePasswordReset(evt); break;
                    case 4726: HandleUserDeleted(evt); break;
                    case 4732: HandleGroupMemberAdd(evt); break;
                    case 4672: HandleSpecialPriv(evt); break;
                }
            }
            catch (Exception ex)
            {
                _log($"[AuthMonitor] Event processing error: {ex.Message}");
            }
        }

        private void HandleLogonSuccess(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 5);      // TargetUserName
            var domain = GetProp(props, 6);    // TargetDomainName
            var logonType = GetIntProp(props, 8);
            var srcIp = GetProp(props, 18);    // IpAddress

            if (IgnoreUsers.Contains(user)) return;
            if (logonType == 5) return; // Skip service logons

            var logonName = LogonTypes.GetValueOrDefault(logonType, $"Type{logonType}");
            var severity = logonType == 10 ? "medium" : "low"; // RDP = medium
            var risk = logonType == 10 ? 30 : 10;

            _onEvent(new AuthEvent
            {
                EventType = "auth_success",
                EventId = 4624,
                User = user,
                Domain = domain,
                SourceIp = srcIp == "-" ? "" : srcIp,
                LogonType = logonType,
                LogonTypeName = logonName,
                Description = $"Logon: {domain}\\{user} ({logonName})" + (srcIp != "-" ? $" from {srcIp}" : ""),
                Severity = severity,
                RiskScore = risk,
                MitreId = "T1078",
                MitreTactic = "Initial Access",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleLogonFailure(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 5);      // TargetUserName
            var domain = GetProp(props, 6);    // TargetDomainName
            var logonType = GetIntProp(props, 10);
            var srcIp = GetProp(props, 19);    // IpAddress
            var status = GetProp(props, 7);    // Status
            var subStatus = GetProp(props, 9); // SubStatus

            if (IgnoreUsers.Contains(user)) return;

            // Track brute force
            var trackKey = string.IsNullOrEmpty(srcIp) || srcIp == "-" ? user : srcIp;
            var now = DateTime.UtcNow;

            _failTracker.AddOrUpdate(trackKey,
                new List<DateTime> { now },
                (_, list) => { lock (list) { list.Add(now); list.RemoveAll(t => (now - t).TotalMinutes > 5); } return list; });

            int failCount;
            lock (_failTracker[trackKey]) { failCount = _failTracker[trackKey].Count; }

            var isBrute = failCount >= 5;
            var severity = isBrute ? "critical" : "high";
            var risk = isBrute ? Math.Min(95, 50 + failCount * 3) : 50;

            _onEvent(new AuthEvent
            {
                EventType = "auth_failure",
                EventId = 4625,
                User = user,
                Domain = domain,
                SourceIp = srcIp == "-" ? "" : srcIp,
                LogonType = logonType,
                Status = status,
                SubStatus = subStatus,
                Description = $"Failed logon: {domain}\\{user}" +
                    (srcIp != "-" ? $" from {srcIp}" : "") +
                    (isBrute ? $" [BRUTE FORCE: {failCount} in 5min]" : ""),
                Severity = severity,
                RiskScore = risk,
                MitreId = "T1110",
                MitreTactic = "Credential Access",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });

            // Emit separate brute force event
            if (isBrute && failCount % 5 == 0)
            {
                _onEvent(new AuthEvent
                {
                    EventType = "brute_force_detected",
                    EventId = 4625,
                    User = user,
                    SourceIp = srcIp == "-" ? "" : srcIp,
                    Description = $"Brute force: {failCount} failures from {trackKey} in 5 minutes",
                    Severity = "critical",
                    RiskScore = Math.Min(95, 50 + failCount * 3),
                    MitreId = "T1110",
                    MitreTactic = "Credential Access",
                    IsSuspicious = true,
                    Timestamp = DateTime.UtcNow.ToString("o"),
                });
            }
        }

        private void HandleLogoff(EventRecord evt)
        {
            // Minimal tracking — just note it happened
        }

        private void HandleExplicitCreds(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 1);     // SubjectUserName
            var targetUser = GetProp(props, 5); // TargetUserName
            var targetServer = GetProp(props, 8);

            if (IgnoreUsers.Contains(user)) return;

            _onEvent(new AuthEvent
            {
                EventType = "auth_explicit",
                EventId = 4648,
                User = user,
                TargetUser = targetUser,
                Description = $"Explicit credentials: {user} → {targetUser}@{targetServer}",
                Severity = "medium",
                RiskScore = 45,
                MitreId = "T1078",
                MitreTactic = "Lateral Movement",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleUserCreated(EventRecord evt)
        {
            var props = GetProps(evt);
            var creator = GetProp(props, 4);
            var newUser = GetProp(props, 0);

            _onEvent(new AuthEvent
            {
                EventType = "user_created",
                EventId = 4720,
                User = creator,
                TargetUser = newUser,
                Description = $"User created: {newUser} by {creator}",
                Severity = "high",
                RiskScore = 70,
                MitreId = "T1136.001",
                MitreTactic = "Persistence",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleUserEnabled(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 4);
            var target = GetProp(props, 0);

            _onEvent(new AuthEvent
            {
                EventType = "user_enabled",
                EventId = 4722,
                User = user,
                TargetUser = target,
                Description = $"User enabled: {target} by {user}",
                Severity = "medium",
                RiskScore = 40,
                MitreId = "T1098",
                MitreTactic = "Persistence",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandlePasswordReset(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 4);
            var target = GetProp(props, 0);

            _onEvent(new AuthEvent
            {
                EventType = "password_reset",
                EventId = 4724,
                User = user,
                TargetUser = target,
                Description = $"Password reset: {target} by {user}",
                Severity = "medium",
                RiskScore = 45,
                MitreId = "T1098",
                MitreTactic = "Persistence",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleUserDeleted(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 4);
            var target = GetProp(props, 0);

            _onEvent(new AuthEvent
            {
                EventType = "user_deleted",
                EventId = 4726,
                User = user,
                TargetUser = target,
                Description = $"User deleted: {target} by {user}",
                Severity = "high",
                RiskScore = 65,
                MitreId = "T1531",
                MitreTactic = "Impact",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleGroupMemberAdd(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 6);     // SubjectUserName
            var member = GetProp(props, 0);   // MemberName
            var group = GetProp(props, 2);    // TargetUserName (group name)

            if (IgnoreUsers.Contains(user)) return;

            var isPrivGroup = group.Contains("Admin", StringComparison.OrdinalIgnoreCase) ||
                              group.Contains("Remote Desktop", StringComparison.OrdinalIgnoreCase);

            _onEvent(new AuthEvent
            {
                EventType = "group_member_add",
                EventId = 4732,
                User = user,
                TargetUser = member,
                GroupName = group,
                Description = $"Added to group: {member} → {group} by {user}",
                Severity = isPrivGroup ? "critical" : "medium",
                RiskScore = isPrivGroup ? 80 : 40,
                MitreId = "T1098",
                MitreTactic = "Persistence",
                IsSuspicious = isPrivGroup,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleSpecialPriv(EventRecord evt)
        {
            var props = GetProps(evt);
            var user = GetProp(props, 1);

            if (IgnoreUsers.Contains(user)) return;

            // Only log if not a service account
            _onEvent(new AuthEvent
            {
                EventType = "admin_logon",
                EventId = 4672,
                User = user,
                Description = $"Admin privileges assigned: {user}",
                Severity = "low",
                RiskScore = 15,
                MitreId = "T1078.003",
                MitreTactic = "Privilege Escalation",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        // ── Helpers ──────────────────────────────────────────────────
        private static IList<EventProperty>? GetProps(EventRecord evt)
        {
            try { return evt.Properties; } catch { return null; }
        }

        private static string GetProp(IList<EventProperty>? props, int idx)
        {
            try { return props != null && idx < props.Count ? props[idx].Value?.ToString() ?? "" : ""; }
            catch { return ""; }
        }

        private static int GetIntProp(IList<EventProperty>? props, int idx)
        {
            try { return props != null && idx < props.Count ? Convert.ToInt32(props[idx].Value) : 0; }
            catch { return 0; }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _watcher?.Dispose();
        }
    }
}
