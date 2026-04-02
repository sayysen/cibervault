// ═══════════════════════════════════════════════════════════════════════════
// Cibervault EDR Agent — Windows Defender Monitor
// Reads Microsoft-Windows-Windows Defender/Operational event log:
//   1116 - Malware detected
//   1117 - Action taken on malware
//   1006 - Engine updated
//   1007 - Platform updated
//   1013 - Scanning history deleted
//   5001 - Real-time protection disabled
//   5004 - Config changed
//   5007 - Anti-malware config changed
// ═══════════════════════════════════════════════════════════════════════════

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading;

namespace CibervaultAgent
{
    public class DefenderEvent
    {
        public string EventType { get; set; } = "";
        public int EventId { get; set; }
        public string ThreatName { get; set; } = "";
        public string ThreatPath { get; set; } = "";
        public string ThreatSeverity { get; set; } = "";
        public string ActionTaken { get; set; } = "";
        public string User { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "medium";
        public int RiskScore { get; set; } = 50;
        public string MitreId { get; set; } = "";
        public string MitreTactic { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public bool IsSuspicious { get; set; }
    }

    public class DefenderMonitor : IDisposable
    {
        private const string DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational";
        private EventLogWatcher? _watcher;
        private readonly Action<DefenderEvent> _onEvent;
        private readonly Action<string> _log;
        private bool _disposed;

        // Threat severity mapping
        private static readonly Dictionary<string, (string sev, int risk)> ThreatLevels = new()
        {
            { "Severe", ("critical", 95) },
            { "High", ("high", 80) },
            { "Medium", ("medium", 60) },
            { "Low", ("low", 35) },
            { "Unknown", ("medium", 50) },
        };

        public DefenderMonitor(Action<DefenderEvent> onEvent, Action<string> log)
        {
            _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public void Start()
        {
            try
            {
                var query = new EventLogQuery(DEFENDER_LOG, PathType.LogName,
                    "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5004 or EventID=5007 or EventID=1013)]]");

                _watcher = new EventLogWatcher(query);
                _watcher.EventRecordWritten += OnDefenderEvent;
                _watcher.Enabled = true;
                _log("[DefenderMonitor] Started — watching Windows Defender log");
            }
            catch (EventLogNotFoundException)
            {
                _log("[DefenderMonitor] Windows Defender log not found — Defender may not be installed");
            }
            catch (Exception ex)
            {
                _log($"[DefenderMonitor] Failed to start: {ex.Message}");
            }
        }

        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnDefenderEvent;
            }
        }

        private void OnDefenderEvent(object? sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                var evt = e.EventRecord;
                var eventId = evt.Id;

                switch (eventId)
                {
                    case 1116: HandleThreatDetected(evt); break;
                    case 1117: HandleActionTaken(evt); break;
                    case 5001: HandleRealTimeDisabled(evt); break;
                    case 5004:
                    case 5007: HandleConfigChanged(evt); break;
                    case 1013: HandleScanHistoryDeleted(evt); break;
                }
            }
            catch (Exception ex)
            {
                _log($"[DefenderMonitor] Event error: {ex.Message}");
            }
        }

        private void HandleThreatDetected(EventRecord evt)
        {
            var props = GetProps(evt);
            var threatName = GetProp(props, 7);     // Threat Name
            var threatSev = GetProp(props, 11);      // Severity Name
            var threatPath = GetProp(props, 17);     // Path
            var user = GetProp(props, 24);           // Detection User

            var (severity, risk) = ThreatLevels.GetValueOrDefault(threatSev, ("medium", 60));

            _onEvent(new DefenderEvent
            {
                EventType = "defender_threat_detected",
                EventId = 1116,
                ThreatName = threatName,
                ThreatPath = threatPath,
                ThreatSeverity = threatSev,
                User = user,
                Description = $"Defender detected: {threatName} at {threatPath}",
                Severity = severity,
                RiskScore = risk,
                MitreId = "T1059",
                MitreTactic = "Execution",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleActionTaken(EventRecord evt)
        {
            var props = GetProps(evt);
            var threatName = GetProp(props, 7);
            var action = GetProp(props, 15);     // Action Name
            var threatPath = GetProp(props, 17);

            _onEvent(new DefenderEvent
            {
                EventType = "defender_action_taken",
                EventId = 1117,
                ThreatName = threatName,
                ThreatPath = threatPath,
                ActionTaken = action,
                Description = $"Defender action: {action} on {threatName}",
                Severity = "medium",
                RiskScore = 40,
                MitreId = "T1059",
                MitreTactic = "Execution",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleRealTimeDisabled(EventRecord evt)
        {
            _onEvent(new DefenderEvent
            {
                EventType = "defender_realtime_disabled",
                EventId = 5001,
                Description = "Windows Defender real-time protection DISABLED",
                Severity = "critical",
                RiskScore = 90,
                MitreId = "T1562.001",
                MitreTactic = "Defense Evasion",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleConfigChanged(EventRecord evt)
        {
            _onEvent(new DefenderEvent
            {
                EventType = "defender_config_changed",
                EventId = evt.Id,
                Description = $"Windows Defender configuration changed (EventID {evt.Id})",
                Severity = "medium",
                RiskScore = 45,
                MitreId = "T1562.001",
                MitreTactic = "Defense Evasion",
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private void HandleScanHistoryDeleted(EventRecord evt)
        {
            _onEvent(new DefenderEvent
            {
                EventType = "defender_history_deleted",
                EventId = 1013,
                Description = "Defender scan history deleted — possible anti-forensics",
                Severity = "high",
                RiskScore = 75,
                MitreId = "T1070",
                MitreTactic = "Defense Evasion",
                IsSuspicious = true,
                Timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? DateTime.UtcNow.ToString("o"),
            });
        }

        private static IList<EventProperty>? GetProps(EventRecord evt)
        {
            try { return evt.Properties; } catch { return null; }
        }

        private static string GetProp(IList<EventProperty>? props, int idx)
        {
            try { return props != null && idx < props.Count ? props[idx].Value?.ToString() ?? "" : ""; }
            catch { return ""; }
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
