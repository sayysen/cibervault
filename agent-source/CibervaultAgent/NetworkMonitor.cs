// ═══════════════════════════════════════════════════════════════════════════
// Cibervault EDR Agent — Windows Network Monitor
// Tracks: new listeners, suspicious outbound, connection frequency
// ═══════════════════════════════════════════════════════════════════════════

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CibervaultAgent
{
    public class NetworkEvent
    {
        public string EventType { get; set; } = "";      // new_listener, suspicious_outbound, connection_spike
        public string Protocol { get; set; } = "tcp";
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string State { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "medium";
        public int RiskScore { get; set; } = 50;
        public string MitreId { get; set; } = "";
        public string MitreTactic { get; set; } = "";
        public string Timestamp { get; set; } = "";
    }

    public class NetworkMonitor : IDisposable
    {
        private const int SCAN_INTERVAL_MS = 30000; // 30 seconds
        private readonly ConcurrentDictionary<string, DateTime> _knownListeners = new();
        private readonly ConcurrentDictionary<string, int> _outboundCounts = new();
        private readonly Action<NetworkEvent> _onEvent;
        private readonly Action<string> _log;
        private Timer? _scanTimer;
        private bool _disposed;
        private bool _baselined;

        // Suspicious destination ports (common backdoors, C2)
        private static readonly HashSet<int> SuspiciousPorts = new()
        {
            4444, 5555, 8888, 9999, 1234, 31337, 6666, 6667,  // Common backdoors
            4443, 8443, 8080, 9090,                              // Alt HTTP/HTTPS
            3389,                                                 // RDP (outbound = suspicious)
            445, 135, 139,                                        // SMB/RPC (outbound to internet)
        };

        // Known safe processes for high-port outbound
        private static readonly HashSet<string> SafeProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "CibervaultAgent", "svchost", "system", "msedge", "chrome", "firefox", "teams",
            "outlook", "onedrive", "code", "devenv", "dotnet",
            "windows update", "trustedinstaller", "msiexec",
        };

        public NetworkMonitor(Action<NetworkEvent> onEvent, Action<string> log)
        {
            _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public void Start()
        {
            _log("[NetworkMonitor] Starting...");
            // Initial baseline
            BaselineListeners();
            _scanTimer = new Timer(ScanCallback, null, SCAN_INTERVAL_MS, SCAN_INTERVAL_MS);
        }

        public void Stop()
        {
            _scanTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        }

        private void BaselineListeners()
        {
            try
            {
                var listeners = GetListeningPorts();
                foreach (var l in listeners)
                {
                    _knownListeners[l.Key] = DateTime.UtcNow;
                }
                _baselined = true;
                _log($"[NetworkMonitor] Baseline: {_knownListeners.Count} listening ports");
            }
            catch (Exception ex)
            {
                _log($"[NetworkMonitor] Baseline error: {ex.Message}");
            }
        }

        private void ScanCallback(object? state)
        {
            try
            {
                // Check for new listeners
                var listeners = GetListeningPorts();
                foreach (var l in listeners)
                {
                    if (!_knownListeners.ContainsKey(l.Key) && _baselined)
                    {
                        _knownListeners[l.Key] = DateTime.UtcNow;
                        var (procName, pid) = GetProcessForPort(l.Value.Port);

                        _onEvent(new NetworkEvent
                        {
                            EventType = "new_listener",
                            Protocol = "tcp",
                            LocalAddress = l.Value.Address,
                            LocalPort = l.Value.Port,
                            ProcessName = procName,
                            ProcessId = pid,
                            Description = $"New listener: {procName} on port {l.Value.Port}",
                            Severity = l.Value.Port < 1024 ? "high" : "medium",
                            RiskScore = l.Value.Port < 1024 ? 70 : 50,
                            MitreId = "T1571",
                            MitreTactic = "Command and Control",
                            Timestamp = DateTime.UtcNow.ToString("o"),
                        });
                    }
                }

                // Check outbound connections
                CheckOutbound();

                // Reset hourly outbound counts
                if (DateTime.UtcNow.Minute == 0 && DateTime.UtcNow.Second < 35)
                {
                    _outboundCounts.Clear();
                }
            }
            catch (Exception ex)
            {
                _log($"[NetworkMonitor] Scan error: {ex.Message}");
            }
        }

        private void CheckOutbound()
        {
            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    if (conn.State != TcpState.Established) continue;

                    var remoteIp = conn.RemoteEndPoint.Address.ToString();
                    var remotePort = conn.RemoteEndPoint.Port;

                    // Skip localhost
                    if (IPAddress.IsLoopback(conn.RemoteEndPoint.Address)) continue;

                    // Track frequency
                    var destKey = $"{remoteIp}:{remotePort}";
                    _outboundCounts.AddOrUpdate(destKey, 1, (_, c) => c + 1);

                    // Check suspicious ports
                    if (SuspiciousPorts.Contains(remotePort))
                    {
                        var (procName, pid) = GetProcessForConnection(conn);

                        _onEvent(new NetworkEvent
                        {
                            EventType = "suspicious_outbound",
                            RemoteAddress = remoteIp,
                            RemotePort = remotePort,
                            LocalPort = conn.LocalEndPoint.Port,
                            ProcessName = procName,
                            ProcessId = pid,
                            State = "ESTABLISHED",
                            Description = $"Suspicious outbound: {procName} → {destKey}",
                            Severity = "high",
                            RiskScore = 75,
                            MitreId = "T1071",
                            MitreTactic = "Command and Control",
                            Timestamp = DateTime.UtcNow.ToString("o"),
                        });
                    }

                    // Check high-frequency destinations
                    if (_outboundCounts.TryGetValue(destKey, out var count) && count > 50)
                    {
                        var (procName, pid) = GetProcessForConnection(conn);
                        if (!SafeProcesses.Contains(procName))
                        {
                            _onEvent(new NetworkEvent
                            {
                                EventType = "connection_spike",
                                RemoteAddress = remoteIp,
                                RemotePort = remotePort,
                                ProcessName = procName,
                                ProcessId = pid,
                                Description = $"Connection spike: {count} connections to {destKey} by {procName}",
                                Severity = "medium",
                                RiskScore = 60,
                                MitreId = "T1041",
                                MitreTactic = "Exfiltration",
                                Timestamp = DateTime.UtcNow.ToString("o"),
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log($"[NetworkMonitor] Outbound check error: {ex.Message}");
            }
        }

        private Dictionary<string, (string Address, int Port)> GetListeningPorts()
        {
            var result = new Dictionary<string, (string, int)>();
            try
            {
                var props = IPGlobalProperties.GetIPGlobalProperties();
                foreach (var ep in props.GetActiveTcpListeners())
                {
                    var key = $"{ep.Address}:{ep.Port}";
                    result[key] = (ep.Address.ToString(), ep.Port);
                }
            }
            catch { }
            return result;
        }

        private (string name, int pid) GetProcessForPort(int port)
        {
            try
            {
                var psi = new ProcessStartInfo("netstat", "-ano")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi)!;
                var output = proc.StandardOutput.ReadToEnd();
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains($":{port}") && line.Contains("LISTENING"))
                    {
                        var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5 && int.TryParse(parts[^1], out int pid))
                        {
                            try { return (Process.GetProcessById(pid).ProcessName, pid); } catch { }
                        }
                    }
                }
            }
            catch { }
            return ("unknown", 0);
        }

        private (string name, int pid) GetProcessForConnection(TcpConnectionInformation conn)
        {
            // .NET doesn't expose PID for connections directly, use netstat
            try
            {
                var psi = new ProcessStartInfo("netstat", "-ano")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi)!;
                var output = proc.StandardOutput.ReadToEnd();
                var remoteStr = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains(remoteStr) && line.Contains("ESTABLISHED"))
                    {
                        var parts = line.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 5 && int.TryParse(parts[^1], out int pid))
                        {
                            try { return (Process.GetProcessById(pid).ProcessName, pid); } catch { }
                        }
                    }
                }
            }
            catch { }
            return ("unknown", 0);
        }

        public (int listeners, int outboundTracked) GetStats()
        {
            return (_knownListeners.Count, _outboundCounts.Count);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _scanTimer?.Dispose();
        }
    }
}
