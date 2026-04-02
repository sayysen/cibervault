// ═══════════════════════════════════════════════════════════════════════════════
// Cibervault EDR Agent — Smart Process Monitor
// Add this file to: CibervaultAgent-Windows/CibervaultAgent/ProcessMonitor.cs
//
// How it works:
//   1. Subscribes to WMI Win32_ProcessStartTrace (all process creates)
//   2. Stores every process in a rolling 10-minute buffer (ProcessRecord)
//   3. Evaluates each new process against suspicious indicators
//   4. When suspicious → walks up to root and down to all children → sends full tree
//   5. Also captures process termination to track short-lived processes
// ═══════════════════════════════════════════════════════════════════════════════

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace CibervaultAgent
{
    /// <summary>
    /// Represents a single captured process with full metadata.
    /// </summary>
    public class ProcessRecord
    {
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public string Name { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string User { get; set; } = "";
        public string ParentName { get; set; } = "";
        public DateTime StartTime { get; set; } = DateTime.UtcNow;
        public DateTime? EndTime { get; set; }
        public string Sha256 { get; set; } = "";
        public string Md5 { get; set; } = "";
        public long FileSize { get; set; }
        public string Integrity { get; set; } = "";  // System, High, Medium, Low
        public bool IsSuspicious { get; set; }
        public string SuspiciousReason { get; set; } = "";
        public int SessionId { get; set; }
        public string TreeId { get; set; } = "";  // Links processes in the same captured tree
    }

    /// <summary>
    /// A full process tree sent to the server when suspicious activity detected.
    /// </summary>
    public class ProcessTreeEvent
    {
        public string TreeId { get; set; } = "";
        public string TriggerPid { get; set; } = "";
        public string TriggerReason { get; set; } = "";
        public string RootProcessName { get; set; } = "";
        public int RootPid { get; set; }
        public DateTime CaptureTime { get; set; } = DateTime.UtcNow;
        public List<ProcessRecord> Processes { get; set; } = new();
        public List<ProcessEdge> Edges { get; set; } = new();
    }

    public class ProcessEdge
    {
        public int FromPid { get; set; }
        public int ToPid { get; set; }
    }

    /// <summary>
    /// Smart Process Monitor — watches all process creation via WMI,
    /// maintains a rolling buffer, captures full trees on suspicious detection.
    /// </summary>
    public class ProcessMonitor : IDisposable
    {
        // ── Configuration ────────────────────────────────────────────────
        private const int BUFFER_MINUTES = 10;        // Keep processes for 10 min
        private const int CLEANUP_INTERVAL_SEC = 60;  // Cleanup old entries every 60s
        private const int MAX_BUFFER_SIZE = 5000;     // Max processes in buffer
        private const int MAX_TREE_DEPTH = 20;        // Prevent infinite recursion
        private const int TREE_COOLDOWN_SEC = 30;     // Don't re-capture same root within 30s

        // ── Suspicious Indicators ────────────────────────────────────────
        // Known LOLBins (Living Off the Land Binaries)
        private static readonly HashSet<string> LOLBins = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "msiexec.exe", "wmic.exe", "attrib.exe",
            "schtasks.exe", "at.exe", "sc.exe", "net.exe", "net1.exe",
            "netsh.exe", "icacls.exe", "cacls.exe", "takeown.exe",
            "vssadmin.exe", "bcdedit.exe", "wbadmin.exe", "cipher.exe",
            "expand.exe", "extrac32.exe", "findstr.exe", "forfiles.exe",
            "hh.exe", "infdefaultinstall.exe", "installutil.exe",
            "mavinject.exe", "msbuild.exe", "msconfig.exe",
            "msdeploy.exe", "msdt.exe", "pcalua.exe", "pcwrun.exe",
            "presentationhost.exe", "reg.exe", "regasm.exe", "regedit.exe",
            "regsvcs.exe", "replace.exe", "rpcping.exe", "sdbinst.exe",
            "syncappvpublishingserver.exe", "te.exe", "tracker.exe",
            "verclsid.exe", "xwizard.exe"
        };

        // Suspicious parent→child combinations
        private static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild = new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe" },
            ["excel.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["outlook.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe" },
            ["powerpnt.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["explorer.exe"] = new(StringComparer.OrdinalIgnoreCase) { "mshta.exe", "regsvr32.exe", "rundll32.exe" },
            ["svchost.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe" },
            ["wmiprvse.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe" },
            ["services.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe" },
        };

        // Suspicious command-line patterns (regex-free for performance)
        private static readonly string[] SuspiciousCmdPatterns = new[]
        {
            "-encodedcommand", "-enc ", "-e ", "frombase64string",
            "invoke-expression", "iex ", "downloadstring", "downloadfile",
            "invoke-webrequest", "wget ", "curl ", "start-bitstransfer",
            "hidden", "-nop ", "-noni", "-windowstyle h", "-w hidden",
            "bypass", "-exec bypass", "unrestricted",
            "vssadmin delete", "wmic shadowcopy", "bcdedit /set",
            "wbadmin delete", "cipher /w", "icacls.*everyone.*full",
            "attrib +h +s", "net user /add", "net localgroup admin",
            "schtasks /create", "reg add.*run", "disable-computer",
            "mimikatz", "lazagne", "procdump", "rubeus",
            "sekurlsa", "lsadump", "kerberoast",
            "$recycle", "taskdl", "taskse", "wannacry",
        };

        // Known suspicious file locations
        private static readonly string[] SuspiciousPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\",
            @"\downloads\", @"\public\", @"\programdata\",
            @"\recycle", @"\perflogs\"
        };

        // ── State ────────────────────────────────────────────────────────
        private readonly ConcurrentDictionary<int, ProcessRecord> _buffer = new();
        private readonly ConcurrentDictionary<string, DateTime> _treeCooldown = new(); // root key → last capture
        private ManagementEventWatcher? _startWatcher;
        private ManagementEventWatcher? _stopWatcher;
        private Timer? _cleanupTimer;
        private readonly Action<ProcessTreeEvent> _onTreeCaptured;
        private readonly Action<string> _log;
        private bool _disposed;
        private int _treesCaptures;
        private int _processesObserved;

        // ── Constructor ──────────────────────────────────────────────────
        /// <param name="onTreeCaptured">Callback when a suspicious tree is captured (send to server)</param>
        /// <param name="log">Logging callback</param>
        public ProcessMonitor(Action<ProcessTreeEvent> onTreeCaptured, Action<string> log)
        {
            _onTreeCaptured = onTreeCaptured ?? throw new ArgumentNullException(nameof(onTreeCaptured));
            _log = log ?? Console.WriteLine;
        }

        // ── Start / Stop ─────────────────────────────────────────────────
        public void Start()
        {
            _log("[ProcessMonitor] Starting smart process monitoring...");

            // Snapshot existing processes into buffer
            SnapshotRunningProcesses();

            // WMI: Watch process creation
            try
            {
                _startWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                _startWatcher.EventArrived += OnProcessStart;
                _startWatcher.Start();
                _log("[ProcessMonitor] WMI process start watcher active");
            }
            catch (Exception ex)
            {
                _log($"[ProcessMonitor] WMI start watcher failed: {ex.Message}");
            }

            // WMI: Watch process termination
            try
            {
                _stopWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
                _stopWatcher.EventArrived += OnProcessStop;
                _stopWatcher.Start();
                _log("[ProcessMonitor] WMI process stop watcher active");
            }
            catch (Exception ex)
            {
                _log($"[ProcessMonitor] WMI stop watcher failed: {ex.Message}");
            }

            // Periodic cleanup
            _cleanupTimer = new Timer(CleanupBuffer, null,
                TimeSpan.FromSeconds(CLEANUP_INTERVAL_SEC),
                TimeSpan.FromSeconds(CLEANUP_INTERVAL_SEC));

            _log("[ProcessMonitor] Smart mode active — monitoring for suspicious process chains");
        }

        public void Stop()
        {
            _log("[ProcessMonitor] Stopping...");
            _startWatcher?.Stop();
            _stopWatcher?.Stop();
            _cleanupTimer?.Dispose();
            _log($"[ProcessMonitor] Stopped. Observed={_processesObserved}, TreesCaptured={_treesCaptures}");
        }

        // ── WMI Event Handlers ───────────────────────────────────────────
        private void OnProcessStart(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                int ppid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
                string name = e.NewEvent["ProcessName"]?.ToString() ?? "";

                Interlocked.Increment(ref _processesObserved);

                // Build record with enrichment
                var record = new ProcessRecord
                {
                    Pid = pid,
                    ParentPid = ppid,
                    Name = name,
                    StartTime = DateTime.UtcNow,
                };

                // Enrich with WMI query for command line, user, path
                EnrichProcess(record);

                // Get parent name from buffer
                if (_buffer.TryGetValue(ppid, out var parent))
                {
                    record.ParentName = parent.Name;
                }

                // Add to buffer
                _buffer[pid] = record;

                // ── SMART DETECTION ──
                var (isSuspicious, reason) = EvaluateSuspicious(record);
                if (isSuspicious)
                {
                    record.IsSuspicious = true;
                    record.SuspiciousReason = reason;
                    _log($"[ProcessMonitor] SUSPICIOUS: {name} (PID:{pid}) — {reason}");

                    // Capture the full tree
                    CaptureTree(pid, reason);
                }
            }
            catch (Exception ex)
            {
                // Don't crash the monitor on individual event failures
                _log($"[ProcessMonitor] Error processing start event: {ex.Message}");
            }
        }

        private void OnProcessStop(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                if (_buffer.TryGetValue(pid, out var record))
                {
                    record.EndTime = DateTime.UtcNow;
                }
            }
            catch { /* ignore stop errors */ }
        }

        // ── Suspicious Evaluation ────────────────────────────────────────
        private (bool isSuspicious, string reason) EvaluateSuspicious(ProcessRecord proc)
        {
            string name = proc.Name.ToLowerInvariant();
            string parentName = proc.ParentName.ToLowerInvariant();
            string cmd = (proc.CommandLine ?? "").ToLowerInvariant();
            string path = (proc.ImagePath ?? "").ToLowerInvariant();

            // 1. Suspicious parent→child relationship
            foreach (var kvp in SuspiciousParentChild)
            {
                if (parentName.Contains(kvp.Key.ToLowerInvariant()))
                {
                    if (kvp.Value.Any(c => name.Contains(c.ToLowerInvariant())))
                    {
                        return (true, $"Suspicious parent-child: {proc.ParentName} → {proc.Name}");
                    }
                }
            }

            // 2. LOLBin spawned by unusual parent
            if (LOLBins.Contains(proc.Name))
            {
                // LOLBin from temp/download path
                if (SuspiciousPaths.Any(p => path.Contains(p.ToLowerInvariant())))
                {
                    return (true, $"LOLBin from suspicious path: {proc.Name} from {path}");
                }

                // LOLBin with suspicious command line
                if (SuspiciousCmdPatterns.Any(p => cmd.Contains(p.ToLowerInvariant())))
                {
                    return (true, $"LOLBin with suspicious args: {proc.Name}");
                }
            }

            // 3. Suspicious command-line patterns (any process)
            foreach (var pattern in SuspiciousCmdPatterns)
            {
                if (cmd.Contains(pattern.ToLowerInvariant()))
                {
                    return (true, $"Suspicious command line pattern: {pattern}");
                }
            }

            // 4. Process from suspicious location
            if (SuspiciousPaths.Any(p => path.Contains(p.ToLowerInvariant())))
            {
                // Only flag if it's NOT a known Windows binary
                if (!path.Contains(@"\windows\") && !path.Contains(@"\program files"))
                {
                    return (true, $"Process from suspicious path: {path}");
                }
            }

            // 5. Unsigned/unknown binary spawning children (heuristic)
            // If the parent is in buffer and had suspicious activity, propagate
            if (_buffer.TryGetValue(proc.ParentPid, out var parentRec) && parentRec.IsSuspicious)
            {
                return (true, $"Child of suspicious process: {parentRec.Name} (PID:{parentRec.Pid})");
            }

            return (false, "");
        }

        // ── Tree Capture ─────────────────────────────────────────────────
        private void CaptureTree(int triggerPid, string reason)
        {
            // Find the root of the tree (walk up parent chain)
            int rootPid = triggerPid;
            int depth = 0;
            var visited = new HashSet<int> { triggerPid };

            while (depth < MAX_TREE_DEPTH)
            {
                if (!_buffer.TryGetValue(rootPid, out var current))
                    break;
                if (current.ParentPid <= 0 || current.ParentPid == rootPid)
                    break;
                if (visited.Contains(current.ParentPid))
                    break;
                // Don't go above system processes
                if (current.ParentPid == 4 || current.ParentPid == 0)
                    break;

                visited.Add(current.ParentPid);
                rootPid = current.ParentPid;
                depth++;
            }

            // Cooldown check — don't re-capture the same tree root within 30s
            string cooldownKey = $"{rootPid}";
            if (_treeCooldown.TryGetValue(cooldownKey, out var lastCapture))
            {
                if ((DateTime.UtcNow - lastCapture).TotalSeconds < TREE_COOLDOWN_SEC)
                    return;
            }
            _treeCooldown[cooldownKey] = DateTime.UtcNow;

            // Walk down from root, collecting all children
            string treeId = $"tree-{Guid.NewGuid():N}".Substring(0, 24);
            var treeProcesses = new List<ProcessRecord>();
            var edges = new List<ProcessEdge>();
            var collectVisited = new HashSet<int>();

            CollectChildren(rootPid, treeProcesses, edges, collectVisited, 0);

            // Also ensure trigger process and its ancestors are included
            int walkPid = triggerPid;
            while (walkPid > 0 && !collectVisited.Contains(walkPid))
            {
                if (_buffer.TryGetValue(walkPid, out var proc))
                {
                    proc.TreeId = treeId;
                    treeProcesses.Add(proc);
                    collectVisited.Add(walkPid);
                    if (proc.ParentPid > 0 && proc.ParentPid != walkPid)
                        edges.Add(new ProcessEdge { FromPid = proc.ParentPid, ToPid = walkPid });
                    walkPid = proc.ParentPid;
                }
                else break;
            }

            if (treeProcesses.Count == 0) return;

            // Tag all with tree ID
            foreach (var p in treeProcesses) p.TreeId = treeId;

            string rootName = _buffer.TryGetValue(rootPid, out var rootProc) ? rootProc.Name : "unknown";

            var treeEvent = new ProcessTreeEvent
            {
                TreeId = treeId,
                TriggerPid = triggerPid.ToString(),
                TriggerReason = reason,
                RootProcessName = rootName,
                RootPid = rootPid,
                CaptureTime = DateTime.UtcNow,
                Processes = treeProcesses,
                Edges = edges.DistinctBy(e => $"{e.FromPid}-{e.ToPid}").ToList(),
            };

            Interlocked.Increment(ref _treesCaptures);
            _log($"[ProcessMonitor] TREE CAPTURED: {treeId} | root={rootName}(PID:{rootPid}) | " +
                 $"trigger=PID:{triggerPid} | {treeProcesses.Count} processes | reason: {reason}");

            // Send to server via callback
            Task.Run(() =>
            {
                try { _onTreeCaptured(treeEvent); }
                catch (Exception ex) { _log($"[ProcessMonitor] Error sending tree: {ex.Message}"); }
            });
        }

        private void CollectChildren(int pid, List<ProcessRecord> result,
            List<ProcessEdge> edges, HashSet<int> visited, int depth)
        {
            if (depth > MAX_TREE_DEPTH || visited.Contains(pid)) return;
            visited.Add(pid);

            if (_buffer.TryGetValue(pid, out var proc))
            {
                result.Add(proc);
            }

            // Find all children of this PID
            foreach (var kvp in _buffer)
            {
                if (kvp.Value.ParentPid == pid && !visited.Contains(kvp.Key))
                {
                    edges.Add(new ProcessEdge { FromPid = pid, ToPid = kvp.Key });
                    CollectChildren(kvp.Key, result, edges, visited, depth + 1);
                }
            }
        }

        // ── Process Enrichment ───────────────────────────────────────────
        private void EnrichProcess(ProcessRecord record)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine, ExecutablePath, SessionId FROM Win32_Process WHERE ProcessId = {record.Pid}");
                foreach (var obj in searcher.Get())
                {
                    record.CommandLine = obj["CommandLine"]?.ToString() ?? "";
                    record.ImagePath = obj["ExecutablePath"]?.ToString() ?? "";
                    record.SessionId = Convert.ToInt32(obj["SessionId"] ?? 0);
                }
            }
            catch { /* process may have exited already */ }

            // Get process owner
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_Process WHERE ProcessId = {record.Pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string[] ownerInfo = new string[2];
                    try
                    {
                        obj.InvokeMethod("GetOwner", ownerInfo);
                        if (!string.IsNullOrEmpty(ownerInfo[0]))
                        {
                            record.User = string.IsNullOrEmpty(ownerInfo[1])
                                ? ownerInfo[0]
                                : $"{ownerInfo[1]}\\{ownerInfo[0]}";
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // Hash the executable (async-safe, but we're in a sync callback)
            if (!string.IsNullOrEmpty(record.ImagePath) && File.Exists(record.ImagePath))
            {
                try
                {
                    var fi = new FileInfo(record.ImagePath);
                    record.FileSize = fi.Length;

                    // Only hash files under 50MB
                    if (fi.Length < 50_000_000)
                    {
                        using var stream = File.OpenRead(record.ImagePath);
                        using var sha = SHA256.Create();
                        byte[] hashBytes = sha.ComputeHash(stream);
                        record.Sha256 = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                        stream.Position = 0;
                        using var md5 = MD5.Create();
                        byte[] md5Bytes = md5.ComputeHash(stream);
                        record.Md5 = BitConverter.ToString(md5Bytes).Replace("-", "").ToLowerInvariant();
                    }
                }
                catch { }
            }
        }

        // ── Snapshot Running Processes ────────────────────────────────────
        private void SnapshotRunningProcesses()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, SessionId FROM Win32_Process");
                int count = 0;
                foreach (ManagementObject obj in searcher.Get())
                {
                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    if (pid <= 4) continue; // Skip System/Idle

                    var record = new ProcessRecord
                    {
                        Pid = pid,
                        ParentPid = Convert.ToInt32(obj["ParentProcessId"] ?? 0),
                        Name = obj["Name"]?.ToString() ?? "",
                        CommandLine = obj["CommandLine"]?.ToString() ?? "",
                        ImagePath = obj["ExecutablePath"]?.ToString() ?? "",
                        SessionId = Convert.ToInt32(obj["SessionId"] ?? 0),
                        StartTime = DateTime.UtcNow, // approximate
                    };

                    _buffer.TryAdd(pid, record);
                    count++;
                }
                _log($"[ProcessMonitor] Snapshot: {count} running processes buffered");
            }
            catch (Exception ex)
            {
                _log($"[ProcessMonitor] Snapshot error: {ex.Message}");
            }
        }

        // ── Buffer Cleanup ───────────────────────────────────────────────
        private void CleanupBuffer(object? state)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-BUFFER_MINUTES);
            int removed = 0;

            // Remove old terminated processes
            foreach (var kvp in _buffer)
            {
                if (kvp.Value.EndTime.HasValue && kvp.Value.EndTime.Value < cutoff)
                {
                    _buffer.TryRemove(kvp.Key, out _);
                    removed++;
                }
                // Also remove very old running processes (orphaned entries)
                else if (kvp.Value.StartTime < cutoff.AddMinutes(-5))
                {
                    // Check if still running
                    try { Process.GetProcessById(kvp.Key); }
                    catch
                    {
                        _buffer.TryRemove(kvp.Key, out _);
                        removed++;
                    }
                }
            }

            // Hard cap
            if (_buffer.Count > MAX_BUFFER_SIZE)
            {
                var oldest = _buffer.OrderBy(kvp => kvp.Value.StartTime)
                    .Take(_buffer.Count - MAX_BUFFER_SIZE)
                    .Select(kvp => kvp.Key).ToList();
                foreach (var pid in oldest) _buffer.TryRemove(pid, out _);
                removed += oldest.Count;
            }

            // Cleanup cooldown entries
            var cooldownCutoff = DateTime.UtcNow.AddSeconds(-TREE_COOLDOWN_SEC * 2);
            foreach (var kvp in _treeCooldown)
            {
                if (kvp.Value < cooldownCutoff)
                    _treeCooldown.TryRemove(kvp.Key, out _);
            }

            if (removed > 0)
                _log($"[ProcessMonitor] Cleanup: removed {removed}, buffer={_buffer.Count}");
        }

        // ── Stats ────────────────────────────────────────────────────────
        public (int bufferSize, int observed, int treesCaptured) GetStats()
        {
            return (_buffer.Count, _processesObserved, _treesCaptures);
        }

        // ── Dispose ──────────────────────────────────────────────────────
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            _startWatcher?.Dispose();
            _stopWatcher?.Dispose();
            _cleanupTimer?.Dispose();
        }
    }
}
