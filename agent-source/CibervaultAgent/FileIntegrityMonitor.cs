// ═══════════════════════════════════════════════════════════════════════════
// Cibervault EDR Agent — Windows File Integrity Monitor
// Watches sensitive paths using FileSystemWatcher + periodic hash checks:
//   - System32 critical DLLs and executables
//   - Windows hosts file, drivers/etc
//   - Startup folders and Run keys (registry)
//   - Scheduled tasks directory
//   - User profile sensitive locations
// ═══════════════════════════════════════════════════════════════════════════

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.Win32;

namespace CibervaultAgent
{
    public class FIMEvent
    {
        public string EventType { get; set; } = "";     // file_create, file_modify, file_delete, registry_change
        public string Path { get; set; } = "";
        public string Action { get; set; } = "";        // created, modified, deleted, renamed
        public string OldHash { get; set; } = "";
        public string NewHash { get; set; } = "";
        public string OldValue { get; set; } = "";
        public string NewValue { get; set; } = "";
        public long FileSize { get; set; }
        public string Owner { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "high";
        public int RiskScore { get; set; } = 70;
        public string MitreId { get; set; } = "";
        public string MitreTactic { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public bool IsSuspicious { get; set; } = true;
    }

    public class FileIntegrityMonitor : IDisposable
    {
        private const int HASH_CHECK_INTERVAL_MS = 300000; // 5 minutes
        private const int REG_CHECK_INTERVAL_MS = 60000;   // 1 minute

        // Sensitive file paths to monitor with FileSystemWatcher
        private static readonly string[] WatchDirs = new[]
        {
            @"C:\Windows\System32\drivers\etc",     // hosts, networks, protocol
            @"C:\Windows\System32\config",           // SAM, SYSTEM, SECURITY hives
            @"C:\Windows\Tasks",                     // Legacy scheduled tasks
            @"C:\Windows\System32\Tasks",            // Modern scheduled tasks
        };

        // Individual critical files to hash-check periodically
        private static readonly string[] CriticalFiles = new[]
        {
            @"C:\Windows\System32\drivers\etc\hosts",
            @"C:\Windows\System32\drivers\etc\lmhosts.sam",
            @"C:\Windows\System32\config\SAM",
            @"C:\Windows\System32\config\SYSTEM",
            @"C:\Windows\System32\config\SECURITY",
            @"C:\Windows\win.ini",
            @"C:\Windows\System32\cmd.exe",
            @"C:\Windows\System32\powershell.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"C:\Windows\System32\net.exe",
            @"C:\Windows\System32\net1.exe",
            @"C:\Windows\System32\schtasks.exe",
            @"C:\Windows\System32\reg.exe",
            @"C:\Windows\System32\wscript.exe",
            @"C:\Windows\System32\cscript.exe",
            @"C:\Windows\System32\mshta.exe",
            @"C:\Windows\System32\rundll32.exe",
            @"C:\Windows\System32\regsvr32.exe",
            @"C:\Windows\System32\certutil.exe",
            @"C:\Windows\System32\bitsadmin.exe",
        };

        // Critical registry keys to monitor
        private static readonly (string Hive, string Key, string Name)[] RegistryKeys = new[]
        {
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
            ("HKLM", @"SYSTEM\CurrentControlSet\Services", "Services"),
            ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC"),
            ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "UserRun"),
            ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "UserRunOnce"),
        };

        // Startup folders
        private static readonly string[] StartupDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };

        private readonly ConcurrentDictionary<string, string> _fileBaselines = new(); // path → sha256
        private readonly ConcurrentDictionary<string, string> _regBaselines = new();  // key → value hash
        private readonly List<FileSystemWatcher> _watchers = new();
        private Timer? _hashTimer;
        private Timer? _regTimer;
        private readonly Action<FIMEvent> _onEvent;
        private readonly Action<string> _log;
        private bool _disposed;
        private bool _baselined;

        public FileIntegrityMonitor(Action<FIMEvent> onEvent, Action<string> log)
        {
            _onEvent = onEvent ?? throw new ArgumentNullException(nameof(onEvent));
            _log = log ?? throw new ArgumentNullException(nameof(log));
        }

        public void Start()
        {
            _log("[FIM] Starting File Integrity Monitor...");

            // Build initial baselines
            BuildFileBaseline();
            BuildRegistryBaseline();

            // Set up FileSystemWatchers for directories
            foreach (var dir in WatchDirs.Concat(StartupDirs))
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;

                    var watcher = new FileSystemWatcher(dir)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                      NotifyFilters.Size | NotifyFilters.CreationTime,
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true,
                    };
                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileChanged;
                    watcher.Deleted += OnFileDeleted;
                    watcher.Renamed += OnFileRenamed;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _log($"[FIM] Cannot watch {dir}: {ex.Message}");
                }
            }

            _log($"[FIM] Watching {_watchers.Count} directories");

            // Start periodic hash checks
            _hashTimer = new Timer(HashCheckCallback, null, HASH_CHECK_INTERVAL_MS, HASH_CHECK_INTERVAL_MS);
            _regTimer = new Timer(RegistryCheckCallback, null, REG_CHECK_INTERVAL_MS, REG_CHECK_INTERVAL_MS);

            _baselined = true;
            _log($"[FIM] Baseline: {_fileBaselines.Count} files, {_regBaselines.Count} registry keys");
        }

        public void Stop()
        {
            _hashTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            _regTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
            }
        }

        // ── File Baseline ────────────────────────────────────────────
        private void BuildFileBaseline()
        {
            foreach (var path in CriticalFiles)
            {
                var hash = HashFile(path);
                if (hash != null)
                {
                    _fileBaselines[path] = hash;
                }
            }

            // Also baseline startup folder files
            foreach (var dir in StartupDirs)
            {
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    foreach (var file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        var hash = HashFile(file);
                        if (hash != null)
                            _fileBaselines[file] = hash;
                    }
                }
                catch { }
            }
        }

        private void BuildRegistryBaseline()
        {
            foreach (var (hive, key, name) in RegistryKeys)
            {
                try
                {
                    var rootKey = hive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                    using var regKey = rootKey.OpenSubKey(key, false);
                    if (regKey == null) continue;

                    var values = regKey.GetValueNames()
                        .Select(n => $"{n}={regKey.GetValue(n)}")
                        .OrderBy(v => v)
                        .ToList();

                    var hash = ComputeStringHash(string.Join("|", values));
                    _regBaselines[$"{hive}\\{key}"] = hash;
                }
                catch { }
            }
        }

        // ── FileSystemWatcher Events ─────────────────────────────────
        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!_baselined) return;
            _onEvent(new FIMEvent
            {
                EventType = "file_create",
                Path = e.FullPath,
                Action = "created",
                Description = $"New file in sensitive directory: {e.FullPath}",
                Severity = IsStartupPath(e.FullPath) ? "critical" : "high",
                RiskScore = IsStartupPath(e.FullPath) ? 85 : 70,
                MitreId = IsStartupPath(e.FullPath) ? "T1547.001" : "T1543",
                MitreTactic = "Persistence",
                Timestamp = DateTime.UtcNow.ToString("o"),
            });

            // Add to baseline
            var hash = HashFile(e.FullPath);
            if (hash != null) _fileBaselines[e.FullPath] = hash;
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!_baselined) return;

            var newHash = HashFile(e.FullPath);
            if (newHash == null) return;

            _fileBaselines.TryGetValue(e.FullPath, out var oldHash);
            if (oldHash == newHash) return; // No actual content change

            var isCritical = CriticalFiles.Contains(e.FullPath, StringComparer.OrdinalIgnoreCase);

            _onEvent(new FIMEvent
            {
                EventType = "file_modify",
                Path = e.FullPath,
                Action = "modified",
                OldHash = oldHash ?? "",
                NewHash = newHash,
                Description = $"Sensitive file modified: {e.FullPath}",
                Severity = isCritical ? "critical" : "high",
                RiskScore = isCritical ? 85 : 65,
                MitreId = e.FullPath.Contains("hosts", StringComparison.OrdinalIgnoreCase) ? "T1565.001" : "T1222",
                MitreTactic = "Defense Evasion",
                Timestamp = DateTime.UtcNow.ToString("o"),
            });

            _fileBaselines[e.FullPath] = newHash;
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (!_baselined) return;
            _fileBaselines.TryRemove(e.FullPath, out _);

            _onEvent(new FIMEvent
            {
                EventType = "file_delete",
                Path = e.FullPath,
                Action = "deleted",
                Description = $"Sensitive file deleted: {e.FullPath}",
                Severity = "critical",
                RiskScore = 80,
                MitreId = "T1070.004",
                MitreTactic = "Defense Evasion",
                Timestamp = DateTime.UtcNow.ToString("o"),
            });
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!_baselined) return;
            _fileBaselines.TryRemove(e.OldFullPath, out _);

            _onEvent(new FIMEvent
            {
                EventType = "file_modify",
                Path = e.FullPath,
                Action = "renamed",
                OldValue = e.OldFullPath,
                NewValue = e.FullPath,
                Description = $"Sensitive file renamed: {e.OldName} → {e.Name}",
                Severity = "high",
                RiskScore = 65,
                MitreId = "T1036.003",
                MitreTactic = "Defense Evasion",
                Timestamp = DateTime.UtcNow.ToString("o"),
            });
        }

        // ── Periodic Hash Check ──────────────────────────────────────
        private void HashCheckCallback(object? state)
        {
            foreach (var path in CriticalFiles)
            {
                try
                {
                    if (!File.Exists(path))
                    {
                        if (_fileBaselines.TryRemove(path, out _))
                        {
                            _onEvent(new FIMEvent
                            {
                                EventType = "file_delete",
                                Path = path,
                                Action = "deleted",
                                Description = $"Critical system file missing: {path}",
                                Severity = "critical",
                                RiskScore = 95,
                                MitreId = "T1070.004",
                                MitreTactic = "Defense Evasion",
                                Timestamp = DateTime.UtcNow.ToString("o"),
                            });
                        }
                        continue;
                    }

                    var currentHash = HashFile(path);
                    if (currentHash == null) continue;

                    if (_fileBaselines.TryGetValue(path, out var baseline) && baseline != currentHash)
                    {
                        _onEvent(new FIMEvent
                        {
                            EventType = "file_modify",
                            Path = path,
                            Action = "modified",
                            OldHash = baseline,
                            NewHash = currentHash,
                            Description = $"Critical file hash changed: {Path.GetFileName(path)}",
                            Severity = "critical",
                            RiskScore = 90,
                            MitreId = "T1574",
                            MitreTactic = "Persistence",
                            Timestamp = DateTime.UtcNow.ToString("o"),
                        });
                        _fileBaselines[path] = currentHash;
                    }
                }
                catch { }
            }
        }

        // ── Registry Check ───────────────────────────────────────────
        private void RegistryCheckCallback(object? state)
        {
            foreach (var (hive, key, name) in RegistryKeys)
            {
                try
                {
                    var rootKey = hive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                    using var regKey = rootKey.OpenSubKey(key, false);
                    if (regKey == null) continue;

                    var values = regKey.GetValueNames()
                        .Select(n => $"{n}={regKey.GetValue(n)}")
                        .OrderBy(v => v)
                        .ToList();

                    var currentHash = ComputeStringHash(string.Join("|", values));
                    var regPath = $"{hive}\\{key}";

                    if (_regBaselines.TryGetValue(regPath, out var baseline))
                    {
                        if (baseline != currentHash)
                        {
                            // Find what changed
                            var desc = $"Registry modified: {name} ({regPath})";

                            _onEvent(new FIMEvent
                            {
                                EventType = "registry_change",
                                Path = regPath,
                                Action = "modified",
                                OldHash = baseline,
                                NewHash = currentHash,
                                Description = desc,
                                Severity = name.Contains("Run") ? "critical" : "high",
                                RiskScore = name.Contains("Run") ? 85 : 65,
                                MitreId = name.Contains("Run") ? "T1547.001" : "T1112",
                                MitreTactic = name.Contains("Run") ? "Persistence" : "Defense Evasion",
                                Timestamp = DateTime.UtcNow.ToString("o"),
                            });
                            _regBaselines[regPath] = currentHash;
                        }
                    }
                    else
                    {
                        _regBaselines[regPath] = currentHash;
                    }
                }
                catch { }
            }
        }

        // ── Helpers ──────────────────────────────────────────────────
        private static string? HashFile(string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                var fi = new FileInfo(path);
                if (fi.Length > 50 * 1024 * 1024) return $"too_large_{fi.Length}"; // Skip >50MB

                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLower();
            }
            catch { return null; }
        }

        private static string ComputeStringHash(string input)
        {
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input))).Replace("-", "").ToLower();
        }

        private static bool IsStartupPath(string path)
        {
            return path.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains("\\Run\\", StringComparison.OrdinalIgnoreCase);
        }

        public (int filesTracked, int registryKeys) GetStats()
        {
            return (_fileBaselines.Count, _regBaselines.Count);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            foreach (var w in _watchers) w.Dispose();
            _hashTimer?.Dispose();
            _regTimer?.Dispose();
        }
    }
}
