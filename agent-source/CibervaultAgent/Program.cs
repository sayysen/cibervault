using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CibervaultAgent
{
    // ======================================================================
    //  WINDOWS SERVICE WRAPPER
    // ======================================================================
    public class CibervaultService : ServiceBase
    {
        private Thread? _workerThread;
        private readonly CancellationTokenSource _cts = new();

        public CibervaultService()
        {
            ServiceName = "CibervaultAgent";
            CanStop = true;
            CanShutdown = true;
        }

        protected override void OnStart(string[] args)
        {
            Agent.WriteLog("[Service] Windows service OnStart called");
            _workerThread = new Thread(() =>
            {
                try
                {
                    Agent.RunAsService(_cts.Token).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    Agent.WriteLog("[Service] Fatal error: " + ex.Message);
                    Stop();
                }
            });
            _workerThread.IsBackground = true;
            _workerThread.Start();
            Agent.WriteLog("[Service] Worker thread started");
        }

        protected override void OnStop()
        {
            Agent.WriteLog("[Service] Windows service OnStop called");
            _cts.Cancel();
            if (_workerThread != null && _workerThread.IsAlive)
                _workerThread.Join(TimeSpan.FromSeconds(10));
            Agent.WriteLog("[Service] Service stopped");
        }

        protected override void OnShutdown() { OnStop(); }
    }

    // ======================================================================
    //  MAIN AGENT CLASS
    // ======================================================================
    public class Agent
    {
        const string VERSION     = "4.0-win-full";
        const string CONFIG_DIR  = @"C:\ProgramData\Cibervault";
        const string CONFIG_FILE = CONFIG_DIR + @"\agent.conf";
        const string STATE_FILE  = CONFIG_DIR + @"\state.json";
        const string LOG_FILE    = CONFIG_DIR + @"\agent.log";
        const int HB_SEC         = 10;
        const int CMD_SEC        = 5;
        const int MAX_LOG        = 5 * 1024 * 1024;

        static string _serverUrl   = "";
        static string _secret      = "";
        static bool   _verifyTls   = true;
        static string _agentId     = "";
        static string _token       = "";
        static HttpClient _http    = null!;
        static ProcessMonitor? _pm;
        static NetworkMonitor? _nm;
        static AuthMonitor? _am;
        static DefenderMonitor? _dm;
        static FileIntegrityMonitor? _fim;
        static CancellationTokenSource _cts = new();
        static readonly object _logLock = new();

        // ==================================================================
        //  ENTRY POINT
        // ==================================================================
        static async Task Main(string[] args)
        {
            // Service mode: hand off to ServiceBase immediately
            if (!Environment.UserInteractive ||
                (args.Length > 0 && args[0].ToLower() == "--service"))
            {
                WriteLog("Agent " + VERSION + " starting as Windows service...");
                ServiceBase.Run(new CibervaultService());
                return;
            }

            // Console mode
            try { Console.Title = "Cibervault EDR Agent v" + VERSION; } catch { }
            WriteLog("Agent " + VERSION + " starting in console mode...");

            if (args.Length > 0)
            {
                switch (args[0].ToLower())
                {
                    case "--install":
                    case "-i":
                        await Setup();
                        return;
                    case "--edit":
                        if (File.Exists(CONFIG_FILE))
                        { Console.WriteLine(File.ReadAllText(CONFIG_FILE)); }
                        else { Console.WriteLine("No config found."); }
                        return;
                    case "--status":
                        ShowStatus();
                        return;
                    default:
                        Console.WriteLine("CibervaultAgent.exe [--install|--edit|--status]");
                        return;
                }
            }

            if (!File.Exists(CONFIG_FILE))
            {
                Console.WriteLine("No configuration found. Starting setup...\n");
                await Setup();
                return;
            }

            LoadConfig();
            if (string.IsNullOrEmpty(_serverUrl) || string.IsNullOrEmpty(_secret))
            {
                Console.WriteLine("Invalid config. Run with --install");
                return;
            }

            MakeHttp();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; _cts.Cancel(); };
            await Run();
        }

        // ==================================================================
        //  SERVICE ENTRY POINT (called by CibervaultService.OnStart)
        // ==================================================================
        public static async Task RunAsService(CancellationToken ct)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            WriteLog("[Service] RunAsService starting...");

            if (!File.Exists(CONFIG_FILE))
            {
                WriteLog("[Service] No config file! Run installer first.");
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(30000, ct);
                    if (File.Exists(CONFIG_FILE)) break;
                }
                if (!File.Exists(CONFIG_FILE)) return;
            }

            LoadConfig();
            if (string.IsNullOrEmpty(_serverUrl) || string.IsNullOrEmpty(_secret))
            {
                WriteLog("[Service] Invalid config. Run installer.");
                return;
            }

            MakeHttp();
            await Run();
        }

        // ==================================================================
        //  MAIN AGENT LOOP
        // ==================================================================
        static async Task Run()
        {
            LoadState();

            if (string.IsNullOrEmpty(_agentId) || string.IsNullOrEmpty(_token))
            {
                int delay = 5;
                while (!_cts.Token.IsCancellationRequested)
                {
                    if (await Enroll()) break;
                    WriteLog("Enrollment failed. Retry in " + delay + "s...");
                    await Task.Delay(delay * 1000, _cts.Token);
                    delay = Math.Min(delay * 2, 120);
                }
            }
            else
            {
                SetAuth();
                WriteLog("Resumed: agent_id=" + _agentId);
            }

            if (_cts.Token.IsCancellationRequested) return;

            // Start process monitor
            try
            {
                _pm = new ProcessMonitor(
                    onTreeCaptured: (tree) => SendTree(tree),
                    log: (msg) => WriteLog(msg));
                _pm.Start();
                WriteLog("[Agent] Process Monitor started (smart mode)");
            }
            catch (Exception ex)
            {
                WriteLog("[!] Process Monitor failed: " + ex.Message);
            }

            // Start network monitor
            try
            {
                _nm = new NetworkMonitor(
                    onEvent: (ne) => SendNetworkEvent(ne),
                    log: (msg) => WriteLog(msg));
                _nm.Start();
                WriteLog("[Agent] Network Monitor started");
            }
            catch (Exception ex) { WriteLog("[!] Network Monitor failed: " + ex.Message); }

            // Start auth monitor (Windows Security Event Log)
            try
            {
                _am = new AuthMonitor(
                    onEvent: (ae) => SendAuthEvent(ae),
                    log: (msg) => WriteLog(msg));
                _am.Start();
                WriteLog("[Agent] Auth Monitor started (Security Event Log)");
            }
            catch (Exception ex) { WriteLog("[!] Auth Monitor failed: " + ex.Message); }

            // Start Windows Defender monitor
            try
            {
                _dm = new DefenderMonitor(
                    onEvent: (de) => SendDefenderEvent(de),
                    log: (msg) => WriteLog(msg));
                _dm.Start();
                WriteLog("[Agent] Defender Monitor started");
            }
            catch (Exception ex) { WriteLog("[!] Defender Monitor failed: " + ex.Message); }

            // Start file integrity monitor
            try
            {
                _fim = new FileIntegrityMonitor(
                    onEvent: (fe) => SendFIMEvent(fe),
                    log: (msg) => WriteLog(msg));
                _fim.Start();
                WriteLog("[Agent] File Integrity Monitor started");
            }
            catch (Exception ex) { WriteLog("[!] FIM failed: " + ex.Message); }


            WriteLog("Agent running: heartbeat=" + HB_SEC + "s, cmdpoll=" + CMD_SEC + "s");
            AppDomain.CurrentDomain.ProcessExit += (s, e) => { _cts.Cancel(); };

            var t1 = LoopSafe("Heartbeat", HeartbeatLoop, _cts.Token);
            var t2 = LoopSafe("CmdPoll", CmdPollLoop, _cts.Token);

            try { await Task.WhenAll(t1, t2); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { WriteLog("[Agent] Error: " + ex.Message); }

            _pm?.Stop();
            _nm?.Stop();
            _nm?.Dispose();
            _am?.Stop();
            _am?.Dispose();
            _dm?.Stop();
            _dm?.Dispose();
            _fim?.Stop();
            _fim?.Dispose();
            _pm?.Dispose();
            WriteLog("Agent stopped.");
        }

        static async Task LoopSafe(string name, Func<CancellationToken, Task> work, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try { await work(ct); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    WriteLog("[" + name + "] Crashed: " + ex.Message + " - restart in 5s");
                    try { await Task.Delay(5000, ct); } catch { break; }
                }
            }
        }

        // ==================================================================
        //  ENROLLMENT
        // ==================================================================
        static async Task<bool> Enroll()
        {
            WriteLog("Enrolling...");
            var payload = new
            {
                hostname = Environment.MachineName,
                ip_address = GetLocalIp(),
                os = "Windows",
                os_version = Environment.OSVersion.Version.ToString(),
                arch = Environment.Is64BitOperatingSystem ? "x64" : "x86",
                agent_version = VERSION,
                agent_secret = _secret,
            };
            var r = await Post("/api/v1/agent/enroll", payload);
            if (r == null) return false;
            var j = r.Value;
            if (j.TryGetProperty("agent_id", out var a) && j.TryGetProperty("token", out var t))
            {
                _agentId = a.GetString() ?? "";
                _token = t.GetString() ?? "";
                SetAuth();
                SaveState();
                WriteLog("Enrolled: agent_id=" + _agentId);
                return true;
            }
            WriteLog("[!] Enrollment response invalid");
            return false;
        }

        // ==================================================================
        //  HEARTBEAT
        // ==================================================================
        static async Task HeartbeatLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var (cpu, mem, disk) = GetResources();
                    var payload = new
                    {
                        agent_id = _agentId,
                        cpu_pct = cpu,
                        mem_pct = mem,
                        disk_pct = disk,
                        agent_version = VERSION,
                    };
                    await Post("/api/v1/agent/heartbeat", payload);
                }
                catch (Exception ex) { WriteLog("[HB] " + ex.Message); }
                await Task.Delay(HB_SEC * 1000, ct);
            }
        }

        // ==================================================================
        //  COMMAND POLLING + EXECUTION
        // ==================================================================
        static async Task CmdPollLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var r = await Get("/api/v1/agent/commands");
                    if (r != null && r.Value.TryGetProperty("commands", out var cmds))
                    {
                        foreach (var cmd in cmds.EnumerateArray())
                        {
                            var cid = cmd.GetProperty("command_id").GetString() ?? "";
                            var ctype = cmd.GetProperty("command_type").GetString() ?? "";
                            var parms = cmd.GetProperty("parameters");
                            WriteLog("[Cmd] " + ctype + " (" + cid.Substring(0, Math.Min(12, cid.Length)) + ")");
                            _ = Task.Run(async () =>
                            {
                                var (ok, output) = await ExecCmd(ctype, parms);
                                await Post("/api/v1/agent/command-result", new
                                {
                                    command_id = cid,
                                    status = ok ? "completed" : "failed",
                                    result = output.Length > 10000 ? output.Substring(0, 10000) : output,
                                    completed_at = DateTime.UtcNow.ToString("o"),
                                });
                            });
                        }
                    }
                }
                catch (Exception ex) { WriteLog("[CmdPoll] " + ex.Message); }
                await Task.Delay(CMD_SEC * 1000, ct);
            }
        }

        static async Task<(bool, string)> ExecCmd(string type, JsonElement p)
        {
            try
            {
                switch (type.ToLower())
                {
                    case "block_ip":
                        var ip = P(p, "ip");
                        return await Shell("netsh advfirewall firewall add rule name=\"CV-Block-" + ip + "\" dir=in action=block remoteip=" + ip + " & " +
                            "netsh advfirewall firewall add rule name=\"CV-Block-" + ip + "-out\" dir=out action=block remoteip=" + ip);
                    case "kill_process":
                        return await Shell("taskkill /F /PID " + P(p, "pid"));
                    case "disable_user":
                        return await Shell("net user " + P(p, "username") + " /active:no");
                    case "isolate_host":
                        var h = ExtractHost(_serverUrl);
                        return await Shell("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound & " +
                            "netsh advfirewall firewall add rule name=\"CV-Allow-SIEM\" dir=out action=allow remoteip=" + h + " & " +
                            "netsh advfirewall firewall add rule name=\"CV-Allow-SIEM-In\" dir=in action=allow remoteip=" + h);
                    case "unisolate_host":
                        return await Shell("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound & " +
                            "netsh advfirewall firewall delete rule name=\"CV-Allow-SIEM\" & " +
                            "netsh advfirewall firewall delete rule name=\"CV-Allow-SIEM-In\"");
                    case "list_processes":
                        return await Shell("tasklist /v /fo csv");
                    case "list_connections":
                        return await Shell("netstat -ano");
                    case "list_sessions":
                        return await Shell("query session");
                    case "collect_triage":
                        return await Triage();
                    case "hash_file":
                        return HashFile(P(p, "path"));
                    case "collect_file":
                        return CollectFile(P(p, "path"));
                    case "defender_scan":
                        var st = P(p, "scan_type", "quick");
                        return await Shell("powershell -Command \"Start-MpScan -ScanType " + (st == "full" ? "FullScan" : "QuickScan") + "\"");
                    case "run_command":
                        var c = P(p, "command");
                        return string.IsNullOrEmpty(c) ? (false, "No command") : await Shell(c);
                    case "self_update":
                        return await SelfUpdate(p);
                    case "policy_update":
                        return await ApplyPolicy(p);
                    default:
                        return (false, "Unknown command: " + type);
                }
            }
            catch (Exception ex) { return (false, "Error: " + ex.Message); }
        }

        // ==================================================================
        //  PROCESS TREE SENDER
        // ==================================================================
        static async void SendTree(ProcessTreeEvent tree)
        {
            try
            {
                // Enrich with Sysmon data before sending
                object? sysmonPayload = null;
                try
                {
                    var sysmon = SysmonEnricher.EnrichTree(tree, windowMinutes: 5);
                    if (sysmon.SysmonAvailable)
                    {
                        WriteLog("[PTree] Sysmon: " +
                            sysmon.NetworkEvents.Count + " net, " +
                            sysmon.FileEvents.Count + " file, " +
                            sysmon.RegistryEvents.Count + " reg, " +
                            sysmon.DnsEvents.Count + " dns, " +
                            sysmon.ImageLoads.Count + " img");
                        sysmonPayload = new
                        {
                            available = true,
                            total_events = sysmon.TotalEventsFound,
                            network = sysmon.NetworkEvents.Select(n => new
                            {
                                pid = n.Pid, process = n.ProcessName, protocol = n.Protocol,
                                src_ip = n.SourceIp, src_port = n.SourcePort,
                                dst_ip = n.DestIp, dst_port = n.DestPort,
                                dst_hostname = n.DestHostname, initiated = n.Initiated, time = n.Timestamp,
                            }).ToList(),
                            files = sysmon.FileEvents.Select(f => new
                            {
                                pid = f.Pid, process = f.ProcessName,
                                operation = f.Operation, target = f.TargetFile,
                                hash = f.Hash, time = f.Timestamp,
                            }).ToList(),
                            registry = sysmon.RegistryEvents.Select(r => new
                            {
                                pid = r.Pid, process = r.ProcessName,
                                operation = r.Operation, target = r.TargetObject,
                                details = r.Details, time = r.Timestamp,
                            }).ToList(),
                            dns = sysmon.DnsEvents.Select(d => new
                            {
                                pid = d.Pid, process = d.ProcessName,
                                query = d.QueryName, result = d.QueryResult, time = d.Timestamp,
                            }).ToList(),
                            image_loads = sysmon.ImageLoads.Select(i => new
                            {
                                pid = i.Pid, process = i.ProcessName,
                                image = i.ImagePath, hash = i.Hash,
                                signed = i.Signed, signature = i.Signature, time = i.Timestamp,
                            }).ToList(),
                        };
                    }
                    else { WriteLog("[PTree] Sysmon not available - tree sent without enrichment"); }
                }
                catch (Exception ex) { WriteLog("[PTree] Sysmon error: " + ex.Message); }

                var payload = new
                {
                    tree_id = tree.TreeId,
                    trigger_pid = tree.TriggerPid,
                    trigger_reason = tree.TriggerReason,
                    root_process = tree.RootProcessName,
                    root_pid = tree.RootPid,
                    capture_time = tree.CaptureTime.ToString("o"),
                    process_count = tree.Processes.Count,
                    processes = tree.Processes.Select(pr => new
                    {
                        pid = pr.Pid, ppid = pr.ParentPid, name = pr.Name,
                        cmdline = (pr.CommandLine ?? "").Length > 2000 ? pr.CommandLine!.Substring(0, 2000) : pr.CommandLine,
                        image_path = pr.ImagePath, user = pr.User, parent_name = pr.ParentName,
                        start_time = pr.StartTime.ToString("o"), end_time = pr.EndTime?.ToString("o"),
                        sha256 = pr.Sha256, md5 = pr.Md5, file_size = pr.FileSize,
                        is_suspicious = pr.IsSuspicious, suspicious_reason = pr.SuspiciousReason,
                        session_id = pr.SessionId,
                    }).ToList(),
                    edges = tree.Edges.Select(e => new { from_pid = e.FromPid, to_pid = e.ToPid }).ToList(),
                    sysmon = sysmonPayload,
                };
                var r = await Post("/api/v1/agent/process-tree", payload);
                WriteLog("[PTree] Sent " + tree.TreeId + " (" + tree.Processes.Count + " procs)");
            }
            catch (Exception ex) { WriteLog("[PTree] Error: " + ex.Message); }
        }

        // ==================================================================
        //  SELF-UPDATE (downloads new binary, replaces, restarts service)
        // ==================================================================
        static async Task<(bool, string)> SelfUpdate(JsonElement p)
        {
            try
            {
                var version = P(p, "version");
                var sha256 = P(p, "sha256");
                var downloadUrl = P(p, "download_url", "/api/v1/agent/update/binary");
                var taskId = P(p, "task_id");

                WriteLog("[Update] Self-update to v" + version);

                var resp = await _http.GetAsync(_serverUrl + downloadUrl);
                if (!resp.IsSuccessStatusCode)
                {
                    var err = "Download failed: HTTP " + resp.StatusCode;
                    WriteLog("[Update] " + err);
                    if (!string.IsNullOrEmpty(taskId))
                        await Post("/api/v1/agent/update/result", new { task_id = taskId, status = "failed", result = err });
                    return (false, err);
                }

                var data = await resp.Content.ReadAsByteArrayAsync();
                WriteLog("[Update] Downloaded " + data.Length + " bytes");

                using var hasher = SHA256.Create();
                var actualHash = BitConverter.ToString(hasher.ComputeHash(data)).Replace("-", "").ToLower();
                if (!string.IsNullOrEmpty(sha256) && actualHash != sha256.ToLower())
                {
                    var err = "Hash mismatch! Expected " + sha256.Substring(0, 12) + " got " + actualHash.Substring(0, 12);
                    WriteLog("[Update] " + err);
                    if (!string.IsNullOrEmpty(taskId))
                        await Post("/api/v1/agent/update/result", new { task_id = taskId, status = "failed", result = err });
                    return (false, err);
                }

                var currentExe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                var tempExe = currentExe + ".update";
                var backupExe = currentExe + ".backup";
                File.WriteAllBytes(tempExe, data);

                if (!string.IsNullOrEmpty(taskId))
                    await Post("/api/v1/agent/update/result", new { task_id = taskId, status = "completed", result = "Updated to v" + version });

                var batPath = Path.Combine(Path.GetTempPath(), "cv_update.bat");
                File.WriteAllText(batPath,
                    "@echo off\r\ntimeout /t 3 /nobreak >nul\r\n" +
                    "net stop CibervaultAgent >nul 2>&1\r\ntimeout /t 2 /nobreak >nul\r\n" +
                    "if exist \"" + backupExe + "\" del /f \"" + backupExe + "\"\r\n" +
                    "move /y \"" + currentExe + "\" \"" + backupExe + "\"\r\n" +
                    "move /y \"" + tempExe + "\" \"" + currentExe + "\"\r\n" +
                    "net start CibervaultAgent\r\ndel /f \"%~f0\"\r\n");

                WriteLog("[Update] Restarting with new binary...");
                Process.Start(new ProcessStartInfo("cmd.exe", "/c \"" + batPath + "\"")
                    { UseShellExecute = false, CreateNoWindow = true });

                return (true, "Self-update to v" + version + " initiated");
            }
            catch (Exception ex) { WriteLog("[Update] " + ex.Message); return (false, "Update error: " + ex.Message); }
        }

        // ==================================================================
        //  POLICY UPDATE (fetches and saves policy from server)
        // ==================================================================
        static async Task<(bool, string)> ApplyPolicy(JsonElement p)
        {
            try
            {
                var policyId = P(p, "policy_id");
                var taskId = P(p, "task_id");
                WriteLog("[Policy] Fetching policy " + policyId);

                var result = await Get("/api/v1/agent/policy");
                if (result == null)
                {
                    if (!string.IsNullOrEmpty(taskId))
                        await Post("/api/v1/agent/update/result", new { task_id = taskId, status = "failed", result = "Failed to fetch policy" });
                    return (false, "Failed to fetch policy");
                }

                var policyPath = CONFIG_DIR + @"\policy.json";
                File.WriteAllText(policyPath, result.Value.ToString());
                WriteLog("[Policy] Saved to " + policyPath);

                if (!string.IsNullOrEmpty(taskId))
                    await Post("/api/v1/agent/update/result", new { task_id = taskId, status = "completed", result = "Policy saved" });

                return (true, "Policy " + policyId + " applied");
            }
            catch (Exception ex) { WriteLog("[Policy] " + ex.Message); return (false, "Policy error: " + ex.Message); }
        }

        // ==================================================================
        //  HELPERS
        // ==================================================================
        static async Task<(bool, string)> Shell(string cmd)
        {
            try
            {
                var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi)!;
                var stdout = await proc.StandardOutput.ReadToEndAsync();
                var stderr = await proc.StandardError.ReadToEndAsync();
                await proc.WaitForExitAsync();
                return (proc.ExitCode == 0, stdout + (string.IsNullOrEmpty(stderr) ? "" : "\nSTDERR: " + stderr));
            }
            catch (Exception ex) { return (false, "Shell error: " + ex.Message); }
        }

        static async Task<(bool, string)> Triage()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== TRIAGE " + DateTime.UtcNow.ToString("o") + " " + Environment.MachineName + " ===");
            var (_, p) = await Shell("tasklist /v /fo csv"); sb.AppendLine("=== PROCESSES ===\n" + p);
            var (_, n) = await Shell("netstat -ano"); sb.AppendLine("=== CONNECTIONS ===\n" + n);
            var (_, s) = await Shell("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"); sb.AppendLine("=== STARTUP ===\n" + s);
            return (true, sb.ToString());
        }

        static (bool, string) HashFile(string path)
        {
            if (!File.Exists(path)) return (false, "File not found: " + path);
            try
            {
                var data = File.ReadAllBytes(path);
                var md5 = BitConverter.ToString(MD5.Create().ComputeHash(data)).Replace("-", "").ToLower();
                var sha = BitConverter.ToString(SHA256.Create().ComputeHash(data)).Replace("-", "").ToLower();
                return (true, "File: " + path + "\nSize: " + data.Length + "\nMD5: " + md5 + "\nSHA256: " + sha);
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        static (bool, string) CollectFile(string path)
        {
            if (!File.Exists(path)) return (false, "File not found");
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length > 5 * 1024 * 1024) return (false, "File too large (>5MB)");
                return (true, "File: " + path + "\nBase64:\n" + Convert.ToBase64String(File.ReadAllBytes(path)));
            }
            catch (Exception ex) { return (false, ex.Message); }
        }

        static string P(JsonElement el, string key, string def = "")
        { return el.TryGetProperty(key, out var v) ? v.GetString() ?? def : def; }

        
        // ==================================================================
        //  EVENT SENDERS FOR NEW MONITORS
        // ==================================================================
        static async void SendNetworkEvent(NetworkEvent ne)
        {
            try
            {
                var payload = new
                {
                    agent_id = _agentId,
                    events = new[] { new {
                        event_id = Guid.NewGuid().ToString(),
                        event_type = ne.EventType,
                        event_time = ne.Timestamp,
                        host = new { hostname = Environment.MachineName },
                        is_suspicious = ne.RiskScore >= 60,
                        mitre_technique = ne.MitreId,
                        mitre_tactic = ne.MitreTactic,
                        network = new {
                            remote_address = ne.RemoteAddress,
                            remote_port = ne.RemotePort,
                            local_port = ne.LocalPort,
                            protocol = ne.Protocol,
                            dst_ip = ne.RemoteAddress,
                        },
                        process = ne.ProcessName,
                        description = ne.Description,
                        severity = ne.Severity,
                        risk_score = ne.RiskScore,
                    }}
                };
                await Post("/api/v1/agent/events", payload);
            }
            catch (Exception ex) { WriteLog("[Net] Send error: " + ex.Message); }
        }

        static async void SendAuthEvent(AuthEvent ae)
        {
            try
            {
                var payload = new
                {
                    agent_id = _agentId,
                    events = new[] { new {
                        event_id = Guid.NewGuid().ToString(),
                        event_type = ae.EventType,
                        event_time = ae.Timestamp,
                        host = new { hostname = Environment.MachineName },
                        is_suspicious = ae.IsSuspicious,
                        mitre_technique = ae.MitreId,
                        mitre_tactic = ae.MitreTactic,
                        auth = new {
                            user = ae.User, source_ip = ae.SourceIp,
                            logon_type = ae.LogonType,
                        },
                        win_event = new {
                            event_id = ae.EventId,
                            source_ip = ae.SourceIp,
                            user = ae.User,
                            domain = ae.Domain,
                            logon_type_name = ae.LogonTypeName,
                            target_user = ae.TargetUser,
                            group = ae.GroupName,
                        },
                        description = ae.Description,
                        severity = ae.Severity,
                        risk_score = ae.RiskScore,
                    }}
                };
                await Post("/api/v1/agent/events", payload);
            }
            catch (Exception ex) { WriteLog("[Auth] Send error: " + ex.Message); }
        }

        static async void SendDefenderEvent(DefenderEvent de)
        {
            try
            {
                var payload = new
                {
                    agent_id = _agentId,
                    events = new[] { new {
                        event_id = Guid.NewGuid().ToString(),
                        event_type = de.EventType,
                        event_time = de.Timestamp,
                        host = new { hostname = Environment.MachineName },
                        is_suspicious = de.IsSuspicious,
                        mitre_technique = de.MitreId,
                        mitre_tactic = de.MitreTactic,
                        win_event = new {
                            event_id = de.EventId,
                            threat_name = de.ThreatName,
                            threat_path = de.ThreatPath,
                            threat_severity = de.ThreatSeverity,
                            action = de.ActionTaken,
                            user = de.User,
                        },
                        description = de.Description,
                        severity = de.Severity,
                        risk_score = de.RiskScore,
                    }}
                };
                await Post("/api/v1/agent/events", payload);
            }
            catch (Exception ex) { WriteLog("[Defender] Send error: " + ex.Message); }
        }

        static async void SendFIMEvent(FIMEvent fe)
        {
            try
            {
                var payload = new
                {
                    agent_id = _agentId,
                    events = new[] { new {
                        event_id = Guid.NewGuid().ToString(),
                        event_type = fe.EventType,
                        event_time = fe.Timestamp,
                        host = new { hostname = Environment.MachineName },
                        is_suspicious = fe.IsSuspicious,
                        mitre_technique = fe.MitreId,
                        mitre_tactic = fe.MitreTactic,
                        file = new {
                            path = fe.Path, action = fe.Action,
                            old_hash = fe.OldHash, new_hash = fe.NewHash,
                        },
                        description = fe.Description,
                        severity = fe.Severity,
                        risk_score = fe.RiskScore,
                    }}
                };
                await Post("/api/v1/agent/events", payload);
            }
            catch (Exception ex) { WriteLog("[FIM] Send error: " + ex.Message); }
        }

static string GetLocalIp()
        {
            try
            {
                using var s = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, 0);
                s.Connect("8.8.8.8", 53);
                return ((System.Net.IPEndPoint)s.LocalEndPoint!).Address.ToString();
            }
            catch { return "127.0.0.1"; }
        }

        static string ExtractHost(string url)
        { try { return new Uri(url).Host; } catch { return url; } }

        static (float, float, float) GetResources()
        {
            float cpu = 0, mem = 0, disk = 0;
            try
            {
                using var proc = Process.GetCurrentProcess();
                mem = (float)(proc.WorkingSet64 * 100.0 / (Environment.SystemPageSize * 1024.0 * 256.0));
                mem = Math.Min(mem, 100f);
                var drive = new DriveInfo("C");
                disk = (float)((drive.TotalSize - drive.AvailableFreeSpace) * 100.0 / drive.TotalSize);
            }
            catch { }
            return (cpu, mem, disk);
        }

        // ==================================================================
        //  HTTP
        // ==================================================================
        static void MakeHttp()
        {
            var handler = new HttpClientHandler();
            if (!_verifyTls)
                handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
            _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        }

        static void SetAuth()
        {
            if (!string.IsNullOrEmpty(_token))
                _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        }

        static async Task<JsonElement?> Post(string ep, object payload)
        {
            try
            {
                var json = JsonSerializer.Serialize(payload);
                var resp = await _http.PostAsync(_serverUrl + ep, new StringContent(json, Encoding.UTF8, "application/json"));
                var body = await resp.Content.ReadAsStringAsync();
                if (!resp.IsSuccessStatusCode)
                { WriteLog("[HTTP] " + ep + " -> " + resp.StatusCode + ": " + body.Substring(0, Math.Min(200, body.Length))); return null; }
                return JsonSerializer.Deserialize<JsonElement>(body);
            }
            catch (Exception ex) { WriteLog("[HTTP] " + ep + " error: " + ex.Message); return null; }
        }

        static async Task<JsonElement?> Get(string ep)
        {
            try
            {
                var resp = await _http.GetAsync(_serverUrl + ep);
                var body = await resp.Content.ReadAsStringAsync();
                if (!resp.IsSuccessStatusCode) return null;
                return JsonSerializer.Deserialize<JsonElement>(body);
            }
            catch (Exception ex) { WriteLog("[HTTP] GET " + ep + " error: " + ex.Message); return null; }
        }

        // ==================================================================
        //  CONFIG / STATE
        // ==================================================================
        static void LoadConfig()
        {
            try
            {
                foreach (var line in File.ReadAllLines(CONFIG_FILE))
                {
                    var t = line.Trim();
                    if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;
                    var parts = t.Split('=', 2);
                    if (parts.Length != 2) continue;
                    switch (parts[0].Trim().ToUpper())
                    {
                        case "CV_SERVER": _serverUrl = parts[1].Trim().TrimEnd('/'); break;
                        case "CV_SECRET": _secret = parts[1].Trim(); break;
                        case "CV_VERIFY_TLS": _verifyTls = parts[1].Trim() != "0"; break;
                    }
                }
                WriteLog("Config loaded: server=" + _serverUrl);
            }
            catch (Exception ex) { WriteLog("[!] Config error: " + ex.Message); }
        }

        static void LoadState()
        {
            try
            {
                if (!File.Exists(STATE_FILE)) return;
                var s = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(STATE_FILE));
                if (s != null) { s.TryGetValue("agent_id", out var a); s.TryGetValue("token", out var t); _agentId = a ?? ""; _token = t ?? ""; }
            }
            catch { }
        }

        static void SaveState()
        {
            try
            {
                Directory.CreateDirectory(CONFIG_DIR);
                File.WriteAllText(STATE_FILE, JsonSerializer.Serialize(new Dictionary<string, string>
                { ["agent_id"] = _agentId, ["token"] = _token, ["version"] = VERSION, ["saved_at"] = DateTime.UtcNow.ToString("o") }));
            }
            catch (Exception ex) { WriteLog("[!] SaveState: " + ex.Message); }
        }

        // ==================================================================
        //  LOGGING
        // ==================================================================
        public static void WriteLog(string msg)
        {
            var line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + msg;
            if (Environment.UserInteractive)
            { try { Console.WriteLine(line); } catch { } }
            lock (_logLock)
            {
                try
                {
                    Directory.CreateDirectory(CONFIG_DIR);
                    if (File.Exists(LOG_FILE) && new FileInfo(LOG_FILE).Length > MAX_LOG)
                    { var bk = LOG_FILE + ".1"; if (File.Exists(bk)) File.Delete(bk); File.Move(LOG_FILE, bk); }
                    File.AppendAllText(LOG_FILE, line + "\n");
                }
                catch { }
            }
        }

        // ==================================================================
        //  INTERACTIVE SETUP
        // ==================================================================
        static async Task Setup()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("  Cibervault EDR Agent Setup v" + VERSION);
            Console.WriteLine("========================================\n");

            Console.Write("Server URL (e.g. https://edr.cibervault.com): ");
            var server = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrEmpty(server)) { Console.WriteLine("Aborted."); return; }

            Console.Write("Agent Secret: ");
            var secret = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrEmpty(secret)) { Console.WriteLine("Aborted."); return; }

            Console.Write("Verify TLS? (Y/n): ");
            var tls = Console.ReadLine()?.Trim().ToLower();
            bool verify = tls != "n" && tls != "no";

            Directory.CreateDirectory(CONFIG_DIR);
            File.WriteAllText(CONFIG_FILE,
                "CV_SERVER=" + server.TrimEnd('/') + "\n" +
                "CV_SECRET=" + secret + "\n" +
                "CV_VERIFY_TLS=" + (verify ? "1" : "0") + "\n");
            Console.WriteLine("\nConfig saved to " + CONFIG_FILE);

            _serverUrl = server.TrimEnd('/'); _secret = secret; _verifyTls = verify;
            MakeHttp();

            Console.Write("\nTesting connection... ");
            var ok = await Enroll();
            Console.WriteLine(ok ? "SUCCESS! Enrolled." : "FAILED. Check server URL and secret.");

            if (ok)
            {
                Console.Write("\nInstall as Windows service? (Y/n): ");
                var svc = Console.ReadLine()?.Trim().ToLower();
                if (svc != "n" && svc != "no")
                {
                    var exe = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                    if (!string.IsNullOrEmpty(exe))
                    {
                        var (s1, o1) = Shell("sc create CibervaultAgent binPath= \"\\\"" + exe + "\\\" --service\" start= auto DisplayName= \"Cibervault EDR Agent\"").Result;
                        Console.WriteLine(s1 ? "[OK] Service installed" : "[!] " + o1);
                        if (s1) { Shell("sc start CibervaultAgent").Wait(); Console.WriteLine("[OK] Service started"); }
                    }
                }
            }

            Console.WriteLine("\nDone. Press any key to exit.");
            Console.ReadKey();
        }

        static void ShowStatus()
        {
            Console.WriteLine("=== Cibervault Agent v" + VERSION + " ===");
            Console.WriteLine("Config: " + (File.Exists(CONFIG_FILE) ? "OK" : "MISSING"));
            Console.WriteLine("State:  " + (File.Exists(STATE_FILE) ? "OK" : "Not enrolled"));
            if (File.Exists(LOG_FILE))
            {
                Console.WriteLine("\n=== Last 10 log lines ===");
                foreach (var line in File.ReadAllLines(LOG_FILE).TakeLast(10))
                    Console.WriteLine(line);
            }
        }
    }
}
