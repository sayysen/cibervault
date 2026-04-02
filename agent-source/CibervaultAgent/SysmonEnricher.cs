// =====================================================================
// Cibervault EDR Agent - Sysmon Enricher
// Reads Sysmon events from Windows Event Log to enrich process trees
// with network connections, file operations, registry changes, DNS queries
//
// Add to: CibervaultAgent/SysmonEnricher.cs
// =====================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace CibervaultAgent
{
    // -- Enrichment data models --

    public class SysmonNetworkEvent
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string Protocol { get; set; } = "";
        public string SourceIp { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestIp { get; set; } = "";
        public int DestPort { get; set; }
        public string DestHostname { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public bool Initiated { get; set; }
    }

    public class SysmonFileEvent
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string Operation { get; set; } = "";  // Created, Modified, Deleted
        public string TargetFile { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public string Hash { get; set; } = "";
    }

    public class SysmonRegistryEvent
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string Operation { get; set; } = "";  // SetValue, CreateKey, DeleteKey
        public string TargetObject { get; set; } = "";
        public string Details { get; set; } = "";
        public string Timestamp { get; set; } = "";
    }

    public class SysmonDnsEvent
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string QueryName { get; set; } = "";
        public string QueryResult { get; set; } = "";
        public string Timestamp { get; set; } = "";
    }

    public class SysmonImageLoadEvent
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string Hash { get; set; } = "";
        public bool Signed { get; set; }
        public string Signature { get; set; } = "";
        public string Timestamp { get; set; } = "";
    }

    public class SysmonEnrichmentData
    {
        public List<SysmonNetworkEvent> NetworkEvents { get; set; } = new();
        public List<SysmonFileEvent> FileEvents { get; set; } = new();
        public List<SysmonRegistryEvent> RegistryEvents { get; set; } = new();
        public List<SysmonDnsEvent> DnsEvents { get; set; } = new();
        public List<SysmonImageLoadEvent> ImageLoads { get; set; } = new();
        public int TotalEventsFound { get; set; }
        public bool SysmonAvailable { get; set; }
    }

    /// <summary>
    /// Reads Sysmon events from Windows Event Log to enrich process trees.
    /// Call EnrichTree() after a process tree is captured.
    /// </summary>
    public static class SysmonEnricher
    {
        const string SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational";
        const int MAX_EVENTS_PER_TYPE = 100;

        // Sysmon Event IDs
        const int SYSMON_PROCESS_CREATE = 1;
        const int SYSMON_NETWORK_CONNECT = 3;
        const int SYSMON_IMAGE_LOAD = 7;
        const int SYSMON_FILE_CREATE = 11;
        const int SYSMON_REG_ADD_DELETE = 12;
        const int SYSMON_REG_SET_VALUE = 13;
        const int SYSMON_REG_RENAME = 14;
        const int SYSMON_FILE_STREAM = 15;
        const int SYSMON_DNS_QUERY = 22;

        /// <summary>
        /// Check if Sysmon event log exists and is accessible.
        /// </summary>
        public static bool IsSysmonAvailable()
        {
            try
            {
                using var session = new EventLogSession();
                var logNames = session.GetLogNames();
                foreach (var name in logNames)
                {
                    if (name.Equals(SYSMON_LOG, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Enrich a captured process tree with Sysmon data.
        /// Queries Sysmon logs for all events related to the PIDs in the tree
        /// within a time window around the capture.
        /// </summary>
        public static SysmonEnrichmentData EnrichTree(ProcessTreeEvent tree, int windowMinutes = 5)
        {
            var result = new SysmonEnrichmentData();

            if (!IsSysmonAvailable())
            {
                result.SysmonAvailable = false;
                return result;
            }
            result.SysmonAvailable = true;

            // Get all PIDs from the tree
            var pids = new HashSet<int>();
            foreach (var proc in tree.Processes)
            {
                pids.Add(proc.Pid);
                if (proc.ParentPid > 0) pids.Add(proc.ParentPid);
            }

            if (pids.Count == 0) return result;

            // Build time window
            var captureTime = tree.CaptureTime;
            var startTime = captureTime.AddMinutes(-windowMinutes);
            var endTime = captureTime.AddMinutes(windowMinutes);

            // Build XPath query for Sysmon events matching our PIDs
            // We query for network, file, registry, DNS events
            var eventIds = new[] {
                SYSMON_NETWORK_CONNECT, SYSMON_FILE_CREATE,
                SYSMON_REG_ADD_DELETE, SYSMON_REG_SET_VALUE, SYSMON_REG_RENAME,
                SYSMON_DNS_QUERY, SYSMON_IMAGE_LOAD, SYSMON_FILE_STREAM
            };
            var eventIdFilter = string.Join(" or ", eventIds.Select(id => "EventID=" + id));

            // Time filter in XPath format
            var startTicks = startTime.ToFileTimeUtc();
            var endTicks = endTime.ToFileTimeUtc();

            var xpath = "*[System[(" + eventIdFilter + ") and " +
                        "TimeCreated[@SystemTime>='" + startTime.ToUniversalTime().ToString("o") + "' and " +
                        "@SystemTime<='" + endTime.ToUniversalTime().ToString("o") + "']]]";

            try
            {
                var query = new EventLogQuery(SYSMON_LOG, PathType.LogName, xpath);
                using var reader = new EventLogReader(query);

                EventRecord? evt;
                int totalFound = 0;

                while ((evt = reader.ReadEvent()) != null)
                {
                    using (evt)
                    {
                        try
                        {
                            // Get ProcessId from event properties
                            var props = GetEventProperties(evt);
                            int eventPid = GetIntProp(props, "ProcessId");

                            // Only include events from our tree PIDs
                            if (!pids.Contains(eventPid)) continue;
                            totalFound++;

                            var eventId = evt.Id;
                            var timestamp = evt.TimeCreated?.ToUniversalTime().ToString("o") ?? "";
                            var processName = GetStringProp(props, "Image");
                            if (string.IsNullOrEmpty(processName))
                                processName = GetStringProp(props, "ProcessName");

                            // Parse by event type
                            switch (eventId)
                            {
                                case SYSMON_NETWORK_CONNECT:
                                    if (result.NetworkEvents.Count < MAX_EVENTS_PER_TYPE)
                                    {
                                        result.NetworkEvents.Add(new SysmonNetworkEvent
                                        {
                                            Pid = eventPid,
                                            ProcessName = processName,
                                            Protocol = GetStringProp(props, "Protocol"),
                                            SourceIp = GetStringProp(props, "SourceIp"),
                                            SourcePort = GetIntProp(props, "SourcePort"),
                                            DestIp = GetStringProp(props, "DestinationIp"),
                                            DestPort = GetIntProp(props, "DestinationPort"),
                                            DestHostname = GetStringProp(props, "DestinationHostname"),
                                            Initiated = GetStringProp(props, "Initiated").ToLower() == "true",
                                            Timestamp = timestamp,
                                        });
                                    }
                                    break;

                                case SYSMON_FILE_CREATE:
                                case SYSMON_FILE_STREAM:
                                    if (result.FileEvents.Count < MAX_EVENTS_PER_TYPE)
                                    {
                                        result.FileEvents.Add(new SysmonFileEvent
                                        {
                                            Pid = eventPid,
                                            ProcessName = processName,
                                            Operation = eventId == SYSMON_FILE_CREATE ? "Created" : "StreamCreated",
                                            TargetFile = GetStringProp(props, "TargetFilename"),
                                            Hash = GetStringProp(props, "Hash"),
                                            Timestamp = timestamp,
                                        });
                                    }
                                    break;

                                case SYSMON_REG_ADD_DELETE:
                                case SYSMON_REG_SET_VALUE:
                                case SYSMON_REG_RENAME:
                                    if (result.RegistryEvents.Count < MAX_EVENTS_PER_TYPE)
                                    {
                                        string regOp = eventId switch
                                        {
                                            SYSMON_REG_ADD_DELETE => GetStringProp(props, "EventType"),
                                            SYSMON_REG_SET_VALUE => "SetValue",
                                            SYSMON_REG_RENAME => "Rename",
                                            _ => "Unknown"
                                        };
                                        result.RegistryEvents.Add(new SysmonRegistryEvent
                                        {
                                            Pid = eventPid,
                                            ProcessName = processName,
                                            Operation = regOp,
                                            TargetObject = GetStringProp(props, "TargetObject"),
                                            Details = GetStringProp(props, "Details"),
                                            Timestamp = timestamp,
                                        });
                                    }
                                    break;

                                case SYSMON_DNS_QUERY:
                                    if (result.DnsEvents.Count < MAX_EVENTS_PER_TYPE)
                                    {
                                        result.DnsEvents.Add(new SysmonDnsEvent
                                        {
                                            Pid = eventPid,
                                            ProcessName = processName,
                                            QueryName = GetStringProp(props, "QueryName"),
                                            QueryResult = GetStringProp(props, "QueryResults"),
                                            Timestamp = timestamp,
                                        });
                                    }
                                    break;

                                case SYSMON_IMAGE_LOAD:
                                    if (result.ImageLoads.Count < MAX_EVENTS_PER_TYPE)
                                    {
                                        result.ImageLoads.Add(new SysmonImageLoadEvent
                                        {
                                            Pid = eventPid,
                                            ProcessName = processName,
                                            ImagePath = GetStringProp(props, "ImageLoaded"),
                                            Hash = GetStringProp(props, "Hashes"),
                                            Signed = GetStringProp(props, "Signed").ToLower() == "true",
                                            Signature = GetStringProp(props, "Signature"),
                                            Timestamp = timestamp,
                                        });
                                    }
                                    break;
                            }
                        }
                        catch { /* skip malformed events */ }
                    }
                }

                result.TotalEventsFound = totalFound;
            }
            catch (Exception ex)
            {
                // Log error but don't fail the tree capture
                result.SysmonAvailable = false;
            }

            return result;
        }

        // -- Helper: extract event properties into a dictionary --
        private static Dictionary<string, string> GetEventProperties(EventRecord evt)
        {
            var props = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                // Parse the XML to get named properties
                var xml = evt.ToXml();
                if (string.IsNullOrEmpty(xml)) return props;

                // Simple XML parsing without System.Xml dependency
                // Look for <Data Name="key">value</Data> patterns
                int pos = 0;
                while (true)
                {
                    int start = xml.IndexOf("<Data Name=\"", pos);
                    if (start < 0) break;

                    int nameStart = start + 12; // length of <Data Name="
                    int nameEnd = xml.IndexOf("\"", nameStart);
                    if (nameEnd < 0) break;

                    string name = xml.Substring(nameStart, nameEnd - nameStart);

                    int valStart = xml.IndexOf(">", nameEnd);
                    if (valStart < 0) break;
                    valStart++; // skip >

                    int valEnd = xml.IndexOf("</Data>", valStart);
                    if (valEnd < 0) break;

                    string value = xml.Substring(valStart, valEnd - valStart);
                    props[name] = value;

                    pos = valEnd + 7; // skip </Data>
                }
            }
            catch { }

            return props;
        }

        private static string GetStringProp(Dictionary<string, string> props, string key)
        {
            return props.TryGetValue(key, out var val) ? val : "";
        }

        private static int GetIntProp(Dictionary<string, string> props, string key)
        {
            if (props.TryGetValue(key, out var val) && int.TryParse(val, out var num))
                return num;
            return 0;
        }
    }
}
