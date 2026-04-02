/**
 * Cibervault EDR — Incidents Visualization Module
 * Process tree, MITRE ATT&CK heatmap, Attack timeline
 *
 * Usage: CvIncidents.renderProcessTree(containerId, eventId)
 *        CvIncidents.renderMitreMatrix(containerId)
 *        CvIncidents.renderAttackTimeline(containerId, agentId)
 */
var CvIncidents = (function() {
    'use strict';

    function apiFetch(url) {
        var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
        return fetch(url, {
            headers: { 'Authorization': 'Bearer ' + token }
        }).then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    var SEV_COLORS = {
        critical: '#ff453a', high: '#ff9f0a', medium: '#ffd60a',
        low: '#32d74b', info: '#636366'
    };

    // ═══════════════════════════════════════════════════════════════════
    //  1. PROCESS TREE
    // ═══════════════════════════════════════════════════════════════════
    function renderProcessTree(containerId, eventId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<div class="cv-skeleton" style="height:200px;margin:12px 0"></div>';

        apiFetch('/api/v1/charts/process-tree/' + encodeURIComponent(eventId))
        .then(function(d) {
            if (d.error) {
                el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">' + d.error + '</div>';
                return;
            }

            var nodes = d.nodes || [];
            var edges = d.edges || [];

            if (!nodes.length) {
                el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">No process data for this event</div>';
                return;
            }

            // Build adjacency: parent -> children
            var children = {};
            var hasParent = {};
            for (var i = 0; i < edges.length; i++) {
                var f = edges[i].from;
                var t = edges[i].to;
                if (!children[f]) children[f] = [];
                children[f].push(t);
                hasParent[t] = true;
            }

            // Find root nodes (no parent in edges)
            var nodeMap = {};
            for (var j = 0; j < nodes.length; j++) {
                nodeMap[nodes[j].id] = nodes[j];
            }

            var roots = [];
            for (var k = 0; k < nodes.length; k++) {
                if (!hasParent[nodes[k].id]) {
                    roots.push(nodes[k].id);
                }
            }
            // If no root found, use first node
            if (!roots.length && nodes.length) roots.push(nodes[0].id);

            // Render tree recursively
            var html = '<div class="ptree-container">'
                     + '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">'
                     + '<span style="font-size:14px">🌲</span>'
                     + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Process Tree</span>'
                     + '<span style="font-size:10px;color:var(--text3)">Host: ' + (d.hostname || '?') + '</span>'
                     + '</div>';

            for (var r = 0; r < roots.length; r++) {
                html += _renderNode(roots[r], nodeMap, children, 0, eventId);
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function(e) {
            el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">Error: ' + e.message + '</div>';
        });
    }

    function _renderNode(nodeId, nodeMap, children, depth, targetEventId) {
        var node = nodeMap[nodeId];
        if (!node) return '';

        var isRoot = node.event_id === targetEventId;
        var isSusp = node.risk_score && node.risk_score >= 50;
        var sevColor = SEV_COLORS[node.severity] || SEV_COLORS.info;

        // Node icon based on process name
        var name = (node.name || 'unknown').toLowerCase();
        var icon = '⚙️';
        if (name.indexOf('cmd') >= 0 || name.indexOf('powershell') >= 0 || name.indexOf('bash') >= 0) icon = '💻';
        else if (name.indexOf('svchost') >= 0 || name.indexOf('services') >= 0) icon = '🔧';
        else if (name.indexOf('explorer') >= 0) icon = '📁';
        else if (name.indexOf('chrome') >= 0 || name.indexOf('firefox') >= 0 || name.indexOf('edge') >= 0) icon = '🌐';
        else if (name.indexOf('word') >= 0 || name.indexOf('excel') >= 0 || name.indexOf('winword') >= 0) icon = '📄';
        else if (isSusp) icon = '⚠️';

        var html = '<div class="ptree-item" style="margin-bottom:6px">';
        html += '<div class="ptree-node' + (isRoot ? ' root' : '') + (isSusp ? ' suspicious' : '') + '"'
             + ' onclick="CvIncidents._onNodeClick(\'' + (node.event_id || '') + '\')"'
             + ' title="' + _escHtml(node.cmdline || node.name || '') + '">';
        html += '<div class="node-icon" style="background:' + sevColor + '22">' + icon + '</div>';
        html += '<div>';
        html += '<div class="node-name">' + _escHtml(node.name || 'unknown') + '</div>';
        html += '<div style="display:flex;gap:8px;align-items:center">';
        html += '<span class="node-pid">PID:' + (node.pid || '?') + '</span>';
        if (node.user) html += '<span class="node-user">' + _escHtml(node.user) + '</span>';
        if (node.mitre_id) html += '<span class="atk-tag mitre">' + node.mitre_id + '</span>';
        html += '</div>';
        if (node.cmdline) {
            html += '<div style="font-size:9px;color:var(--text3);font-family:var(--mono);margin-top:3px;'
                  + 'max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
                  + _escHtml(node.cmdline) + '</div>';
        }
        html += '</div>';
        // Risk badge
        if (node.risk_score && node.risk_score > 0) {
            html += '<span style="margin-left:auto;font-family:var(--mono);font-size:11px;font-weight:700;color:'
                  + sevColor + '">' + Math.round(node.risk_score) + '</span>';
        }
        html += '</div>'; // close ptree-node

        // Render children
        var kids = children[nodeId] || [];
        if (kids.length > 0) {
            html += '<div class="ptree-branch">';
            for (var i = 0; i < kids.length; i++) {
                html += _renderNode(kids[i], nodeMap, children, depth + 1, targetEventId);
            }
            html += '</div>';
        }
        html += '</div>'; // close ptree-item
        return html;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  2. MITRE ATT&CK HEATMAP MATRIX
    // ═══════════════════════════════════════════════════════════════════
    function renderMitreMatrix(containerId, hours) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<div class="cv-skeleton" style="height:300px"></div>';
        hours = hours || 168;

        apiFetch('/api/v1/charts/mitre-heatmap?hours=' + hours)
        .then(function(d) {
            var techniques = d.techniques || [];
            var tactics = d.tactics || [];

            if (!techniques.length) {
                el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:60px;font-size:12px">'
                             + '<div style="font-size:32px;margin-bottom:8px">🎯</div>'
                             + 'No MITRE ATT&CK detections in the last ' + hours + ' hours</div>';
                return;
            }

            // Group techniques by tactic
            var byTactic = {};
            for (var i = 0; i < techniques.length; i++) {
                var tac = techniques[i].tactic;
                if (!byTactic[tac]) byTactic[tac] = [];
                byTactic[tac].push(techniques[i]);
            }

            // Find max count for heat scaling
            var maxCount = Math.max.apply(null, techniques.map(function(t) { return t.count; }));

            // Standard tactic order
            var TACTIC_ORDER = [
                'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                'Defense Evasion', 'Credential Access', 'Discovery',
                'Lateral Movement', 'Collection', 'Command and Control',
                'Exfiltration', 'Impact'
            ];

            var activeTactics = TACTIC_ORDER.filter(function(t) { return byTactic[t] && byTactic[t].length > 0; });
            // Add any non-standard tactics
            Object.keys(byTactic).forEach(function(t) {
                if (activeTactics.indexOf(t) < 0) activeTactics.push(t);
            });

            var colCount = Math.min(activeTactics.length, 14);
            var html = '<div style="margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">'
                     + '<div style="display:flex;align-items:center;gap:8px">'
                     + '<span style="font-size:14px">🎯</span>'
                     + '<span style="font-weight:700;font-size:13px;color:var(--text1)">MITRE ATT&CK Matrix</span>'
                     + '<span style="font-size:10px;color:var(--text3)">Last ' + hours + 'h</span>'
                     + '</div>'
                     + '<div style="display:flex;gap:6px;align-items:center;font-size:9px;color:var(--text3)">'
                     + '<span>Low</span>'
                     + '<div style="display:flex;gap:1px">'
                     + '<div style="width:16px;height:8px;border-radius:2px" class="mitre-heat-1"></div>'
                     + '<div style="width:16px;height:8px;border-radius:2px" class="mitre-heat-2"></div>'
                     + '<div style="width:16px;height:8px;border-radius:2px" class="mitre-heat-3"></div>'
                     + '<div style="width:16px;height:8px;border-radius:2px" class="mitre-heat-4"></div>'
                     + '</div>'
                     + '<span>High</span>'
                     + '</div></div>';

            html += '<div class="mitre-matrix" style="grid-template-columns:repeat(' + colCount + ',1fr)">';

            for (var c = 0; c < activeTactics.length; c++) {
                var tactic = activeTactics[c];
                var techs = byTactic[tactic] || [];
                // Sort by count desc
                techs.sort(function(a, b) { return b.count - a.count; });

                // Tactic total
                var tacTotal = 0;
                for (var ti = 0; ti < techs.length; ti++) tacTotal += techs[ti].count;

                html += '<div class="mitre-tactic-col">';
                html += '<div class="mitre-tactic-header">' + tactic
                      + '<div style="font-size:11px;font-weight:800;margin-top:2px;color:var(--text1)">' + tacTotal + '</div></div>';

                for (var t2 = 0; t2 < techs.length; t2++) {
                    var tech = techs[t2];
                    var ratio = tech.count / (maxCount || 1);
                    var heat = ratio > 0.75 ? 4 : ratio > 0.5 ? 3 : ratio > 0.25 ? 2 : 1;

                    html += '<div class="mitre-technique mitre-heat-' + heat + '"'
                          + ' onclick="CvIncidents._onTechniqueClick(\'' + tech.technique_id + '\')"'
                          + ' title="' + tech.technique_id + ' — ' + tech.count + ' events (max score: ' + tech.max_score + ')">';
                    html += '<span class="tech-id">' + tech.technique_id + '</span>';
                    html += '<span class="tech-count">' + tech.count + '</span>';
                    html += '</div>';
                }
                html += '</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function(e) {
            el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">Error: ' + e.message + '</div>';
        });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  3. ATTACK TIMELINE
    // ═══════════════════════════════════════════════════════════════════
    function renderAttackTimeline(containerId, agentId, hours) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<div class="cv-skeleton" style="height:300px"></div>';
        hours = hours || 24;

        var url = '/api/v1/charts/attack-timeline?hours=' + hours;
        if (agentId) url += '&agent_id=' + encodeURIComponent(agentId);

        apiFetch(url)
        .then(function(d) {
            var events = d.events || [];
            if (!events.length) {
                el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:60px;font-size:12px">'
                             + '<div style="font-size:32px;margin-bottom:8px">📋</div>'
                             + 'No suspicious events in the last ' + hours + ' hours</div>';
                return;
            }

            var html = '<div style="margin-bottom:10px;display:flex;align-items:center;gap:8px">'
                     + '<span style="font-size:14px">📋</span>'
                     + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Attack Timeline</span>'
                     + '<span style="font-size:10px;color:var(--text3)">' + events.length + ' events · Last ' + hours + 'h</span>'
                     + '</div>';

            html += '<div class="atk-timeline">';

            var prevDate = '';
            for (var i = 0; i < events.length; i++) {
                var ev = events[i];
                var sev = ev.severity || 'info';
                var time = (ev.time || '').replace('T', ' ').replace('Z', '').slice(0, 19);
                var dateStr = time.slice(0, 10);

                // Date separator
                if (dateStr !== prevDate) {
                    html += '<div style="font-size:10px;font-weight:700;color:var(--accent);margin:12px 0 6px;text-transform:uppercase;letter-spacing:0.5px">'
                          + dateStr + '</div>';
                    prevDate = dateStr;
                }

                html += '<div class="atk-event sev-' + sev + ' cv-animate-in"'
                      + ' style="animation-delay:' + (i * 30) + 'ms"'
                      + ' onclick="CvIncidents._onTimelineClick(\'' + ev.event_id + '\')">';
                html += '<div class="atk-time">' + time.slice(11) + '</div>';
                html += '<div class="atk-title">' + _escHtml(ev.rule_name || ev.event_type || 'Event') + '</div>';

                // Description
                if (ev.description) {
                    html += '<div style="font-size:11px;color:var(--text2);margin:2px 0;max-height:36px;overflow:hidden">'
                          + _escHtml(ev.description.slice(0, 150)) + '</div>';
                }

                html += '<div class="atk-meta">';
                html += '<span class="badge badge-' + sev + '" style="font-size:9px;padding:1px 6px">' + sev.toUpperCase() + '</span>';
                if (ev.risk_score) html += '<span class="atk-tag" style="color:' + (SEV_COLORS[sev] || SEV_COLORS.info) + '">' + Math.round(ev.risk_score) + '/100</span>';
                if (ev.mitre_id) html += '<span class="atk-tag mitre">' + ev.mitre_id + '</span>';
                if (ev.tactic) html += '<span class="atk-tag">' + ev.tactic + '</span>';
                if (ev.hostname) html += '<span class="atk-tag host">' + _escHtml(ev.hostname) + '</span>';
                if (ev.source_ip) html += '<span class="atk-tag">' + ev.source_ip + '</span>';
                html += '</div>';
                html += '</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function(e) {
            el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">Error: ' + e.message + '</div>';
        });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  4. INCIDENT STATS SUMMARY ROW
    // ═══════════════════════════════════════════════════════════════════
    function renderIncidentStats(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        apiFetch('/api/v1/charts/severity-distribution?hours=24')
        .then(function(d) {
            var dist = d.distribution || {};
            var total = d.total || 0;

            var html = '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:14px">';
            var items = [
                { label: 'Critical', val: dist.critical || 0, color: SEV_COLORS.critical },
                { label: 'High',     val: dist.high || 0,     color: SEV_COLORS.high },
                { label: 'Medium',   val: dist.medium || 0,   color: SEV_COLORS.medium },
                { label: 'Low',      val: dist.low || 0,      color: SEV_COLORS.low },
                { label: 'Total',    val: total,               color: '#64d2ff' },
            ];
            for (var i = 0; i < items.length; i++) {
                html += '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);'
                      + 'padding:10px;text-align:center;border-top:2px solid ' + items[i].color + '">'
                      + '<div style="font-family:var(--mono);font-size:22px;font-weight:800;color:' + items[i].color + '">' + items[i].val + '</div>'
                      + '<div style="font-size:10px;color:var(--text3);text-transform:uppercase;margin-top:3px">' + items[i].label + '</div>'
                      + '</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        })
        .catch(function() {});
    }


    // ── Helpers ──────────────────────────────────────────────────────
    function _escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Click handlers — wire these up in your dashboard
    function _onNodeClick(eventId) {
        if (eventId && typeof openEventDetail === 'function') {
            // Find event in INCIDENTS_DATA or fetch it
            if (typeof INCIDENTS_DATA !== 'undefined') {
                for (var i = 0; i < INCIDENTS_DATA.length; i++) {
                    if (INCIDENTS_DATA[i].event_id === eventId) {
                        openEventDetail(INCIDENTS_DATA[i]);
                        return;
                    }
                }
            }
        }
    }

    function _onTechniqueClick(techniqueId) {
        // Navigate to threat hunting with MITRE ID
        if (typeof showPage === 'function') {
            showPage('hunting');
            var q = document.getElementById('hunt-q');
            if (q) {
                q.value = techniqueId;
                if (typeof doHunt === 'function') doHunt();
            }
        }
    }

    function _onTimelineClick(eventId) {
        _onNodeClick(eventId);
    }

    // Public API
    return {
        renderProcessTree: renderProcessTree,
        renderMitreMatrix: renderMitreMatrix,
        renderAttackTimeline: renderAttackTimeline,
        renderIncidentStats: renderIncidentStats,
        _onNodeClick: _onNodeClick,
        _onTechniqueClick: _onTechniqueClick,
        _onTimelineClick: _onTimelineClick,
    };
})();
