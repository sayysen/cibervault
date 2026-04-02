/**
 * Cibervault EDR — Enhanced Active Response Module
 * Command history, status tracking, bulk actions, response playbooks
 *
 * Usage: CvResponse.init()
 */
var CvResponse = (function() {
    'use strict';

    function apiFetch(url, opts) {
        var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
        opts = opts || {};
        opts.headers = Object.assign({ 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, opts.headers || {});
        return fetch(url, opts).then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    //  RESPONSE PLAYBOOKS
    // ═══════════════════════════════════════════════════════════════════
    var PLAYBOOKS = [
        {
            id: 'pb-isolate-investigate',
            name: 'Isolate & Investigate',
            icon: '🔒',
            description: 'Isolate a compromised host, collect triage data, and run a Defender scan.',
            steps: [
                { cmd: 'isolate_host', params: {}, label: 'Isolate Host' },
                { cmd: 'collect_triage', params: {}, label: 'Collect Triage Data' },
                { cmd: 'defender_scan', params: { scan_type: 'quick' }, label: 'Run Defender Quick Scan' },
                { cmd: 'list_connections', params: {}, label: 'List Network Connections' }
            ]
        },
        {
            id: 'pb-block-threat',
            name: 'Block Threat Actor',
            icon: '🚫',
            description: 'Block an IP, kill suspicious processes, and collect forensic evidence.',
            steps: [
                { cmd: 'block_ip', params: { ip: '{ip}' }, label: 'Block IP Address', input: { key: 'ip', placeholder: 'IP to block' } },
                { cmd: 'list_processes', params: {}, label: 'List Running Processes' },
                { cmd: 'collect_triage', params: {}, label: 'Collect Forensics' }
            ]
        },
        {
            id: 'pb-malware-response',
            name: 'Malware Response',
            icon: '🦠',
            description: 'Kill a malicious process, hash the file, collect it, then scan the system.',
            steps: [
                { cmd: 'kill_process', params: { pid: '{pid}' }, label: 'Kill Malicious Process', input: { key: 'pid', placeholder: 'PID to kill' } },
                { cmd: 'hash_file', params: { path: '{filepath}' }, label: 'Hash Malware File', input: { key: 'filepath', placeholder: 'File path' } },
                { cmd: 'collect_file', params: { path: '{filepath}' }, label: 'Collect File for Analysis' },
                { cmd: 'defender_scan', params: { scan_type: 'full' }, label: 'Full Defender Scan' }
            ]
        },
        {
            id: 'pb-credential-theft',
            name: 'Credential Theft Response',
            icon: '🔑',
            description: 'Disable a compromised account, kill suspicious processes, and investigate.',
            steps: [
                { cmd: 'disable_user', params: { username: '{username}' }, label: 'Disable Compromised User', input: { key: 'username', placeholder: 'Username to disable' } },
                { cmd: 'list_processes', params: {}, label: 'List Processes' },
                { cmd: 'collect_triage', params: {}, label: 'Collect Evidence' },
                { cmd: 'list_connections', params: {}, label: 'Check Network Connections' }
            ]
        },
        {
            id: 'pb-full-triage',
            name: 'Full Forensic Triage',
            icon: '🔬',
            description: 'Complete forensic collection: processes, connections, triage data, and system scan.',
            steps: [
                { cmd: 'list_processes', params: {}, label: 'Enumerate Processes' },
                { cmd: 'list_connections', params: {}, label: 'Enumerate Connections' },
                { cmd: 'collect_triage', params: {}, label: 'Collect Triage Package' },
                { cmd: 'defender_scan', params: { scan_type: 'quick' }, label: 'Quick AV Scan' }
            ]
        }
    ];


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER PLAYBOOKS
    // ═══════════════════════════════════════════════════════════════════
    function renderPlaybooks(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        var html = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">'
                 + '<span style="font-size:14px">📖</span>'
                 + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Response Playbooks</span>'
                 + '<span style="font-size:10px;color:var(--text3)">Pre-built response workflows</span>'
                 + '</div>';

        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px">';
        for (var i = 0; i < PLAYBOOKS.length; i++) {
            var pb = PLAYBOOKS[i];
            html += '<div class="playbook-card" onclick="CvResponse.openPlaybook(\'' + pb.id + '\')">';
            html += '<div class="pb-icon">' + pb.icon + '</div>';
            html += '<div class="pb-name">' + pb.name + '</div>';
            html += '<div class="pb-desc">' + pb.description + '</div>';
            html += '<div class="pb-steps">' + pb.steps.length + ' steps</div>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  OPEN PLAYBOOK MODAL
    // ═══════════════════════════════════════════════════════════════════
    function openPlaybook(playbookId) {
        var pb = PLAYBOOKS.find(function(p) { return p.id === playbookId; });
        if (!pb) return;

        // Get available agents for target selection
        apiFetch('/api/v1/dashboard/agents')
        .then(function(agents) {
            var onlineAgents = (agents || []).filter(function(a) { return a.status === 'online'; });

            var overlay = document.createElement('div');
            overlay.id = 'pb-overlay';
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center';

            var modal = document.createElement('div');
            modal.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:500px;width:90%;max-height:80vh;overflow-y:auto';

            var html = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">'
                     + '<div style="display:flex;align-items:center;gap:10px">'
                     + '<span style="font-size:24px">' + pb.icon + '</span>'
                     + '<div><div style="font-size:15px;font-weight:700;color:var(--text1)">' + pb.name + '</div>'
                     + '<div style="font-size:11px;color:var(--text3)">' + pb.description + '</div></div>'
                     + '</div>'
                     + '<button onclick="CvResponse.closePlaybook()" style="background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer">✕</button>'
                     + '</div>';

            // Target agent selector
            html += '<div style="margin-bottom:14px">'
                  + '<label style="font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;display:block;margin-bottom:4px">Target Agent</label>'
                  + '<select id="pb-target-agent" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text1);padding:8px 12px;font-size:13px">';
            if (!onlineAgents.length) {
                html += '<option value="">No online agents</option>';
            }
            for (var a = 0; a < onlineAgents.length; a++) {
                html += '<option value="' + onlineAgents[a].agent_id + '">' + (onlineAgents[a].hostname || onlineAgents[a].agent_id) + ' (' + (onlineAgents[a].ip_address || '?') + ')</option>';
            }
            html += '</select></div>';

            // Input fields for parameterized steps
            for (var s = 0; s < pb.steps.length; s++) {
                var step = pb.steps[s];
                if (step.input) {
                    html += '<div style="margin-bottom:10px">'
                          + '<label style="font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;display:block;margin-bottom:4px">'
                          + step.label + '</label>'
                          + '<input type="text" id="pb-input-' + step.input.key + '" placeholder="' + step.input.placeholder + '"'
                          + ' style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text1);padding:8px 12px;font-size:13px;box-sizing:border-box"/>'
                          + '</div>';
                }
            }

            // Steps list
            html += '<div style="margin-top:14px;border-top:1px solid var(--border);padding-top:12px">'
                  + '<div style="font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;margin-bottom:8px">Execution Steps</div>';
            for (var st = 0; st < pb.steps.length; st++) {
                html += '<div id="pb-step-' + st + '" style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:12px">'
                      + '<span style="width:20px;height:20px;border-radius:50%;background:var(--bg3);border:1px solid var(--border);'
                      + 'display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--text3);flex-shrink:0">' + (st + 1) + '</span>'
                      + '<span style="color:var(--text1)">' + pb.steps[st].label + '</span>'
                      + '<span style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-left:auto">' + pb.steps[st].cmd + '</span>'
                      + '</div>';
            }
            html += '</div>';

            // Execute button
            html += '<div style="margin-top:16px;display:flex;gap:8px">'
                  + '<button id="pb-execute-btn" class="btn btn-primary" style="flex:1;padding:10px"'
                  + ' onclick="CvResponse.executePlaybook(\'' + pb.id + '\')">🚀 Execute Playbook</button>'
                  + '<button class="btn" onclick="CvResponse.closePlaybook()">Cancel</button>'
                  + '</div>';

            modal.innerHTML = html;
            overlay.appendChild(modal);
            overlay.addEventListener('click', function(e) { if (e.target === overlay) CvResponse.closePlaybook(); });
            document.body.appendChild(overlay);
        })
        .catch(function(e) {
            if (typeof toast === 'function') toast('Error loading agents: ' + e.message, 'error');
        });
    }

    function closePlaybook() {
        var ov = document.getElementById('pb-overlay');
        if (ov) ov.parentNode.removeChild(ov);
    }


    // ═══════════════════════════════════════════════════════════════════
    //  EXECUTE PLAYBOOK (sequential command issue)
    // ═══════════════════════════════════════════════════════════════════
    function executePlaybook(playbookId) {
        var pb = PLAYBOOKS.find(function(p) { return p.id === playbookId; });
        if (!pb) return;

        var agentSel = document.getElementById('pb-target-agent');
        var agentId = agentSel ? agentSel.value : '';
        if (!agentId) {
            if (typeof toast === 'function') toast('Select a target agent', 'error');
            return;
        }

        var execBtn = document.getElementById('pb-execute-btn');
        if (execBtn) { execBtn.disabled = true; execBtn.textContent = '⏳ Executing...'; }

        // Gather input values
        var inputValues = {};
        for (var s = 0; s < pb.steps.length; s++) {
            if (pb.steps[s].input) {
                var inp = document.getElementById('pb-input-' + pb.steps[s].input.key);
                inputValues[pb.steps[s].input.key] = inp ? inp.value.trim() : '';
            }
        }

        // Execute steps sequentially
        var stepIdx = 0;
        function runNextStep() {
            if (stepIdx >= pb.steps.length) {
                if (typeof toast === 'function') toast('Playbook "' + pb.name + '" completed!', 'success');
                closePlaybook();
                return;
            }

            var step = pb.steps[stepIdx];
            var stepEl = document.getElementById('pb-step-' + stepIdx);

            // Mark step as running
            if (stepEl) {
                var circle = stepEl.querySelector('span');
                if (circle) { circle.style.background = 'var(--accent)'; circle.style.color = '#fff'; circle.textContent = '⋯'; }
            }

            // Resolve parameters
            var params = JSON.parse(JSON.stringify(step.params));
            Object.keys(params).forEach(function(k) {
                if (typeof params[k] === 'string' && params[k].match(/^\{(\w+)\}$/)) {
                    var key = params[k].replace(/[{}]/g, '');
                    params[k] = inputValues[key] || params[k];
                }
            });

            var ME = (typeof window.ME !== 'undefined') ? window.ME : { username: 'admin' };

            apiFetch('/api/v1/dashboard/issue-command', {
                method: 'POST',
                body: JSON.stringify({
                    agent_id: agentId,
                    command_type: step.cmd,
                    parameters: params,
                    issued_by: ME.username || 'admin'
                })
            })
            .then(function() {
                if (stepEl) {
                    var circle = stepEl.querySelector('span');
                    if (circle) { circle.style.background = 'var(--low)'; circle.textContent = '✓'; }
                }
                stepIdx++;
                // Small delay between commands
                setTimeout(runNextStep, 800);
            })
            .catch(function(e) {
                if (stepEl) {
                    var circle = stepEl.querySelector('span');
                    if (circle) { circle.style.background = 'var(--crit)'; circle.textContent = '✕'; }
                }
                if (typeof toast === 'function') toast('Step failed: ' + e.message, 'error');
                // Continue anyway
                stepIdx++;
                setTimeout(runNextStep, 500);
            });
        }
        runNextStep();
    }


    // ═══════════════════════════════════════════════════════════════════
    //  COMMAND HISTORY LOG
    // ═══════════════════════════════════════════════════════════════════
    function renderCommandHistory(containerId, agentId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<div class="cv-skeleton" style="height:200px"></div>';

        var url = '/api/v1/charts/command-history?limit=50';
        if (agentId) url += '&agent_id=' + encodeURIComponent(agentId);

        apiFetch(url)
        .then(function(d) {
            var cmds = d.commands || [];
            if (!cmds.length) {
                el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">'
                             + '<div style="font-size:24px;margin-bottom:8px">📋</div>No command history</div>';
                return;
            }

            var html = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">'
                     + '<span style="font-size:14px">📋</span>'
                     + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Command History</span>'
                     + '<span style="font-size:10px;color:var(--text3)">' + cmds.length + ' commands</span>'
                     + '</div>';

            // Header
            html += '<div class="ar-history-row" style="font-weight:700;color:var(--text2);font-size:10px;text-transform:uppercase;border-bottom:2px solid var(--border)">'
                  + '<div>Time</div><div>Command</div><div>Agent</div><div>Issued By</div><div>Status</div><div>Duration</div></div>';

            for (var i = 0; i < cmds.length; i++) {
                var cmd = cmds[i];
                var status = cmd.status || 'pending';
                var statusClass = status === 'completed' ? 'completed' : status === 'failed' ? 'failed' : status === 'running' ? 'running' : 'pending';
                var time = (cmd.issued_at || '').replace('T', ' ').slice(0, 16);
                var duration = '';
                if (cmd.issued_at && cmd.completed_at) {
                    try {
                        var ms = new Date(cmd.completed_at) - new Date(cmd.issued_at);
                        duration = ms < 1000 ? ms + 'ms' : (ms / 1000).toFixed(1) + 's';
                    } catch(e) {}
                }

                html += '<div class="ar-history-row">'
                      + '<div style="font-family:var(--mono);color:var(--text3)">' + time + '</div>'
                      + '<div style="font-weight:600;color:var(--accent)">' + (cmd.command_type || '?') + '</div>'
                      + '<div style="color:var(--text2)">' + (cmd.agent_id || '?').slice(0, 12) + '</div>'
                      + '<div style="color:var(--text3)">' + (cmd.issued_by || '?') + '</div>'
                      + '<div><span class="ar-status-badge ' + statusClass + '">' + status + '</span></div>'
                      + '<div style="font-family:var(--mono);color:var(--text3)">' + (duration || '-') + '</div>'
                      + '</div>';

                // Show result if completed
                if (cmd.result && status === 'completed') {
                    var resultText = typeof cmd.result === 'object' ? JSON.stringify(cmd.result).slice(0, 200) : String(cmd.result).slice(0, 200);
                    html += '<div style="padding:4px 12px 8px;font-size:10px;font-family:var(--mono);color:var(--text3);'
                          + 'background:var(--bg);border-bottom:1px solid var(--border);max-height:60px;overflow:hidden">'
                          + _escHtml(resultText) + '</div>';
                }
            }
            el.innerHTML = html;
        })
        .catch(function(e) {
            el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:12px">Error: ' + e.message + '</div>';
        });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  BULK ACTIONS
    // ═══════════════════════════════════════════════════════════════════
    function renderBulkActions(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        var html = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">'
                 + '<span style="font-size:14px">⚡</span>'
                 + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Quick Actions</span>'
                 + '<span style="font-size:10px;color:var(--text3)">Execute on all online agents</span>'
                 + '</div>';

        var actions = [
            { cmd: 'list_processes', icon: '📋', name: 'List All Processes', desc: 'Enumerate running processes on all agents' },
            { cmd: 'list_connections', icon: '🌐', name: 'Network Audit', desc: 'List active connections on all agents' },
            { cmd: 'defender_scan', icon: '🛡️', name: 'Quick Scan All', desc: 'Run Defender quick scan on all Windows agents', params: { scan_type: 'quick' } },
            { cmd: 'collect_triage', icon: '🔬', name: 'Collect Triage', desc: 'Gather forensic triage from all agents' },
        ];

        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px">';
        for (var i = 0; i < actions.length; i++) {
            var a = actions[i];
            html += '<div class="ar-cmd-card" onclick="CvResponse.executeBulk(\'' + a.cmd + '\', ' + JSON.stringify(a.params || {}).replace(/"/g, '&quot;') + ')">'
                  + '<div class="cmd-icon">' + a.icon + '</div>'
                  + '<div class="cmd-name">' + a.name + '</div>'
                  + '<div class="cmd-desc">' + a.desc + '</div>'
                  + '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function executeBulk(command, params) {
        if (!confirm('Execute "' + command + '" on ALL online agents?')) return;

        apiFetch('/api/v1/dashboard/agents')
        .then(function(agents) {
            var online = (agents || []).filter(function(a) { return a.status === 'online'; });
            if (!online.length) {
                if (typeof toast === 'function') toast('No online agents', 'error');
                return;
            }

            var ME = (typeof window.ME !== 'undefined') ? window.ME : { username: 'admin' };
            var promises = online.map(function(agent) {
                return apiFetch('/api/v1/dashboard/issue-command', {
                    method: 'POST',
                    body: JSON.stringify({
                        agent_id: agent.agent_id,
                        command_type: command,
                        parameters: params || {},
                        issued_by: ME.username || 'admin'
                    })
                }).catch(function() { return null; }); // Don't fail all if one fails
            });

            Promise.all(promises).then(function(results) {
                var success = results.filter(function(r) { return r !== null; }).length;
                if (typeof toast === 'function') toast('Command sent to ' + success + '/' + online.length + ' agents', 'success');
            });
        })
        .catch(function(e) {
            if (typeof toast === 'function') toast('Error: ' + e.message, 'error');
        });
    }


    // ── Helpers ──────────────────────────────────────────────────────
    function _escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function init() {
        // Modules loaded — nothing to wire up globally
    }

    return {
        init: init,
        renderPlaybooks: renderPlaybooks,
        openPlaybook: openPlaybook,
        closePlaybook: closePlaybook,
        executePlaybook: executePlaybook,
        renderCommandHistory: renderCommandHistory,
        renderBulkActions: renderBulkActions,
        executeBulk: executeBulk,
        PLAYBOOKS: PLAYBOOKS,
    };
})();
