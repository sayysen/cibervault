/**
 * Cibervault EDR - Agent Update Manager
 * Dashboard module for binary uploads, policy management, update push
 */
var CvUpdates = (function() {
    'use strict';

    function api(url, opts) {
        var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
        opts = opts || {};
        if (!opts.headers) opts.headers = {};
        opts.headers['Authorization'] = 'Bearer ' + token;
        if (!opts.headers['Content-Type'] && !(opts.body instanceof FormData))
            opts.headers['Content-Type'] = 'application/json';
        return fetch(url, opts).then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    // ================================================================
    //  RENDER MAIN UPDATE PANEL
    // ================================================================
    function renderUpdatePanel(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        var html = '<div style="margin-bottom:14px">'
            + '<div style="display:flex;gap:6px;margin-bottom:14px">'
            + '<button class="filter-btn active" id="upd-tab-binaries" onclick="CvUpdates.showTab(\'binaries\')">Agent Binaries</button>'
            + '<button class="filter-btn" id="upd-tab-policies" onclick="CvUpdates.showTab(\'policies\')">Detection Policies</button>'
            + '<button class="filter-btn" id="upd-tab-push" onclick="CvUpdates.showTab(\'push\')">Push Updates</button>'
            + '<button class="filter-btn" id="upd-tab-tasks" onclick="CvUpdates.showTab(\'tasks\')">Update History</button>'
            + '</div>'
            + '<div id="upd-panel-binaries"></div>'
            + '<div id="upd-panel-policies" style="display:none"></div>'
            + '<div id="upd-panel-push" style="display:none"></div>'
            + '<div id="upd-panel-tasks" style="display:none"></div>'
            + '</div>';

        el.innerHTML = html;
        loadBinaries();
    }

    function showTab(tab) {
        var tabs = ['binaries', 'policies', 'push', 'tasks'];
        for (var i = 0; i < tabs.length; i++) {
            var p = document.getElementById('upd-panel-' + tabs[i]);
            var b = document.getElementById('upd-tab-' + tabs[i]);
            if (p) p.style.display = tabs[i] === tab ? '' : 'none';
            if (b) b.classList.toggle('active', tabs[i] === tab);
        }
        if (tab === 'binaries') loadBinaries();
        if (tab === 'policies') loadPolicies();
        if (tab === 'push') loadPushPanel();
        if (tab === 'tasks') loadTasks();
    }

    // ================================================================
    //  BINARIES TAB
    // ================================================================
    function loadBinaries() {
        var el = document.getElementById('upd-panel-binaries');
        if (!el) return;

        var html = '<div class="card">'
            + '<div class="card-title">Agent Binaries</div>'
            + '<div style="font-size:11px;color:var(--text3);margin-bottom:12px">'
            + 'Upload agent executables. The active binary is used for push updates.</div>'
            + '<div style="display:flex;gap:8px;align-items:flex-end;margin-bottom:14px;flex-wrap:wrap">'
            + '<div><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Agent EXE</label>'
            + '<input type="file" id="upd-file" accept=".exe" style="font-size:12px;color:var(--text1)"></div>'
            + '<div><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Version</label>'
            + '<input type="text" id="upd-version" placeholder="3.0.1" class="inp" style="width:100px"></div>'
            + '<div><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Notes</label>'
            + '<input type="text" id="upd-notes" placeholder="What changed" class="inp" style="width:200px"></div>'
            + '<button class="btn btn-primary" onclick="CvUpdates.uploadBinary()">Upload</button>'
            + '</div>'
            + '<div id="upd-binary-list"></div>'
            + '</div>';
        el.innerHTML = html;

        api('/api/v1/admin/agent-binaries').then(function(d) {
            var bins = d.binaries || [];
            if (!bins.length) {
                document.getElementById('upd-binary-list').innerHTML = '<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">No binaries uploaded yet</div>';
                return;
            }
            var tbl = '<table><thead><tr><th>Version</th><th>Filename</th><th>Size</th><th>SHA256</th><th>Uploaded</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
            for (var i = 0; i < bins.length; i++) {
                var b = bins[i];
                var size = b.file_size ? (b.file_size / 1024 / 1024).toFixed(1) + ' MB' : '?';
                var hash = b.sha256 ? b.sha256.substring(0, 12) + '...' : '';
                var time = (b.uploaded_at || '').replace('T', ' ').slice(0, 16);
                var active = b.is_active ? '<span class="badge badge-online">ACTIVE</span>' : '<span class="badge badge-offline">inactive</span>';
                tbl += '<tr>'
                    + '<td style="font-weight:600;color:var(--accent)">' + (b.version || '?') + '</td>'
                    + '<td class="mono" style="font-size:11px">' + (b.filename || '') + '</td>'
                    + '<td>' + size + '</td>'
                    + '<td class="mono" style="font-size:10px;color:var(--text3)" title="' + (b.sha256 || '') + '">' + hash + '</td>'
                    + '<td style="font-size:11px;color:var(--text3)">' + time + '</td>'
                    + '<td>' + active + '</td>'
                    + '<td style="display:flex;gap:4px">'
                    + (b.is_active ? '' : '<button class="btn btn-sm btn-primary" onclick="CvUpdates.activateBinary(\'' + b.binary_id + '\')">Activate</button>')
                    + '<button class="btn btn-sm btn-danger" onclick="CvUpdates.deleteBinary(\'' + b.binary_id + '\')">Delete</button>'
                    + '</td></tr>';
            }
            tbl += '</tbody></table>';
            document.getElementById('upd-binary-list').innerHTML = '<div class="table-wrap">' + tbl + '</div>';
        }).catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    function uploadBinary() {
        var fileInput = document.getElementById('upd-file');
        var version = (document.getElementById('upd-version') || {}).value || '';
        var notes = (document.getElementById('upd-notes') || {}).value || '';
        if (!fileInput || !fileInput.files.length) { if (typeof toast === 'function') toast('Select a file', 'error'); return; }
        if (!version) { if (typeof toast === 'function') toast('Enter a version', 'error'); return; }

        var fd = new FormData();
        fd.append('file', fileInput.files[0]);
        fd.append('version', version);
        fd.append('notes', notes);
        fd.append('platform', 'win-x64');

        var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
        fetch('/api/v1/admin/agent-binary/upload', {
            method: 'POST', body: fd,
            headers: { 'Authorization': 'Bearer ' + token }
        }).then(function(r) { return r.json(); })
        .then(function(d) {
            if (d.binary_id) {
                if (typeof toast === 'function') toast('Binary uploaded: v' + version, 'success');
                loadBinaries();
            } else { if (typeof toast === 'function') toast('Upload failed', 'error'); }
        }).catch(function(e) { if (typeof toast === 'function') toast('Upload error: ' + e.message, 'error'); });
    }

    function activateBinary(id) {
        api('/api/v1/admin/agent-binary/' + id + '/activate', { method: 'POST' })
        .then(function() { if (typeof toast === 'function') toast('Binary activated', 'success'); loadBinaries(); })
        .catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    function deleteBinary(id) {
        if (!confirm('Delete this binary?')) return;
        api('/api/v1/admin/agent-binary/' + id, { method: 'DELETE' })
        .then(function() { if (typeof toast === 'function') toast('Binary deleted', 'success'); loadBinaries(); })
        .catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    // ================================================================
    //  POLICIES TAB
    // ================================================================
    function loadPolicies() {
        var el = document.getElementById('upd-panel-policies');
        if (!el) return;

        api('/api/v1/admin/policies').then(function(d) {
            var pols = d.policies || [];
            var html = '<div class="card"><div class="card-title">Detection Policies</div>'
                + '<div style="font-size:11px;color:var(--text3);margin-bottom:12px">'
                + 'Manage detection rules, suspicious patterns, and monitoring thresholds. Assign policies to agents.</div>';

            for (var i = 0; i < pols.length; i++) {
                var p = pols[i];
                var pd = p.policy_data || {};
                var det = pd.detection || {};
                var pm = pd.process_monitor || {};
                var isDefault = p.is_default ? ' (DEFAULT)' : '';

                html += '<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:14px;margin-bottom:10px">'
                    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
                    + '<div><span style="font-weight:700;color:var(--text1)">' + (p.name || '?') + isDefault + '</span>'
                    + '<span style="font-size:10px;color:var(--text3);margin-left:8px">v' + (p.version || 1) + '</span></div>'
                    + '<div style="display:flex;gap:4px">'
                    + '<button class="btn btn-sm" onclick="CvUpdates.editPolicy(\'' + p.policy_id + '\')">Edit</button>'
                    + (p.is_default ? '' : '<button class="btn btn-sm btn-danger" onclick="CvUpdates.deletePolicy(\'' + p.policy_id + '\')">Delete</button>')
                    + '</div></div>'
                    + '<div style="font-size:11px;color:var(--text2)">' + (p.description || '') + '</div>'
                    + '<div style="display:flex;gap:12px;margin-top:8px;font-size:10px;color:var(--text3)">'
                    + '<span>LOLBins: ' + ((det.lolbins || []).length) + '</span>'
                    + '<span>Cmd Patterns: ' + ((det.suspicious_cmd_patterns || []).length) + '</span>'
                    + '<span>Parent Rules: ' + Object.keys(det.suspicious_parents || {}).length + '</span>'
                    + '<span>Process Monitor: ' + (pm.enabled ? 'ON' : 'OFF') + '</span>'
                    + '<span>Sysmon: ' + (pm.sysmon_enrichment ? 'ON' : 'OFF') + '</span>'
                    + '</div></div>';
            }

            html += '<button class="btn btn-primary" style="margin-top:8px" onclick="CvUpdates.createPolicy()">+ New Policy</button>';
            html += '</div>';
            el.innerHTML = html;
        }).catch(function(e) { el.innerHTML = '<div style="color:var(--text3);padding:20px">Error: ' + e.message + '</div>'; });
    }

    function editPolicy(policyId) {
        api('/api/v1/admin/policies').then(function(d) {
            var pol = (d.policies || []).find(function(p) { return p.policy_id === policyId; });
            if (!pol) return;
            _openPolicyEditor(pol);
        });
    }

    function createPolicy() {
        _openPolicyEditor({
            policy_id: null,
            name: 'New Policy',
            description: '',
            policy_data: {
                process_monitor: { enabled: true, buffer_minutes: 10, max_buffer_size: 5000, tree_cooldown_sec: 30, sysmon_enrichment: true },
                detection: { suspicious_parents: {}, suspicious_cmd_patterns: [], suspicious_paths: [], lolbins: [] },
                heartbeat_interval_sec: 10, command_poll_interval_sec: 5
            }
        });
    }

    function _openPolicyEditor(pol) {
        var pd = pol.policy_data || {};
        var jsonStr = JSON.stringify(pd, null, 2);

        var overlay = document.createElement('div');
        overlay.id = 'policy-overlay';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center';

        var modal = document.createElement('div');
        modal.style.cssText = 'background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:90%;max-width:700px;max-height:85vh;overflow-y:auto';

        modal.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
            + '<div style="font-size:16px;font-weight:700;color:var(--text1)">' + (pol.policy_id ? 'Edit Policy' : 'Create Policy') + '</div>'
            + '<button onclick="document.getElementById(\'policy-overlay\').remove()" style="background:none;border:none;color:var(--text3);font-size:18px;cursor:pointer">X</button></div>'
            + '<div style="margin-bottom:10px"><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Name</label>'
            + '<input type="text" id="pol-name" class="inp" value="' + (pol.name || '') + '" style="width:100%"></div>'
            + '<div style="margin-bottom:10px"><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Description</label>'
            + '<input type="text" id="pol-desc" class="inp" value="' + (pol.description || '') + '" style="width:100%"></div>'
            + '<div style="margin-bottom:14px"><label style="font-size:10px;color:var(--text3);display:block;margin-bottom:3px">Policy JSON</label>'
            + '<textarea id="pol-json" style="width:100%;height:350px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text1);padding:10px;font-family:var(--mono);font-size:11px;resize:vertical">' + jsonStr.replace(/</g,'&lt;') + '</textarea></div>'
            + '<div style="display:flex;gap:8px">'
            + '<button class="btn btn-primary" onclick="CvUpdates._savePolicy(\'' + (pol.policy_id || '') + '\')">Save Policy</button>'
            + '<button class="btn" onclick="document.getElementById(\'policy-overlay\').remove()">Cancel</button></div>';

        overlay.appendChild(modal);
        overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
        document.body.appendChild(overlay);
    }

    function _savePolicy(policyId) {
        var name = (document.getElementById('pol-name') || {}).value || 'Policy';
        var desc = (document.getElementById('pol-desc') || {}).value || '';
        var jsonText = (document.getElementById('pol-json') || {}).value || '{}';
        var pd;
        try { pd = JSON.parse(jsonText); } catch (e) { if (typeof toast === 'function') toast('Invalid JSON: ' + e.message, 'error'); return; }

        var body = { name: name, description: desc, policy_data: pd };
        var url = policyId ? '/api/v1/admin/policies/' + policyId : '/api/v1/admin/policies';
        var method = policyId ? 'PUT' : 'POST';

        api(url, { method: method, body: JSON.stringify(body) })
        .then(function() {
            document.getElementById('policy-overlay').remove();
            if (typeof toast === 'function') toast('Policy saved', 'success');
            loadPolicies();
        }).catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    function deletePolicy(id) {
        if (!confirm('Delete this policy?')) return;
        api('/api/v1/admin/policies/' + id, { method: 'DELETE' })
        .then(function() { if (typeof toast === 'function') toast('Policy deleted', 'success'); loadPolicies(); })
        .catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    // ================================================================
    //  PUSH UPDATES TAB
    // ================================================================
    function loadPushPanel() {
        var el = document.getElementById('upd-panel-push');
        if (!el) return;

        // Load agents and binaries/policies
        Promise.all([
            api('/api/v1/dashboard/agents'),
            api('/api/v1/admin/agent-binaries'),
            api('/api/v1/admin/policies')
        ]).then(function(results) {
            var agents = results[0] || [];
            var bins = (results[1].binaries || []);
            var pols = (results[2].policies || []);

            var html = '<div class="card"><div class="card-title">Push Updates to Agents</div>'
                + '<div style="font-size:11px;color:var(--text3);margin-bottom:14px">'
                + 'Select agents and push a binary update or policy change.</div>';

            // Agent selection
            html += '<div style="margin-bottom:14px"><label style="font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;display:block;margin-bottom:6px">Select Agents</label>';
            html += '<div style="display:flex;gap:6px;margin-bottom:6px"><button class="btn btn-sm" onclick="CvUpdates._selectAll(true)">Select All</button><button class="btn btn-sm" onclick="CvUpdates._selectAll(false)">Deselect All</button></div>';
            html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px">';
            for (var i = 0; i < agents.length; i++) {
                var a = agents[i];
                var online = a.status === 'online';
                html += '<label style="display:flex;align-items:center;gap:6px;padding:6px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:12px">'
                    + '<input type="checkbox" class="upd-agent-cb" value="' + a.agent_id + '" ' + (online ? 'checked' : '') + '>'
                    + '<span style="color:' + (online ? 'var(--low)' : 'var(--text3)') + '">' + (online ? '●' : '○') + '</span>'
                    + '<span style="color:var(--text1)">' + (a.hostname || a.agent_id.slice(0, 12)) + '</span>'
                    + '<span style="font-size:9px;color:var(--text3);margin-left:auto">' + (a.agent_version || '?') + '</span>'
                    + '</label>';
            }
            html += '</div></div>';

            // Update type selection
            html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">';

            // Binary push
            html += '<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px">'
                + '<div style="font-weight:700;font-size:13px;color:var(--text1);margin-bottom:8px">Binary Update</div>'
                + '<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Push a new agent executable to selected endpoints</div>'
                + '<select id="upd-push-binary" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text1);padding:6px;font-size:12px;margin-bottom:8px">'
                + '<option value="">Select a binary...</option>';
            for (var b = 0; b < bins.length; b++) {
                html += '<option value="' + bins[b].binary_id + '">' + bins[b].version + ' - ' + bins[b].filename + (bins[b].is_active ? ' (ACTIVE)' : '') + '</option>';
            }
            html += '</select>'
                + '<button class="btn btn-primary" onclick="CvUpdates.pushBinary()" style="width:100%">Push Binary Update</button>'
                + '</div>';

            // Policy push
            html += '<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px">'
                + '<div style="font-weight:700;font-size:13px;color:var(--text1);margin-bottom:8px">Policy Update</div>'
                + '<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Push detection rules and config to selected endpoints</div>'
                + '<select id="upd-push-policy" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text1);padding:6px;font-size:12px;margin-bottom:8px">'
                + '<option value="">Select a policy...</option>';
            for (var p = 0; p < pols.length; p++) {
                html += '<option value="' + pols[p].policy_id + '">' + pols[p].name + ' v' + pols[p].version + (pols[p].is_default ? ' (DEFAULT)' : '') + '</option>';
            }
            html += '</select>'
                + '<button class="btn btn-primary" onclick="CvUpdates.pushPolicy()" style="width:100%">Push Policy Update</button>'
                + '</div>';

            html += '</div></div>';
            el.innerHTML = html;
        }).catch(function(e) { el.innerHTML = '<div style="color:var(--text3);padding:20px">Error: ' + e.message + '</div>'; });
    }

    function _selectAll(checked) {
        var cbs = document.querySelectorAll('.upd-agent-cb');
        for (var i = 0; i < cbs.length; i++) cbs[i].checked = checked;
    }

    function _getSelectedAgents() {
        var cbs = document.querySelectorAll('.upd-agent-cb:checked');
        var ids = [];
        for (var i = 0; i < cbs.length; i++) ids.push(cbs[i].value);
        return ids;
    }

    function pushBinary() {
        var agents = _getSelectedAgents();
        var binaryId = (document.getElementById('upd-push-binary') || {}).value;
        if (!agents.length) { if (typeof toast === 'function') toast('Select at least one agent', 'error'); return; }
        if (!binaryId) { if (typeof toast === 'function') toast('Select a binary', 'error'); return; }
        if (!confirm('Push binary update to ' + agents.length + ' agent(s)?')) return;

        api('/api/v1/admin/push-update', { method: 'POST', body: JSON.stringify({ agent_ids: agents, binary_id: binaryId }) })
        .then(function(d) { if (typeof toast === 'function') toast('Binary update pushed to ' + d.pushed + ' agents (v' + d.version + ')', 'success'); })
        .catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    function pushPolicy() {
        var agents = _getSelectedAgents();
        var policyId = (document.getElementById('upd-push-policy') || {}).value;
        if (!agents.length) { if (typeof toast === 'function') toast('Select at least one agent', 'error'); return; }
        if (!policyId) { if (typeof toast === 'function') toast('Select a policy', 'error'); return; }
        if (!confirm('Push policy to ' + agents.length + ' agent(s)?')) return;

        api('/api/v1/admin/policies/' + policyId + '/assign', { method: 'POST', body: JSON.stringify({ agent_ids: agents }) })
        .then(function(d) { if (typeof toast === 'function') toast('Policy pushed to ' + d.assigned + ' agents', 'success'); })
        .catch(function(e) { if (typeof toast === 'function') toast('Error: ' + e.message, 'error'); });
    }

    // ================================================================
    //  TASKS TAB
    // ================================================================
    function loadTasks() {
        var el = document.getElementById('upd-panel-tasks');
        if (!el) return;

        api('/api/v1/admin/update-tasks?limit=50').then(function(d) {
            var tasks = d.tasks || [];
            var html = '<div class="card"><div class="card-title">Update History</div>';

            if (!tasks.length) {
                html += '<div style="color:var(--text3);font-size:12px;padding:20px;text-align:center">No update tasks yet</div>';
            } else {
                html += '<div class="table-wrap"><table><thead><tr><th>Time</th><th>Agent</th><th>Type</th><th>Status</th><th>Result</th></tr></thead><tbody>';
                for (var i = 0; i < tasks.length; i++) {
                    var t = tasks[i];
                    var sc = { pending: 'badge-med', completed: 'badge-online', failed: 'badge-crit', applied: 'badge-online' };
                    html += '<tr>'
                        + '<td class="mono" style="font-size:10px">' + (t.created_at || '').replace('T', ' ').slice(0, 16) + '</td>'
                        + '<td style="font-size:12px">' + (t.agent_id || '').slice(0, 16) + '</td>'
                        + '<td><span class="badge badge-info">' + (t.task_type || '') + '</span></td>'
                        + '<td><span class="badge ' + (sc[t.status] || 'badge-info') + '">' + (t.status || '') + '</span></td>'
                        + '<td style="font-size:10px;color:var(--text3);max-width:200px;overflow:hidden;text-overflow:ellipsis">' + (t.result || '-') + '</td>'
                        + '</tr>';
                }
                html += '</tbody></table></div>';
            }

            html += '</div>';
            el.innerHTML = html;
        }).catch(function(e) { el.innerHTML = '<div style="color:var(--text3);padding:20px">Error: ' + e.message + '</div>'; });
    }

    return {
        renderUpdatePanel: renderUpdatePanel,
        showTab: showTab,
        uploadBinary: uploadBinary,
        activateBinary: activateBinary,
        deleteBinary: deleteBinary,
        loadBinaries: loadBinaries,
        loadPolicies: loadPolicies,
        editPolicy: editPolicy,
        createPolicy: createPolicy,
        _savePolicy: _savePolicy,
        deletePolicy: deletePolicy,
        loadPushPanel: loadPushPanel,
        pushBinary: pushBinary,
        pushPolicy: pushPolicy,
        loadTasks: loadTasks,
        _selectAll: _selectAll,
    };
})();
