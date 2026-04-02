/**
 * Cibervault EDR — Process Explorer (SentinelOne-style)
 * Visual process tree with horizontal layout, command lines, color coding
 *
 * Usage:
 *   CvProcessExplorer.renderTree('container-id', treeId)
 *   CvProcessExplorer.renderTreeForEvent('container-id', eventId)
 *   CvProcessExplorer.renderTreeList('container-id')   // list all recent trees
 */
var CvProcessExplorer = (function() {
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

    // ── Process Icon Map ────────────────────────────────────────────────
    var PROCESS_ICONS = {
        'cmd.exe': '💻', 'powershell.exe': '⚡', 'pwsh.exe': '⚡',
        'wscript.exe': '📜', 'cscript.exe': '📜', 'mshta.exe': '📜',
        'explorer.exe': '📁', 'svchost.exe': '🔧', 'services.exe': '🔧',
        'lsass.exe': '🔐', 'winlogon.exe': '🔐',
        'chrome.exe': '🌐', 'firefox.exe': '🌐', 'msedge.exe': '🌐', 'iexplore.exe': '🌐',
        'winword.exe': '📄', 'excel.exe': '📊', 'outlook.exe': '📧', 'powerpnt.exe': '📽️',
        'notepad.exe': '📝', 'calc.exe': '🔢',
        'taskmgr.exe': '📋', 'regedit.exe': '🔑',
        'conhost.exe': '▪️', 'csrss.exe': '⬛', 'smss.exe': '⬛',
        'attrib.exe': '🏷️', 'icacls.exe': '🔓', 'cacls.exe': '🔓',
        'certutil.exe': '📜', 'bitsadmin.exe': '📡',
        'net.exe': '🌐', 'net1.exe': '🌐', 'netsh.exe': '🌐',
        'sc.exe': '🔧', 'reg.exe': '🔑', 'schtasks.exe': '⏰',
        'vssadmin.exe': '💾', 'wbadmin.exe': '💾', 'bcdedit.exe': '⚙️',
        'cipher.exe': '🔒', 'rundll32.exe': '🔗', 'regsvr32.exe': '🔗',
        'wmic.exe': '🖥️', 'wmiprvse.exe': '🖥️',
        'taskdl.exe': '⚠️', 'taskse.exe': '⚠️',
    };

    function getIcon(name) {
        return PROCESS_ICONS[(name || '').toLowerCase()] || '⚙️';
    }

    // ── Severity Colors ─────────────────────────────────────────────────
    function getSuspiciousColor(node) {
        if (node.is_suspicious) return '#ff453a';
        if (node.suspicious_reason) return '#ff9f0a';
        return 'transparent';
    }

    // ═══════════════════════════════════════════════════════════════════
    //  RENDER FULL PROCESS TREE (SentinelOne style)
    // ═══════════════════════════════════════════════════════════════════
    function renderTree(containerId, treeId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = _loadingHTML('Loading process tree...');

        apiFetch('/api/v1/process-tree/' + encodeURIComponent(treeId))
        .then(function(data) {
            if (!data.nodes || !data.nodes.length) {
                el.innerHTML = _emptyHTML('No process data in this tree');
                return;
            }
            _buildTreeUI(el, data);
        })
        .catch(function(e) {
            el.innerHTML = _errorHTML(e.message);
        });
    }

    function renderTreeForEvent(containerId, eventId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = _loadingHTML('Building process tree...');

        apiFetch('/api/v1/process-tree/by-event/' + encodeURIComponent(eventId))
        .then(function(data) {
            if (!data.nodes || !data.nodes.length) {
                el.innerHTML = _emptyHTML(data.message || 'No process tree captured for this event');
                return;
            }
            _buildTreeUI(el, data);
        })
        .catch(function(e) {
            el.innerHTML = _errorHTML(e.message);
        });
    }

    // ── Build the visual tree ───────────────────────────────────────────
    function _buildTreeUI(container, data) {
        var nodes = data.nodes || [];
        var edges = data.edges || [];

        // Build adjacency map
        var nodeMap = {};
        var children = {};
        var hasParent = {};

        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            nodeMap[n.pid] = n;
        }

        for (var j = 0; j < edges.length; j++) {
            var e = edges[j];
            var from = e.from || e.from_pid;
            var to = e.to || e.to_pid;
            if (!children[from]) children[from] = [];
            children[from].push(to);
            hasParent[to] = true;
        }

        // Find roots (no incoming edge)
        var roots = [];
        for (var k = 0; k < nodes.length; k++) {
            if (!hasParent[nodes[k].pid]) {
                roots.push(nodes[k].pid);
            }
        }
        if (!roots.length && nodes.length) roots.push(nodes[0].pid);

        // Header bar
        var html = '<div class="pe-container">';

        // Tabs (like SentinelOne)
        html += '<div class="pe-tabs">'
              + '<button class="pe-tab active" onclick="this.parentNode.querySelector(\'.active\').classList.remove(\'active\');this.classList.add(\'active\')">Process Explorer</button>'
              + '<button class="pe-tab" onclick="this.parentNode.querySelector(\'.active\').classList.remove(\'active\');this.classList.add(\'active\')">Network Explorer</button>'
              + '<button class="pe-tab" onclick="this.parentNode.querySelector(\'.active\').classList.remove(\'active\');this.classList.add(\'active\')">MITRE | ATT&CK</button>'
              + '<button class="pe-tab" onclick="this.parentNode.querySelector(\'.active\').classList.remove(\'active\');this.classList.add(\'active\')">Timeline</button>'
              + '</div>';

        // Info bar
        html += '<div class="pe-info">'
              + '<span>🌲 ' + nodes.length + ' processes</span>'
              + '<span>⚠️ ' + nodes.filter(function(n) { return n.is_suspicious; }).length + ' suspicious</span>';
        if (data.trigger_reason) {
            html += '<span style="color:#ff453a">🔥 ' + _esc(data.trigger_reason) + '</span>';
        }
        if (data.hostname) {
            html += '<span>🖥️ ' + _esc(data.hostname) + '</span>';
        }
        html += '</div>';

        // Tree area
        html += '<div class="pe-tree-area">';
        for (var r = 0; r < roots.length; r++) {
            html += _renderNode(roots[r], nodeMap, children, 0, data.trigger_pid);
        }
        html += '</div>';
        html += '</div>';

        container.innerHTML = html;
    }

    // ── Render a single node + its children ─────────────────────────────
    function _renderNode(pid, nodeMap, children, depth, triggerPid) {
        var node = nodeMap[pid];
        if (!node) return '';

        var isTrigger = String(pid) === String(triggerPid);
        var isSusp = node.is_suspicious;
        var icon = getIcon(node.name);
        var borderColor = isTrigger ? '#ff453a' : isSusp ? '#ff9f0a' : '#38383a';
        var bgColor = isTrigger ? 'rgba(255,69,58,0.08)' : isSusp ? 'rgba(255,159,10,0.05)' : 'rgba(255,255,255,0.02)';

        // Build command line display
        var cmdDisplay = '';
        if (node.cmdline && node.cmdline !== node.name && node.cmdline !== node.image_path) {
            // Show args only (remove exe path)
            var args = node.cmdline;
            if (args.toLowerCase().indexOf(node.name.toLowerCase()) >= 0) {
                var idx = args.toLowerCase().indexOf(node.name.toLowerCase());
                args = args.substring(idx + node.name.length).trim();
            }
            if (args.startsWith('"')) {
                // Remove quoted path
                var endQ = args.indexOf('"', 1);
                if (endQ > 0) args = args.substring(endQ + 1).trim();
            }
            if (args.length > 0) {
                cmdDisplay = '<span class="pe-cmd-args">' + _esc(args.substring(0, 120)) + '</span>';
            }
        }

        var html = '<div class="pe-node-row" data-pid="' + pid + '">';

        // The process bar
        html += '<div class="pe-node" style="border-left:3px solid ' + borderColor + ';background:' + bgColor + '">';

        // Expand/collapse toggle (if has children)
        var kids = children[pid] || [];
        if (kids.length > 0) {
            html += '<span class="pe-toggle" onclick="CvProcessExplorer._toggle(this)">▼</span>';
        } else {
            html += '<span class="pe-toggle-spacer"></span>';
        }

        // Icon
        html += '<span class="pe-icon">' + icon + '</span>';

        // Process name + args
        html += '<span class="pe-name">' + _esc(node.name || 'unknown') + '</span>';
        html += cmdDisplay;

        // Right-side badges
        html += '<span class="pe-badges">';

        // Suspicious indicator
        if (isTrigger) {
            html += '<span class="pe-badge pe-badge-crit" title="Trigger process">🔥 TRIGGER</span>';
        } else if (isSusp) {
            html += '<span class="pe-badge pe-badge-warn" title="' + _esc(node.suspicious_reason || '') + '">⚠️ SUSPICIOUS</span>';
        }

        // PID
        html += '<span class="pe-badge pe-badge-pid">PID:' + pid + '</span>';

        // User
        if (node.user) {
            html += '<span class="pe-badge pe-badge-user">' + _esc(node.user) + '</span>';
        }

        // Hash (truncated)
        if (node.sha256) {
            html += '<span class="pe-badge pe-badge-hash" title="' + node.sha256 + '">'
                  + node.sha256.substring(0, 8) + '...</span>';
        }

        html += '</span>'; // close badges
        html += '</div>';  // close pe-node

        // Children
        if (kids.length > 0) {
            html += '<div class="pe-children">';
            for (var c = 0; c < kids.length; c++) {
                html += _renderNode(kids[c], nodeMap, children, depth + 1, triggerPid);
            }
            html += '</div>';
        }

        html += '</div>'; // close pe-node-row
        return html;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  RENDER TREE LIST (for incidents page)
    // ═══════════════════════════════════════════════════════════════════
    function renderTreeList(containerId, hours) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = _loadingHTML('Loading process trees...');

        apiFetch('/api/v1/process-trees?hours=' + (hours || 24) + '&limit=20')
        .then(function(data) {
            var trees = data.trees || [];
            if (!trees.length) {
                el.innerHTML = _emptyHTML('No process trees captured yet. Trees appear when the agent detects suspicious process chains.');
                return;
            }

            var html = '<div style="margin-bottom:10px;display:flex;align-items:center;gap:8px">'
                     + '<span style="font-size:14px">🌲</span>'
                     + '<span style="font-weight:700;font-size:13px;color:var(--text1)">Captured Process Trees</span>'
                     + '<span style="font-size:10px;color:var(--text3)">' + trees.length + ' trees</span>'
                     + '</div>';

            for (var i = 0; i < trees.length; i++) {
                var t = trees[i];
                var time = (t.capture_time || '').replace('T', ' ').slice(0, 19);

                html += '<div class="pe-tree-card" onclick="CvProcessExplorer.renderTree(this.closest(\'[id]\').id.replace(\'-list\',\'-detail\') || \'cv-ptree-detail\',\'' + t.tree_id + '\')">'
                      + '<div style="display:flex;align-items:center;gap:10px">'
                      + '<span style="font-size:20px">' + getIcon(t.root_process) + '</span>'
                      + '<div style="flex:1">'
                      + '<div style="font-weight:700;font-size:13px;color:var(--text1)">' + _esc(t.root_process || '?') + '</div>'
                      + '<div style="font-size:11px;color:var(--text3)">' + _esc(t.trigger_reason || '') + '</div>'
                      + '</div>'
                      + '<div style="text-align:right">'
                      + '<div style="font-family:var(--mono);font-size:10px;color:var(--text3)">' + time + '</div>'
                      + '<div style="font-size:11px;color:var(--accent)">' + (t.process_count || 0) + ' processes</div>'
                      + '<div style="font-size:10px;color:var(--text2)">' + _esc(t.hostname || '') + '</div>'
                      + '</div>'
                      + '</div></div>';
            }

            el.innerHTML = html;
        })
        .catch(function(e) {
            el.innerHTML = _errorHTML(e.message);
        });
    }


    // ── Toggle children ─────────────────────────────────────────────────
    function _toggle(el) {
        var row = el.closest('.pe-node-row');
        var childContainer = row.querySelector('.pe-children');
        if (!childContainer) return;

        var isHidden = childContainer.style.display === 'none';
        childContainer.style.display = isHidden ? '' : 'none';
        el.textContent = isHidden ? '▼' : '▶';
    }


    // ── Helper HTML ─────────────────────────────────────────────────────
    function _loadingHTML(msg) {
        return '<div style="padding:40px;text-align:center;color:var(--text3);font-size:12px">'
             + '<div class="cv-pulse" style="font-size:24px;margin-bottom:8px">🌲</div>'
             + (msg || 'Loading...') + '</div>';
    }
    function _emptyHTML(msg) {
        return '<div style="padding:40px;text-align:center;color:var(--text3);font-size:12px">'
             + '<div style="font-size:24px;margin-bottom:8px">🌲</div>'
             + (msg || 'No data') + '</div>';
    }
    function _errorHTML(msg) {
        return '<div style="padding:40px;text-align:center;color:var(--crit);font-size:12px">'
             + '<div style="font-size:24px;margin-bottom:8px">❌</div>'
             + 'Error: ' + _esc(msg) + '</div>';
    }
    function _esc(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }


    // Public API
    return {
        renderTree: renderTree,
        renderTreeForEvent: renderTreeForEvent,
        renderTreeList: renderTreeList,
        _toggle: _toggle,
    };
})();
