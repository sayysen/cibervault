/**
 * Cibervault AI v2 — Enhanced AI Chat, SOAR Management, Alert Correlation, Rule Generation
 *
 * Features:
 * - Markdown rendering in AI responses (bold, code, lists, headers)
 * - Copy code blocks, copy full response
 * - Export chat history as markdown
 * - Typing indicator / streaming feel
 * - SOAR rule management UI
 * - Alert correlation UI
 * - AI rule generation UI
 *
 * Usage: Load after dashboard.html, call CvAIv2.init()
 */
var CvAIv2 = (function () {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════
  //  MARKDOWN RENDERER (lightweight, no dependencies)
  // ═══════════════════════════════════════════════════════════════════

  function renderMarkdown(text) {
    if (!text) return '';
    var html = _escapeHtml(text);

    // Code blocks (``` ... ```)
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, function (m, lang, code) {
      var id = 'cb-' + Math.random().toString(36).substr(2, 6);
      return '<div class="ai-code-block" style="position:relative;margin:8px 0">'
        + '<div style="display:flex;justify-content:space-between;align-items:center;background:var(--bg);padding:4px 10px;border-radius:6px 6px 0 0;border:1px solid var(--border);border-bottom:0">'
        + '<span style="font-size:10px;color:var(--text3);text-transform:uppercase">' + (lang || 'code') + '</span>'
        + '<button class="ai-copy-btn" data-target="' + id + '" style="font-size:10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text2);padding:2px 8px;cursor:pointer" onclick="CvAIv2.copyCode(this)">Copy</button>'
        + '</div>'
        + '<pre id="' + id + '" style="margin:0;background:var(--bg);border:1px solid var(--border);border-radius:0 0 6px 6px;padding:10px;overflow-x:auto;font-size:12px;line-height:1.5"><code>' + code + '</code></pre>'
        + '</div>';
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background:var(--bg3);padding:1px 5px;border-radius:3px;font-size:11px;font-family:var(--mono)">$1</code>');

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text1)">$1</strong>');

    // Italic
    html = html.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

    // Headers
    html = html.replace(/^### (.+)$/gm, '<div style="font-size:13px;font-weight:700;color:var(--accent);margin:10px 0 4px">$1</div>');
    html = html.replace(/^## (.+)$/gm, '<div style="font-size:14px;font-weight:700;color:var(--text1);margin:12px 0 4px">$1</div>');

    // Bullet lists
    html = html.replace(/^[\-\*] (.+)$/gm, '<div style="padding-left:14px;margin:2px 0"><span style="color:var(--accent);margin-right:6px">•</span>$1</div>');

    // Numbered lists
    html = html.replace(/^(\d+)\. (.+)$/gm, '<div style="padding-left:14px;margin:2px 0"><span style="color:var(--accent);margin-right:6px;font-weight:600">$1.</span>$2</div>');

    // Line breaks
    html = html.replace(/\n/g, '<br>');

    // Clean up excessive <br> after block elements
    html = html.replace(/<\/div><br>/g, '</div>');
    html = html.replace(/<\/pre><br>/g, '</pre>');

    return html;
  }

  function _escapeHtml(t) {
    var d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
  }


  // ═══════════════════════════════════════════════════════════════════
  //  ENHANCED CHAT
  // ═══════════════════════════════════════════════════════════════════

  var chatHistory = [];

  function sendChat() {
    var inp = document.getElementById('ai-chat-input');
    var btn = document.getElementById('ai-chat-send');
    var msg = (inp ? inp.value.trim() : '');
    if (!msg) return;
    if (inp) inp.value = '';
    if (btn) { btn.disabled = true; btn.textContent = '...'; }

    // Add user message
    chatHistory.push({ role: 'user', content: msg });
    _addBubble('user', msg);
    _addTypingIndicator();

    apiFetch('/api/v1/ai/chat/v2', {
      method: 'POST',
      body: JSON.stringify({ message: msg, history: chatHistory.slice(-10) })
    })
      .then(function (d) {
        _removeTypingIndicator();
        var reply = d.reply || 'No response';
        chatHistory.push({ role: 'assistant', content: reply });
        _addBubble('assistant', reply, d.context);
        if (btn) { btn.disabled = false; btn.textContent = 'Send'; }
      })
      .catch(function (e) {
        _removeTypingIndicator();
        _addBubble('assistant', 'Error: ' + e.message);
        if (btn) { btn.disabled = false; btn.textContent = 'Send'; }
      });
  }

  function _addBubble(role, text, context) {
    var hist = document.getElementById('ai-chat-history');
    if (!hist) return;

    // Remove initial placeholder
    var ph = hist.querySelector('[style*="text-align:center"]');
    if (ph && hist.children.length === 1) hist.removeChild(ph);

    var isUser = role === 'user';
    var wrap = document.createElement('div');
    wrap.style.cssText = 'display:flex;flex-direction:column;align-items:' + (isUser ? 'flex-end' : 'flex-start');

    var bubble = document.createElement('div');
    bubble.className = 'ai-msg-bubble ' + role;

    if (isUser) {
      bubble.style.cssText = 'max-width:85%;padding:10px 14px;border-radius:12px;font-size:12px;line-height:1.6;'
        + 'background:var(--accent);color:#fff;border-bottom-right-radius:4px;white-space:pre-wrap';
      bubble.textContent = text;
    } else {
      bubble.style.cssText = 'max-width:90%;padding:12px 16px;border-radius:12px;font-size:12px;line-height:1.7;'
        + 'background:var(--bg3);color:var(--text1);border-bottom-left-radius:4px';
      bubble.innerHTML = renderMarkdown(text);

      // Add action bar under assistant messages
      var actionBar = document.createElement('div');
      actionBar.style.cssText = 'display:flex;gap:6px;margin-top:6px;flex-wrap:wrap';
      actionBar.innerHTML =
        '<button class="ai-action-btn" onclick="CvAIv2.copyResponse(this)" title="Copy response">📋 Copy</button>'
        + (text.match(/```/) ? '<button class="ai-action-btn" onclick="CvAIv2.copyAllCode(this)" title="Copy all code blocks">💻 Copy Code</button>' : '');
      bubble.appendChild(actionBar);
    }

    wrap.appendChild(bubble);

    // Context badge
    if (context && !isUser) {
      var badge = document.createElement('div');
      badge.style.cssText = 'font-size:10px;color:var(--text3);margin-top:4px;display:flex;gap:8px';
      var parts = [];
      if (context.alerts_24h) parts.push('📊 ' + context.alerts_24h + ' alerts');
      if (context.open_incidents) parts.push('🔴 ' + context.open_incidents + ' incidents');
      if (context.ueba_anomalies) parts.push('👤 ' + context.ueba_anomalies + ' anomalies');
      badge.textContent = parts.join(' · ');
      wrap.appendChild(badge);
    }

    hist.appendChild(wrap);
    hist.scrollTop = hist.scrollHeight;
  }

  function _addTypingIndicator() {
    var hist = document.getElementById('ai-chat-history');
    if (!hist) return;
    var el = document.createElement('div');
    el.id = 'ai-typing';
    el.style.cssText = 'display:flex;align-items:flex-start';
    el.innerHTML = '<div style="padding:10px 16px;background:var(--bg3);border-radius:12px;font-size:12px;color:var(--text3)">'
      + '<span class="ai-dots"><span>●</span><span>●</span><span>●</span></span> Analyzing your environment...'
      + '</div>';
    hist.appendChild(el);
    hist.scrollTop = hist.scrollHeight;
  }

  function _removeTypingIndicator() {
    var el = document.getElementById('ai-typing');
    if (el) el.remove();
  }

  function clearChat() {
    chatHistory = [];
    var hist = document.getElementById('ai-chat-history');
    if (hist) hist.innerHTML = '<div style="text-align:center;color:var(--text3);font-size:12px;padding:20px 0">Chat cleared. Ask me anything about your security environment...</div>';
  }

  function exportChat() {
    if (!chatHistory.length) { toast('No chat to export', 'error'); return; }
    var md = '# Cibervault AI Chat Export\n';
    md += '**Date:** ' + new Date().toISOString() + '\n\n---\n\n';
    chatHistory.forEach(function (m) {
      md += (m.role === 'user' ? '**You:** ' : '**AI Analyst:** ') + m.content + '\n\n';
    });
    var blob = new Blob([md], { type: 'text/markdown' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'cibervault-chat-' + new Date().toISOString().slice(0, 10) + '.md';
    a.click();
    toast('Chat exported!', 'success');
  }

  function copyResponse(btn) {
    var bubble = btn.closest('.ai-msg-bubble');
    if (!bubble) return;
    // Get text content without the action bar
    var clone = bubble.cloneNode(true);
    var actions = clone.querySelectorAll('.ai-action-btn');
    actions.forEach(function(a) { a.parentElement.remove(); });
    var text = clone.textContent.trim();
    _copyText(text);
  }

  function copyCode(btn) {
    var targetId = btn.getAttribute('data-target');
    var pre = document.getElementById(targetId);
    if (pre) {
      _copyText(pre.textContent);
      btn.textContent = '✓ Copied';
      setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
    }
  }

  function copyAllCode(btn) {
    var bubble = btn.closest('.ai-msg-bubble');
    if (!bubble) return;
    var codes = bubble.querySelectorAll('pre code');
    var text = Array.prototype.map.call(codes, function (c) { return c.textContent; }).join('\n\n');
    _copyText(text);
  }

  function _copyText(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      toast('Copied to clipboard!', 'success');
    }
  }


  // ═══════════════════════════════════════════════════════════════════
  //  SOAR MANAGEMENT UI
  // ═══════════════════════════════════════════════════════════════════

  function loadSOAR() {
    loadSOARStats();
    loadSOARRules();
    loadSOARActions();
  }

  function loadSOARStats() {
    apiFetch('/api/v1/soar/stats').then(function (d) {
      var html = '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">'
        + _statCard('Active Rules', d.active_rules, 'var(--accent)')
        + _statCard('Actions Executed', d.total_executed, 'var(--low)')
        + _statCard('Pending Approval', d.pending_approval, d.pending_approval > 0 ? 'var(--crit)' : 'var(--text3)')
        + '</div>';

      if (d.top_rules_7d && d.top_rules_7d.length) {
        html += '<div style="font-size:11px;color:var(--text3);margin-bottom:4px">Top rules (7 days):</div>';
        d.top_rules_7d.forEach(function (r) {
          html += '<div style="font-size:12px;margin:2px 0"><span style="color:var(--accent)">' + r.count + 'x</span> ' + r.name + '</div>';
        });
      }
      setHtml('soar-stats', html);
    }).catch(function () { setHtml('soar-stats', '<div class="empty">Could not load SOAR stats</div>'); });
  }

  function _statCard(label, value, color) {
    return '<div style="background:var(--bg3);border-radius:var(--r);padding:14px;text-align:center">'
      + '<div style="font-size:24px;font-weight:700;color:' + color + '">' + (value || 0) + '</div>'
      + '<div style="font-size:11px;color:var(--text3);margin-top:2px">' + label + '</div></div>';
  }

  function loadSOARRules() {
    apiFetch('/api/v1/soar/rules').then(function (d) {
      var rules = d.rules || [];
      if (!rules.length) {
        setHtml('soar-rules-list', '<div class="empty"><div class="empty-title">No SOAR rules</div></div>');
        return;
      }
      var html = '<table style="width:100%;font-size:12px;border-collapse:collapse">'
        + '<tr style="color:var(--text3);font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--border)">'
        + '<th style="padding:6px;text-align:left">Rule</th>'
        + '<th style="padding:6px;text-align:left">Trigger</th>'
        + '<th style="padding:6px;text-align:left">Action</th>'
        + '<th style="padding:6px;text-align:center">Runs</th>'
        + '<th style="padding:6px;text-align:center">Status</th>'
        + '<th style="padding:6px;text-align:center">Actions</th></tr>';

      rules.forEach(function (r) {
        var enabled = r.enabled === 1 || r.enabled === true;
        var actionIcons = { 'block_ip': '🚫', 'isolate_host': '🔒', 'defender_scan': '🛡️', 'collect_triage': '📦', 'kill_process': '💀' };
        html += '<tr style="border-bottom:1px solid var(--border)">'
          + '<td style="padding:8px 6px"><div style="font-weight:600">' + _escapeHtml(r.name) + '</div>'
          + '<div style="font-size:10px;color:var(--text3)">' + _escapeHtml(r.description || '').substring(0, 60) + '</div></td>'
          + '<td style="padding:8px 6px"><span style="background:var(--bg3);padding:2px 6px;border-radius:3px;font-size:10px">' + r.trigger_type + '</span>'
          + (r.mitre_id ? ' <span style="color:var(--accent);font-size:10px">' + r.mitre_id + '</span>' : '') + '</td>'
          + '<td style="padding:8px 6px">' + (actionIcons[r.action_type] || '⚡') + ' ' + (r.action_type || '').replace(/_/g, ' ') + '</td>'
          + '<td style="padding:8px 6px;text-align:center">' + (r.total_executions || 0) + '</td>'
          + '<td style="padding:8px 6px;text-align:center"><span style="width:8px;height:8px;border-radius:50%;display:inline-block;background:'
          + (enabled ? 'var(--low)' : 'var(--text3)') + '"></span> ' + (r.require_confirmation ? '<span style="font-size:9px;color:var(--med);margin-left:4px">APPROVAL</span>' : '<span style="font-size:9px;color:var(--text3);margin-left:4px">AUTO</span>') + '</td>'
          + '<td style="padding:8px 6px;text-align:center">'
          + '<button class="btn btn-sm" onclick="CvAIv2.toggleSOARRule(\'' + r.rule_id + '\',' + (enabled ? 'false' : 'true') + ')">' + (enabled ? 'Disable' : 'Enable') + '</button>'
          + '</td></tr>';
      });
      html += '</table>';
      setHtml('soar-rules-list', html);
    }).catch(function (e) { setHtml('soar-rules-list', '<div class="empty">Error loading rules: ' + e.message + '</div>'); });
  }

  function loadSOARActions() {
    apiFetch('/api/v1/soar/actions?limit=20').then(function (d) {
      var actions = d.actions || [];
      if (!actions.length) {
        setHtml('soar-actions-list', '<div class="empty" style="padding:20px"><div class="empty-icon">⚡</div><div class="empty-title">No automated actions yet</div><div style="font-size:11px;color:var(--text3)">Actions will appear here when SOAR rules trigger</div></div>');
        return;
      }
      var html = '';
      actions.forEach(function (a) {
        var statusColors = { 'executed': 'var(--low)', 'pending': 'var(--med)', 'pending_confirmation': 'var(--high)', 'rejected': 'var(--crit)' };
        html += '<div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid var(--border)">'
          + '<div style="width:8px;height:8px;border-radius:50%;background:' + (statusColors[a.status] || 'var(--text3)') + ';flex-shrink:0"></div>'
          + '<div style="flex:1;min-width:0">'
          + '<div style="font-size:12px;font-weight:500">' + (a.action_type || '').replace(/_/g, ' ') + ' on ' + (a.hostname || '?') + '</div>'
          + '<div style="font-size:10px;color:var(--text3)">' + (a.trigger_summary || '').substring(0, 80) + '</div>'
          + '<div style="font-size:10px;color:var(--text3)">' + (a.rule_name || '') + ' · ' + _timeAgo(a.created_at) + '</div>'
          + '</div>'
          + '<div style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg3);color:' + (statusColors[a.status] || 'var(--text3)') + '">' + (a.status || '').replace(/_/g, ' ') + '</div>'
          + (a.status === 'pending_confirmation' ? '<button class="btn btn-sm" style="background:var(--low);color:#000" onclick="CvAIv2.confirmAction(\'' + a.action_id + '\',true)">Approve</button><button class="btn btn-sm" onclick="CvAIv2.confirmAction(\'' + a.action_id + '\',false)">Reject</button>' : '')
          + '</div>';
      });
      setHtml('soar-actions-list', html);
    }).catch(function () { setHtml('soar-actions-list', '<div class="empty">Could not load actions</div>'); });
  }

  function toggleSOARRule(ruleId, enable) {
    apiFetch('/api/v1/soar/rules/' + ruleId, {
      method: 'PATCH',
      body: JSON.stringify({ enabled: enable })
    }).then(function () {
      toast('Rule ' + (enable ? 'enabled' : 'disabled'), 'success');
      loadSOARRules();
    }).catch(function (e) { toast('Error: ' + e.message, 'error'); });
  }

  function confirmAction(actionId, approve) {
    apiFetch('/api/v1/soar/actions/' + actionId + '/confirm', {
      method: 'POST',
      body: JSON.stringify({ approve: approve })
    }).then(function () {
      toast('Action ' + (approve ? 'approved' : 'rejected'), 'success');
      loadSOARActions();
      loadSOARStats();
    }).catch(function (e) { toast('Error: ' + e.message, 'error'); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  ALERT CORRELATION UI
  // ═══════════════════════════════════════════════════════════════════

  function runCorrelation() {
    var btn = document.getElementById('corr-run-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Correlating...'; }

    apiFetch('/api/v1/ai/correlate', { method: 'POST', body: JSON.stringify({ window_hours: 4, min_cluster: 2 }) })
      .then(function (d) {
        if (btn) { btn.disabled = false; btn.textContent = '🔗 Run Correlation'; }
        toast('Found ' + (d.new_incidents || 0) + ' new incidents', 'success');
        loadCorrelatedIncidents();
      })
      .catch(function (e) {
        if (btn) { btn.disabled = false; btn.textContent = '🔗 Run Correlation'; }
        toast('Correlation error: ' + e.message, 'error');
      });
  }

  function loadCorrelatedIncidents() {
    apiFetch('/api/v1/ai/incidents?limit=20').then(function (d) {
      var incidents = d.incidents || [];
      if (!incidents.length) {
        setHtml('corr-incidents-list', '<div class="empty" style="padding:30px"><div class="empty-icon">🔗</div><div class="empty-title">No correlated incidents</div><div style="font-size:11px;color:var(--text3)">Run correlation to group related alerts</div></div>');
        return;
      }

      var html = '';
      incidents.forEach(function (inc) {
        var sevColors = { 'critical': 'var(--crit)', 'high': 'var(--high)', 'medium': 'var(--med)', 'low': 'var(--low)' };
        var statusColors = { 'open': 'var(--crit)', 'investigating': 'var(--med)', 'resolved': 'var(--low)', 'closed': 'var(--text3)' };
        var hosts = (inc.affected_hosts || []).join(', ');
        var tactics = (inc.kill_chain_stages || []).join(' → ');

        html += '<div class="card" style="margin-bottom:10px;padding:14px;cursor:pointer" onclick="CvAIv2.showIncident(\'' + inc.incident_id + '\')">'
          + '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
          + '<span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;background:' + (sevColors[inc.severity] || 'var(--text3)') + ';color:#fff">' + (inc.priority || 'P3') + '</span>'
          + '<span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg);border:1px solid ' + (sevColors[inc.severity] || 'var(--border)') + ';color:' + (sevColors[inc.severity] || 'var(--text2)') + '">' + (inc.severity || 'medium').toUpperCase() + '</span>'
          + '<span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg);color:' + (statusColors[inc.status] || 'var(--text3)') + ';border:1px solid currentColor">' + (inc.status || 'open') + '</span>'
          + '<span style="font-size:10px;color:var(--text3);margin-left:auto">' + (inc.event_count || 0) + ' events</span>'
          + '</div>'
          + '<div style="font-size:13px;font-weight:600;margin-bottom:4px">' + _escapeHtml(inc.title || 'Unnamed Incident') + '</div>'
          + (inc.summary ? '<div style="font-size:11px;color:var(--text2);margin-bottom:6px">' + _escapeHtml(inc.summary).substring(0, 200) + '</div>' : '')
          + '<div style="display:flex;gap:12px;font-size:10px;color:var(--text3)">'
          + '<span>🖥️ ' + hosts + '</span>'
          + (tactics ? '<span>⛓️ ' + tactics + '</span>' : '')
          + '<span>🕐 ' + _timeAgo(inc.first_seen) + '</span>'
          + '</div></div>';
      });
      setHtml('corr-incidents-list', html);
    }).catch(function (e) { setHtml('corr-incidents-list', '<div class="empty">Error: ' + e.message + '</div>'); });
  }

  function showIncident(incidentId) {
    apiFetch('/api/v1/ai/incidents?limit=50').then(function (d) {
      var inc = (d.incidents || []).find(function (i) { return i.incident_id === incidentId; });
      if (!inc) { toast('Incident not found', 'error'); return; }

      var analysis = inc.ai_analysis || {};
      var html = '<div style="padding:16px">'
        + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
        + '<h3 style="margin:0;font-size:16px">' + _escapeHtml(inc.title) + '</h3>'
        + '<button class="btn btn-sm" onclick="CvAIv2.enrichIncident(\'' + incidentId + '\')">🤖 AI Analyze</button>'
        + '</div>';

      // Summary
      if (inc.summary) {
        html += '<div style="background:var(--bg3);border-radius:var(--r);padding:12px;margin-bottom:12px;font-size:12px;line-height:1.6;border-left:3px solid var(--accent)">'
          + _escapeHtml(inc.summary) + '</div>';
      }

      // AI analysis details
      if (analysis.recommended_actions) {
        html += '<div style="margin-bottom:12px"><div style="font-size:11px;font-weight:600;color:var(--text3);margin-bottom:4px">RECOMMENDED ACTIONS</div>';
        analysis.recommended_actions.forEach(function (a) {
          html += '<div style="font-size:12px;margin:2px 0;padding-left:12px">→ ' + _escapeHtml(a) + '</div>';
        });
        html += '</div>';
      }

      if (analysis.iocs && analysis.iocs.length) {
        html += '<div style="margin-bottom:12px"><div style="font-size:11px;font-weight:600;color:var(--text3);margin-bottom:4px">IOCs</div>';
        analysis.iocs.forEach(function (ioc) {
          html += '<div style="font-size:11px;font-family:var(--mono);background:var(--bg3);display:inline-block;padding:2px 8px;border-radius:3px;margin:2px">' + _escapeHtml(ioc) + '</div>';
        });
        html += '</div>';
      }

      // Kill chain
      var stages = inc.kill_chain_stages || [];
      if (stages.length) {
        html += '<div style="margin-bottom:12px"><div style="font-size:11px;font-weight:600;color:var(--text3);margin-bottom:6px">KILL CHAIN PROGRESSION</div>'
          + '<div style="display:flex;gap:4px;flex-wrap:wrap">';
        stages.forEach(function (s) {
          html += '<span style="font-size:10px;padding:3px 8px;border-radius:4px;background:var(--accent);color:#fff">' + s + '</span>';
        });
        html += '</div></div>';
      }

      // Status actions
      html += '<div style="display:flex;gap:8px;margin-top:16px;border-top:1px solid var(--border);padding-top:12px">'
        + '<button class="btn btn-sm btn-primary" onclick="CvAIv2.updateIncident(\'' + incidentId + '\',\'investigating\')">Mark Investigating</button>'
        + '<button class="btn btn-sm" style="background:var(--low);color:#000" onclick="CvAIv2.updateIncident(\'' + incidentId + '\',\'resolved\')">Resolve</button>'
        + '<button class="btn btn-sm" onclick="CvAIv2.updateIncident(\'' + incidentId + '\',\'closed\')">Close</button>'
        + '</div></div>';

      // Show in a modal-like card
      var modal = document.getElementById('corr-detail');
      if (modal) { modal.innerHTML = html; modal.style.display = 'block'; }
    });
  }

  function enrichIncident(incidentId) {
    toast('Running AI analysis...', 'info');
    apiFetch('/api/v1/ai/incidents/' + incidentId + '/enrich', { method: 'POST' })
      .then(function () {
        toast('Incident enriched!', 'success');
        showIncident(incidentId);
        loadCorrelatedIncidents();
      })
      .catch(function (e) { toast('Enrichment failed: ' + e.message, 'error'); });
  }

  function updateIncident(incidentId, status) {
    apiFetch('/api/v1/ai/incidents/' + incidentId, {
      method: 'PATCH',
      body: JSON.stringify({ status: status })
    }).then(function () {
      toast('Incident ' + status, 'success');
      loadCorrelatedIncidents();
      var detail = document.getElementById('corr-detail');
      if (detail) detail.style.display = 'none';
    }).catch(function (e) { toast('Error: ' + e.message, 'error'); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  AI RULE GENERATION UI
  // ═══════════════════════════════════════════════════════════════════

  var _pendingRule = null;

  function generateRule() {
    var desc = (document.getElementById('ai-rulegen-desc') || {}).value || '';
    if (!desc.trim()) { toast('Describe the attack pattern', 'error'); return; }
    var btn = document.getElementById('ai-rulegen-btn');
    var result = document.getElementById('ai-rulegen-result');
    if (btn) { btn.disabled = true; btn.textContent = 'Generating...'; }
    if (result) { result.style.display = 'none'; }

    apiFetch('/api/v1/ai/generate-rule', {
      method: 'POST',
      body: JSON.stringify({ description: desc })
    })
      .then(function (d) {
        if (btn) { btn.disabled = false; btn.textContent = '🤖 Generate Rule'; }
        if (d.error) { toast('AI error: ' + d.error, 'error'); return; }
        _pendingRule = d.rule;
        _showGeneratedRule(d.rule);
      })
      .catch(function (e) {
        if (btn) { btn.disabled = false; btn.textContent = '🤖 Generate Rule'; }
        toast('Error: ' + e.message, 'error');
      });
  }

  function _showGeneratedRule(rule) {
    var result = document.getElementById('ai-rulegen-result');
    if (!result) return;
    result.style.display = 'block';

    var sevColors = { 'critical': 'var(--crit)', 'high': 'var(--high)', 'medium': 'var(--med)', 'low': 'var(--low)' };
    var html = '<div style="border:1px solid var(--accent);border-radius:var(--r);padding:14px;background:var(--bg3)">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
      + '<div style="font-size:14px;font-weight:700">' + _escapeHtml(rule.name || 'AI Rule') + '</div>'
      + '<span style="font-size:10px;padding:2px 8px;border-radius:4px;background:' + (sevColors[rule.severity] || 'var(--med)') + ';color:#fff">' + (rule.severity || 'medium').toUpperCase() + '</span>'
      + '</div>'
      + '<div style="font-size:12px;color:var(--text2);margin-bottom:8px">' + _escapeHtml(rule.description || '') + '</div>'
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px;margin-bottom:10px">'
      + '<div><span style="color:var(--text3)">Event Types:</span> ' + (rule.event_types || []).join(', ') + '</div>'
      + '<div><span style="color:var(--text3)">MITRE:</span> ' + (rule.mitre_id || '—') + ' ' + (rule.mitre_tactic || '') + '</div>'
      + '<div><span style="color:var(--text3)">Match Field:</span> <code style="background:var(--bg);padding:1px 4px;border-radius:2px">' + (rule.match_field || '—') + '</code></div>'
      + '<div><span style="color:var(--text3)">Score:</span> ' + (rule.base_score || 50) + '</div>'
      + '</div>'
      + '<div style="margin-bottom:10px"><span style="color:var(--text3);font-size:11px">Pattern:</span><br>'
      + '<code style="font-size:11px;background:var(--bg);padding:4px 8px;border-radius:4px;display:block;margin-top:4px;word-break:break-all">' + _escapeHtml(rule.match_pattern || '') + '</code></div>'
      + (rule.rationale ? '<div style="font-size:11px;color:var(--text2);font-style:italic;margin-bottom:10px">' + _escapeHtml(rule.rationale) + '</div>' : '')
      + '<div style="display:flex;gap:8px">'
      + '<button class="btn btn-primary" onclick="CvAIv2.acceptRule()">✅ Accept & Save Rule</button>'
      + '<button class="btn" onclick="CvAIv2.generateRule()">🔄 Regenerate</button>'
      + '</div></div>';
    result.innerHTML = html;
  }

  function acceptRule() {
    if (!_pendingRule) { toast('No rule to accept', 'error'); return; }
    apiFetch('/api/v1/ai/generate-rule/accept', {
      method: 'POST',
      body: JSON.stringify({ rule: _pendingRule })
    })
      .then(function (d) {
        toast('Rule saved: ' + d.name, 'success');
        _pendingRule = null;
        var result = document.getElementById('ai-rulegen-result');
        if (result) result.innerHTML = '<div style="padding:14px;text-align:center;color:var(--low);font-weight:600">✅ Rule saved! Go to Detection Rules to see it.</div>';
      })
      .catch(function (e) { toast('Error saving: ' + e.message, 'error'); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  HELPERS
  // ═══════════════════════════════════════════════════════════════════

  function _timeAgo(iso) {
    if (!iso) return '';
    try {
      var diff = (Date.now() - new Date(iso).getTime()) / 1000;
      if (diff < 60) return 'just now';
      if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
      if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
      return Math.floor(diff / 86400) + 'd ago';
    } catch (e) { return iso; }
  }

  function apiFetch(url, opts) {
    var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
    opts = opts || {};
    opts.headers = Object.assign({ 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, opts.headers || {});
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  function setHtml(id, html) { var e = document.getElementById(id); if (e) e.innerHTML = html; }
  function toast(msg, type) { if (typeof window.toast === 'function') window.toast(msg, type); else console.log('[' + type + '] ' + msg); }


  // ═══════════════════════════════════════════════════════════════════
  //  INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════

  function init() {
    // Inject CSS for typing animation
    var style = document.createElement('style');
    style.textContent = '.ai-dots span{animation:aidot 1.4s infinite;opacity:0.3;font-size:8px;margin:0 1px}'
      + '.ai-dots span:nth-child(2){animation-delay:0.2s}.ai-dots span:nth-child(3){animation-delay:0.4s}'
      + '@keyframes aidot{0%,100%{opacity:0.3}50%{opacity:1}}'
      + '.ai-action-btn{font-size:10px;background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text3);padding:2px 8px;cursor:pointer}'
      + '.ai-action-btn:hover{background:var(--bg3);color:var(--text1)}';
    document.head.appendChild(style);

    // Override the original sendAIChat if it exists
    if (typeof window.sendAIChat !== 'undefined') {
      window._originalSendAIChat = window.sendAIChat;
    }
    window.sendAIChat = sendChat;
    window.clearAIChat = clearChat;

    console.log('[CvAIv2] AI v2 module loaded');
  }

  // Public API
  return {
    init: init,
    sendChat: sendChat,
    clearChat: clearChat,
    exportChat: exportChat,
    copyResponse: copyResponse,
    copyCode: copyCode,
    copyAllCode: copyAllCode,
    loadSOAR: loadSOAR,
    loadSOARRules: loadSOARRules,
    loadSOARActions: loadSOARActions,
    loadSOARStats: loadSOARStats,
    toggleSOARRule: toggleSOARRule,
    confirmAction: confirmAction,
    runCorrelation: runCorrelation,
    loadCorrelatedIncidents: loadCorrelatedIncidents,
    showIncident: showIncident,
    enrichIncident: enrichIncident,
    updateIncident: updateIncident,
    generateRule: generateRule,
    acceptRule: acceptRule,
    renderMarkdown: renderMarkdown,
  };
})();

// Auto-init
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', CvAIv2.init);
} else {
  CvAIv2.init();
}
