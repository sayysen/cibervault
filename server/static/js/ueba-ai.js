/**
 * Cibervault AI-UEBA Frontend v2
 * 
 * Enhancements:
 * - Expandable IP list per profile card
 * - Login time heatmap (hours x days SVG grid)
 * - Risk trend sparklines
 * - Alert timeline per user
 * - High-risk: IPs, last login, MITRE, block button
 * - New user auto-flagging
 */
var CvUEBA = (function () {
  'use strict';

  function apiFetch(url, opts) {
    var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
    opts = opts || {};
    opts.headers = Object.assign({ 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, opts.headers || {});
    return fetch(url, opts).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  function el(id) { return document.getElementById(id); }
  function setHtml(id, html) { var e = el(id); if (e) e.innerHTML = html; }
  function toast(msg, type) { if (typeof window.toast === 'function') window.toast(msg, type); }
  function _esc(t) { var d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
  function _ago(iso) {
    if (!iso) return '';
    try { var d = (Date.now() - new Date(iso).getTime()) / 1000;
      if (d < 60) return 'just now'; if (d < 3600) return Math.floor(d/60) + 'm ago';
      if (d < 86400) return Math.floor(d/3600) + 'h ago'; return Math.floor(d/86400) + 'd ago';
    } catch(e) { return iso.slice(0,16); }
  }
  var sevColors = {critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)',info:'var(--text3)'};


  // ═══════════════════════════════════════════════════════════════════
  //  SUMMARY with enhanced high-risk + new user detection
  // ═══════════════════════════════════════════════════════════════════

  function loadSummary() {
    apiFetch('/api/v1/ueba/ai/summary').then(function (d) {
      var html = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px">'
        + _miniStat('User Profiles', d.user_profiles || 0, 'var(--accent)')
        + _miniStat('Host Profiles', d.host_profiles || 0, 'var(--text1)')
        + _miniStat('High Risk', (d.high_risk_users || []).length, (d.high_risk_users||[]).length > 0 ? 'var(--crit)' : 'var(--low)')
        + _miniStat('Events Analyzed', _fmtNum(d.total_events_analyzed || 0), 'var(--med)')
        + '</div>';

      // High risk users — enhanced
      var hrs = d.high_risk_users || [];
      if (hrs.length) {
        html += '<div style="font-size:11px;font-weight:600;color:var(--crit);margin-bottom:8px">HIGH RISK USERS</div>';
        hrs.forEach(function (u) {
          var ips = (u.ips || []).slice(0, 3).join(', ') + (u.ip_count > 3 ? ' +' + (u.ip_count - 3) + ' more' : '');
          var tactics = (u.mitre_tactics || []).slice(0, 3).join(', ');
          html += '<div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid var(--border);background:var(--bg3);border-radius:var(--r);margin-bottom:4px">'
            + '<div style="min-width:36px;text-align:center"><div style="font-size:18px;font-weight:700;color:var(--crit)">' + Math.round(u.risk_score) + '</div><div style="font-size:8px;color:var(--text3)">RISK</div></div>'
            + '<div style="flex:1;min-width:0">'
            + '<div style="font-size:12px;font-weight:600;cursor:pointer;color:var(--accent)" onclick="CvUEBA.investigateUser(\'' + _esc(u.user) + '\')">' + _esc(u.user) + '</div>'
            + '<div style="font-size:10px;color:var(--text3);margin-top:2px">'
            + '<span title="IPs">&#127760; ' + (ips || 'no IPs') + '</span>'
            + (u.last_login ? ' &middot; <span title="Last login">&#128338; ' + _ago(u.last_login) + (u.last_ip ? ' from ' + u.last_ip : '') + '</span>' : '')
            + '</div>'
            + (tactics ? '<div style="font-size:10px;color:var(--med);margin-top:2px">&#9876; MITRE: ' + _esc(tactics) + '</div>' : '')
            + '<div style="font-size:10px;color:var(--text3);margin-top:1px">' + _esc(u.reason) + ' &middot; ' + u.login_count + ' logins &middot; fail rate: ' + Math.round(u.fail_ratio * 100) + '%</div>'
            + '</div>'
            + '<div style="display:flex;flex-direction:column;gap:4px">'
            + '<button class="btn btn-sm" style="font-size:9px;padding:2px 8px;background:var(--crit);color:#fff" onclick="CvUEBA.blockUser(\'' + _esc(u.user) + '\')">Block</button>'
            + '<button class="btn btn-sm" style="font-size:9px;padding:2px 8px" onclick="CvUEBA.investigateUser(\'' + _esc(u.user) + '\')">Investigate</button>'
            + '</div></div>';
        });
      }

      // New users
      var newUsers = d.new_users || [];
      if (newUsers.length) {
        html += '<div style="font-size:11px;font-weight:600;color:var(--med);margin-top:14px;margin-bottom:6px">&#9888; NEW USERS DETECTED <span style="font-weight:400;color:var(--text3)">(low activity, first appearance)</span></div>';
        newUsers.forEach(function (u) {
          var ips = (u.ips || []).join(', ') || 'no IPs';
          html += '<div style="display:flex;align-items:center;gap:8px;padding:4px 8px;font-size:11px;border-left:3px solid var(--med);margin:3px 0;background:var(--bg3);border-radius:0 var(--r) var(--r) 0">'
            + '<span style="font-weight:600;color:var(--med)">NEW</span>'
            + '<span style="font-weight:500;cursor:pointer;color:var(--accent)" onclick="CvUEBA.investigateUser(\'' + _esc(u.user) + '\')">' + _esc(u.user) + '</span>'
            + '<span style="color:var(--text3)">' + u.events + ' events</span>'
            + '<span style="color:var(--text3)">IPs: ' + _esc(ips) + '</span>'
            + '<button class="btn btn-sm" style="font-size:9px;padding:1px 6px;margin-left:auto" onclick="CvUEBA.investigateUser(\'' + _esc(u.user) + '\')">Check</button>'
            + '</div>';
        });
      }

      setHtml('ueba-ai-summary', html);
    }).catch(function () { setHtml('ueba-ai-summary', ''); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  PROFILE CARDS with expandable IPs
  // ═══════════════════════════════════════════════════════════════════

  function loadAIProfiles() {
    apiFetch('/api/v1/ueba/ai/profiles').then(function (d) {
      var profiles = d.profiles || [];
      if (!profiles.length) {
        setHtml('ueba-ai-profiles', '<div class="empty" style="padding:20px"><div class="empty-icon" style="font-size:28px">&#129504;</div><div class="empty-title">No AI baselines yet</div><div style="font-size:11px;color:var(--text3)">Click "Rebuild Baselines" to analyze behavior patterns</div></div>');
        return;
      }
      var html = '';
      profiles.forEach(function (p, idx) {
        var risk = _calcRisk(p);
        var rc = risk >= 60 ? 'var(--crit)' : risk >= 35 ? 'var(--high)' : risk >= 15 ? 'var(--med)' : 'var(--low)';
        var isHost = p.user.startsWith('host:');
        var initial = isHost ? '&#128421;' : p.user[0].toUpperCase();
        var ips = p.known_ips || [];
        var ipPreview = ips.slice(0, 2).join(', ') + (ips.length > 2 ? ' +' + (ips.length - 2) : '');
        var tactics = Object.keys(p.tactics_seen || {});
        var tacticStr = tactics.slice(0, 2).join(', ');
        var cardId = 'ueba-card-' + idx;

        html += '<div style="border-bottom:1px solid var(--border)">'
          + '<div style="display:flex;align-items:center;gap:12px;padding:10px;cursor:pointer" onclick="CvUEBA.toggleCard(\'' + cardId + '\')">'
          + '<div style="width:36px;height:36px;border-radius:50%;background:' + rc + '22;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;color:' + rc + ';flex-shrink:0">' + initial + '</div>'
          + '<div style="flex:1;min-width:0">'
          + '<div style="font-size:12px;font-weight:600">' + _esc(p.user) + '</div>'
          + '<div style="font-size:10px;color:var(--text3);display:flex;gap:10px;flex-wrap:wrap;margin-top:2px">'
          + '<span>' + p.total_events + ' events</span>'
          + '<span>' + p.login_count + ' logins</span>'
          + '<span>' + p.ip_count + ' IPs</span>'
          + '<span>avg ' + p.daily_avg + '/day</span>'
          + (tacticStr ? '<span style="color:var(--med)">MITRE: ' + _esc(tacticStr) + '</span>' : '')
          + '</div>'
          + (ipPreview ? '<div style="font-size:10px;color:var(--text3);margin-top:1px;font-family:var(--mono)">&#127760; ' + _esc(ipPreview) + '</div>' : '')
          + '</div>'
          + _riskGauge(risk, rc)
          + '<div style="text-align:right;min-width:50px"><div style="font-size:16px;font-weight:700;color:' + rc + '">' + risk + '</div><div style="font-size:9px;color:var(--text3)">RISK</div></div>'
          + '<div style="font-size:10px;color:var(--text3)">&#9660;</div>'
          + '</div>'
          // Expandable detail
          + '<div id="' + cardId + '" style="display:none;padding:0 10px 12px 58px">'
          + _renderExpandedProfile(p, idx)
          + '</div></div>';
      });
      setHtml('ueba-ai-profiles', html);
    }).catch(function (e) { setHtml('ueba-ai-profiles', '<div class="empty">Error: ' + e.message + '</div>'); });
  }

  function _renderExpandedProfile(p, idx) {
    var html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">';

    // Left: IPs
    html += '<div><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">ALL IPs (' + p.ip_count + ')</div>';
    if (p.known_ips && p.known_ips.length) {
      p.known_ips.forEach(function (ip) {
        html += '<div style="font-size:11px;font-family:var(--mono);padding:2px 0;display:flex;align-items:center;gap:6px">'
          + '<span style="width:6px;height:6px;border-radius:50%;background:var(--accent);flex-shrink:0"></span>' + _esc(ip) + '</div>';
      });
    } else {
      html += '<div style="font-size:10px;color:var(--text3)">No IPs recorded</div>';
    }
    html += '</div>';

    // Right: Quick stats
    html += '<div>'
      + '<div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">DETAILS</div>'
      + '<div style="font-size:11px;margin:2px 0">Fail ratio: <span style="color:' + (p.fail_ratio > 0.3 ? 'var(--crit)' : 'var(--low)') + ';font-weight:600">' + Math.round(p.fail_ratio * 100) + '%</span></div>'
      + '<div style="font-size:11px;margin:2px 0">Off-hours: <span style="color:' + (p.off_hours_pct > 0.2 ? 'var(--high)' : 'var(--low)') + '">' + Math.round(p.off_hours_pct * 100) + '%</span></div>'
      + '<div style="font-size:11px;margin:2px 0">Daily avg: ' + p.daily_avg + ' (±' + p.daily_std + ')</div>'
      + '<div style="font-size:11px;margin:2px 0">Processes: ' + p.process_diversity + ' unique</div>';

    // MITRE tactics
    var tactics = Object.keys(p.tactics_seen || {});
    if (tactics.length) {
      html += '<div style="font-size:10px;font-weight:600;color:var(--text3);margin-top:6px;margin-bottom:2px">MITRE TACTICS</div>';
      tactics.forEach(function (t) {
        html += '<span style="display:inline-block;font-size:9px;padding:1px 6px;border-radius:3px;background:var(--accent)22;color:var(--accent);margin:1px 2px">' + _esc(t) + '(' + p.tactics_seen[t] + ')</span>';
      });
    }
    html += '</div></div>';

    // Action buttons
    html += '<div style="display:flex;gap:6px;margin-top:8px">'
      + '<button class="btn btn-sm btn-primary" style="font-size:10px" onclick="CvUEBA.investigateUser(\'' + _esc(p.user) + '\')">&#129504; Investigate</button>'
      + '<button class="btn btn-sm" style="font-size:10px" onclick="CvUEBA.showHeatmap(\'' + _esc(p.user) + '\')">&#128200; Heatmap</button>'
      + '<button class="btn btn-sm" style="font-size:10px" onclick="CvUEBA.showTimeline(\'' + _esc(p.user) + '\')">&#128197; Timeline</button>'
      + '<button class="btn btn-sm" style="font-size:10px" onclick="CvUEBA.showPeers(\'' + _esc(p.user) + '\')">&#128101; Peers</button>'
      + '</div>';

    return html;
  }

  function toggleCard(id) {
    var el = document.getElementById(id);
    if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
  }


  // ═══════════════════════════════════════════════════════════════════
  //  LOGIN HEATMAP (hours x days SVG)
  // ═══════════════════════════════════════════════════════════════════

  function showHeatmap(username) {
    var resultEl = el('ueba-investigation-result');
    if (resultEl) { resultEl.style.display = 'block'; resultEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Loading heatmap for ' + _esc(username) + '...</div>'; }

    apiFetch('/api/v1/ueba/ai/user/' + encodeURIComponent(username) + '/heatmap').then(function (d) {
      var hm = d.heatmap || [];
      var days = d.days || ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
      var maxVal = 0;
      hm.forEach(function (row) { row.forEach(function (v) { if (v > maxVal) maxVal = v; }); });

      var cellW = 22, cellH = 20, padL = 36, padT = 22;
      var svgW = padL + 24 * cellW + 10;
      var svgH = padT + 7 * cellH + 10;

      var svg = '<svg width="100%" viewBox="0 0 ' + svgW + ' ' + svgH + '" xmlns="http://www.w3.org/2000/svg" style="font-family:var(--font-sans)">';

      // Hour labels
      for (var h = 0; h < 24; h++) {
        if (h % 3 === 0) {
          svg += '<text x="' + (padL + h * cellW + cellW/2) + '" y="14" text-anchor="middle" style="font-size:8px;fill:var(--color-text-secondary)">' + h + ':00</text>';
        }
      }

      // Day labels + cells
      for (var day = 0; day < 7; day++) {
        svg += '<text x="2" y="' + (padT + day * cellH + cellH/2 + 3) + '" style="font-size:9px;fill:var(--color-text-secondary)">' + days[day] + '</text>';
        for (var hr = 0; hr < 24; hr++) {
          var val = hm[day] ? hm[day][hr] || 0 : 0;
          var intensity = maxVal > 0 ? val / maxVal : 0;
          var fill = intensity === 0 ? 'var(--color-background-secondary)' : _heatColor(intensity);
          svg += '<rect x="' + (padL + hr * cellW) + '" y="' + (padT + day * cellH) + '" width="' + (cellW - 1) + '" height="' + (cellH - 1) + '" rx="2" fill="' + fill + '">';
          if (val > 0) svg += '<title>' + days[day] + ' ' + hr + ':00 — ' + val + ' events</title>';
          svg += '</rect>';
          if (val > 0) {
            svg += '<text x="' + (padL + hr * cellW + cellW/2) + '" y="' + (padT + day * cellH + cellH/2 + 3) + '" text-anchor="middle" style="font-size:7px;fill:' + (intensity > 0.5 ? '#fff' : 'var(--color-text-secondary)') + '">' + val + '</text>';
          }
        }
      }
      svg += '</svg>';

      var html = '<div style="padding:14px">'
        + '<div style="font-size:13px;font-weight:600;margin-bottom:8px">&#128200; Login heatmap — ' + _esc(username) + ' <span style="font-size:10px;color:var(--text3);font-weight:400">(last 30 days)</span></div>'
        + '<div style="overflow-x:auto">' + svg + '</div>'
        + '<div style="display:flex;align-items:center;gap:8px;margin-top:8px;font-size:10px;color:var(--text3)">'
        + '<span>Less</span>'
        + '<div style="display:flex;gap:2px">'
        + '<div style="width:12px;height:12px;border-radius:2px;background:var(--color-background-secondary)"></div>'
        + '<div style="width:12px;height:12px;border-radius:2px;background:rgba(56,132,244,0.25)"></div>'
        + '<div style="width:12px;height:12px;border-radius:2px;background:rgba(56,132,244,0.5)"></div>'
        + '<div style="width:12px;height:12px;border-radius:2px;background:rgba(56,132,244,0.75)"></div>'
        + '<div style="width:12px;height:12px;border-radius:2px;background:rgba(56,132,244,1)"></div>'
        + '</div><span>More</span></div></div>';

      if (resultEl) resultEl.innerHTML = html;
    }).catch(function (e) { if (resultEl) resultEl.innerHTML = '<div style="padding:14px;color:var(--crit)">Heatmap error: ' + e.message + '</div>'; });
  }

  function _heatColor(intensity) {
    var r = Math.round(56 + (56 - 56) * intensity);
    var g = Math.round(132 - 80 * intensity);
    var b = Math.round(244 - 50 * intensity);
    return 'rgba(56,132,244,' + (0.15 + intensity * 0.85).toFixed(2) + ')';
  }


  // ═══════════════════════════════════════════════════════════════════
  //  ALERT TIMELINE
  // ═══════════════════════════════════════════════════════════════════

  function showTimeline(username) {
    var resultEl = el('ueba-investigation-result');
    if (resultEl) { resultEl.style.display = 'block'; resultEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">Loading timeline...</div>'; }

    apiFetch('/api/v1/ueba/ai/user/' + encodeURIComponent(username) + '/timeline').then(function (d) {
      var events = d.timeline || [];
      if (!events.length) {
        if (resultEl) resultEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text3)">No alerts found for ' + _esc(username) + '</div>';
        return;
      }

      var html = '<div style="padding:14px">'
        + '<div style="font-size:13px;font-weight:600;margin-bottom:12px">&#128197; Alert timeline — ' + _esc(username) + ' <span style="font-size:10px;color:var(--text3);font-weight:400">(' + events.length + ' events)</span></div>';

      var lastDate = '';
      events.forEach(function (ev) {
        var dateStr = (ev.event_time || '').slice(0, 10);
        if (dateStr !== lastDate) {
          html += '<div style="font-size:10px;color:var(--text3);font-weight:600;margin:10px 0 4px;padding-top:6px;border-top:1px solid var(--border)">' + dateStr + '</div>';
          lastDate = dateStr;
        }
        var sc = sevColors[ev.severity] || 'var(--text3)';
        var time = (ev.event_time || '').slice(11, 19);
        html += '<div style="display:flex;align-items:flex-start;gap:10px;padding:4px 0;margin-left:8px;border-left:2px solid ' + sc + ';padding-left:12px">'
          + '<div style="min-width:50px;font-size:10px;font-family:var(--mono);color:var(--text3)">' + time + '</div>'
          + '<div style="width:8px;height:8px;border-radius:50%;background:' + sc + ';flex-shrink:0;margin-top:3px"></div>'
          + '<div style="flex:1">'
          + '<div style="font-size:11px;font-weight:500">' + _esc(ev.rule_name || ev.event_type) + '</div>'
          + '<div style="font-size:10px;color:var(--text3)">'
          + _esc(ev.hostname || '')
          + (ev.source_ip ? ' from <span style="font-family:var(--mono)">' + _esc(ev.source_ip) + '</span>' : '')
          + (ev.mitre_id ? ' <span style="color:var(--accent)">[' + _esc(ev.mitre_id) + ']</span>' : '')
          + ' <span style="color:' + sc + '">' + (ev.severity || '') + '</span>'
          + ' score:' + (ev.risk_score || 0)
          + '</div></div></div>';
      });

      html += '</div>';
      if (resultEl) resultEl.innerHTML = html;
    }).catch(function (e) { if (resultEl) resultEl.innerHTML = '<div style="padding:14px;color:var(--crit)">Timeline error: ' + e.message + '</div>'; });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  USER INVESTIGATION (same as v1 but improved)
  // ═══════════════════════════════════════════════════════════════════

  function investigateUser(username) {
    if (!username) {
      username = (el('ueba-investigate-input') || el('ai-ueba-user-input') || {}).value || '';
      if (!username.trim()) { toast('Enter a username', 'error'); return; }
    }
    username = username.trim().toLowerCase();

    var resultEl = el('ueba-investigation-result');
    if (resultEl) {
      resultEl.style.display = 'block';
      resultEl.innerHTML = '<div style="text-align:center;padding:30px;color:var(--text3)"><div style="font-size:24px;margin-bottom:8px">&#129504;</div>Investigating ' + _esc(username) + '...<br><span style="font-size:11px">(AI is analyzing behavioral patterns — ~30-60s)</span></div>';
    }

    apiFetch('/api/v1/ueba/ai/investigate', {
      method: 'POST',
      body: JSON.stringify({ username: username })
    }).then(function (d) {
      if (d.error) { _showError(resultEl, d.error); return; }
      _renderInvestigation(resultEl, d);
    }).catch(function (e) { _showError(resultEl, e.message); });
  }

  function _showError(container, msg) {
    if (container) container.innerHTML = '<div style="padding:16px;color:var(--crit)">Error: ' + _esc(msg) + '</div>';
  }

  function _renderInvestigation(container, data) {
    if (!container) return;
    var inv = data.investigation || {};
    var bl = data.baseline || {};
    var peer = data.peer_analysis || {};
    var vc = {
      'likely_compromised': { bg: 'var(--crit)', label: 'LIKELY COMPROMISED' },
      'suspicious': { bg: 'var(--high)', label: 'SUSPICIOUS' },
      'likely_legitimate': { bg: 'var(--low)', label: 'LIKELY LEGITIMATE' },
      'insufficient_data': { bg: 'var(--text3)', label: 'INSUFFICIENT DATA' },
    }[inv.verdict] || { bg: 'var(--text3)', label: 'UNKNOWN' };

    var html = '<div style="padding:16px">'
      + '<div style="background:' + vc.bg + '22;border:1px solid ' + vc.bg + ';border-radius:var(--r);padding:16px;margin-bottom:16px;text-align:center">'
      + '<div style="font-size:12px;font-weight:700;color:' + vc.bg + ';letter-spacing:1px;margin-bottom:6px">' + vc.label + '</div>'
      + '<div style="font-size:36px;font-weight:700;color:' + vc.bg + '">' + (inv.risk_score || 0) + '<span style="font-size:14px;color:var(--text3)">/100</span></div>'
      + '<div style="font-size:10px;color:var(--text3);margin-top:4px">Confidence: ' + (inv.confidence || '?').toUpperCase() + '</div></div>'
      + '<div style="background:var(--bg3);border-radius:var(--r);padding:12px;margin-bottom:14px;font-size:12px;line-height:1.6;border-left:3px solid ' + vc.bg + '">' + _esc(inv.summary || '') + '</div>';

    if (inv.indicators && inv.indicators.length) {
      html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--crit);margin-bottom:4px">SUSPICIOUS INDICATORS</div>';
      inv.indicators.forEach(function (i) { html += '<div style="font-size:11px;padding:3px 0 3px 12px;border-left:2px solid var(--crit);margin:2px 0">&#9888; ' + _esc(i) + '</div>'; });
      html += '</div>';
    }
    if (inv.benign_explanations && inv.benign_explanations.length) {
      html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--low);margin-bottom:4px">POSSIBLE BENIGN EXPLANATIONS</div>';
      inv.benign_explanations.forEach(function (b) { html += '<div style="font-size:11px;padding:3px 0 3px 12px;border-left:2px solid var(--low);margin:2px 0">&#10004; ' + _esc(b) + '</div>'; });
      html += '</div>';
    }
    if (inv.recommended_actions && inv.recommended_actions.length) {
      html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--accent);margin-bottom:4px">RECOMMENDED ACTIONS</div>';
      inv.recommended_actions.forEach(function (a) { html += '<div style="font-size:11px;margin:2px 0;padding-left:12px">&#10148; ' + _esc(a) + '</div>'; });
      html += '</div>';
    }

    // Stats + peer
    html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px">'
      + _miniStat('Events', bl.total_events || 0, 'var(--text1)')
      + _miniStat('Logins', bl.login_count || 0, 'var(--accent)')
      + _miniStat('Fail Rate', Math.round((bl.fail_ratio || 0) * 100) + '%', bl.fail_ratio > 0.3 ? 'var(--crit)' : 'var(--low)')
      + _miniStat('Known IPs', (bl.known_ips || []).length, 'var(--med)')
      + '</div>';

    // Action buttons
    html += '<div style="display:flex;gap:8px;border-top:1px solid var(--border);padding-top:12px">';
    if (inv.escalate) html += '<button class="btn btn-sm" style="background:var(--crit);color:#fff" onclick="toast(\'Escalation sent\',\'info\')">&#9888; Escalate</button>';
    html += '<button class="btn btn-sm" onclick="CvUEBA.showHeatmap(\'' + _esc(data.username) + '\')">&#128200; Heatmap</button>'
      + '<button class="btn btn-sm" onclick="CvUEBA.showTimeline(\'' + _esc(data.username) + '\')">&#128197; Timeline</button>'
      + '<button class="btn btn-sm" onclick="CvUEBA.showPeers(\'' + _esc(data.username) + '\')">&#128101; Peers</button>'
      + '<button class="btn btn-sm" onclick="CvUEBA.blockUser(\'' + _esc(data.username) + '\')">&#128683; Block User</button>'
      + '</div></div>';

    container.innerHTML = html;
  }


  // ═══════════════════════════════════════════════════════════════════
  //  PEER GROUP
  // ═══════════════════════════════════════════════════════════════════

  function showPeers(username) {
    apiFetch('/api/v1/ueba/ai/peers/' + encodeURIComponent(username)).then(function (d) {
      var peers = d.peers || [];
      var dev = d.deviation || {};
      var html = '<div style="padding:12px"><div style="font-size:13px;font-weight:600;margin-bottom:10px">&#128101; Peer group — ' + _esc(username) + '</div>';
      if (!peers.length) {
        html += '<div style="font-size:12px;color:var(--text3)">No similar users found.</div>';
      } else {
        html += '<table style="width:100%;font-size:11px;border-collapse:collapse"><tr style="color:var(--text3);font-size:10px;border-bottom:1px solid var(--border)"><th style="padding:6px;text-align:left">User</th><th style="padding:6px;text-align:center">Similarity</th><th style="padding:6px;text-align:center">Daily Avg</th><th style="padding:6px;text-align:center">Logins</th></tr>';
        peers.forEach(function (p) {
          var sim = Math.round(p.similarity * 100);
          html += '<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px;font-weight:500;cursor:pointer;color:var(--accent)" onclick="CvUEBA.investigateUser(\'' + _esc(p.user) + '\')">' + _esc(p.user) + '</td><td style="padding:6px;text-align:center;color:' + (sim >= 70 ? 'var(--low)' : 'var(--med)') + ';font-weight:600">' + sim + '%</td><td style="padding:6px;text-align:center">' + (p.daily_avg || 0).toFixed(1) + '</td><td style="padding:6px;text-align:center">' + (p.login_count || 0) + '</td></tr>';
        });
        html += '</table>';
      }
      if (dev.assessment) {
        html += '<div style="margin-top:8px;font-size:11px;padding:6px;background:var(--bg3);border-radius:var(--r)">Peer deviation: <span style="font-weight:600;color:' + (dev.overall_peer_deviation >= 0.5 ? 'var(--crit)' : 'var(--low)') + '">' + (dev.overall_peer_deviation || 0) + '</span> — ' + _esc(dev.assessment) + '</div>';
      }
      html += '</div>';
      var resultEl = el('ueba-investigation-result');
      if (resultEl) { resultEl.style.display = 'block'; resultEl.innerHTML = html; }
    }).catch(function (e) { toast('Error: ' + e.message, 'error'); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  BLOCK USER (sends to Active Response)
  // ═══════════════════════════════════════════════════════════════════

  function blockUser(username, ip) {
    if (!ip) {
      apiFetch('/api/v1/ueba/ai/profiles').then(function(d) {
        var p = (d.profiles||[]).find(function(x){ return x.user===username; });
        if (p && p.known_ips && p.known_ips.length) {
          if (p.known_ips.length === 1) {
            blockUser(username, p.known_ips[0]);
          } else {
            var chosen = prompt('Multiple IPs for ' + username + ':
' + p.known_ips.join('
') + '

Enter IP to block:');
            if (chosen) blockUser(username, chosen.trim());
          }
        } else { toast('No IPs found for ' + username, 'error'); }
      });
      return;
    }
    if (!confirm('Block IP ' + ip + '?
This blocks it at the server firewall (iptables).
Associated user: ' + username)) return;

    apiFetch('/api/v1/server/block-ip', {
      method: 'POST',
      body: JSON.stringify({ ip: ip, reason: 'UEBA high-risk user: ' + username, blocked_by: 'UEBA-AI', duration_hours: 24 })
    }).then(function(d) {
      if (d.status === 'blocked') {
        toast('IP ' + ip + ' BLOCKED at server firewall (24h)', 'success');
      } else if (d.status === 'already_blocked') {
        toast('IP ' + ip + ' is already blocked', 'info');
      } else {
        toast('Block result: ' + (d.status||'unknown'), 'info');
      }
    }).catch(function(e) { toast('Block failed: ' + e.message, 'error'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  AI SCORING
  // ═══════════════════════════════════════════════════════════════════

  function scoreAlerts() {
    toast('Scoring recent UEBA alerts...', 'info');
    apiFetch('/api/v1/ueba/ai/score-batch', { method: 'POST', body: JSON.stringify({ limit: 5 }) })
      .then(function (d) {
        var scored = d.scored || [];
        if (!scored.length) { toast('No UEBA alerts to score', 'info'); return; }
        var html = '<div style="padding:12px"><div style="font-size:13px;font-weight:600;margin-bottom:10px">&#129302; AI Risk Scores</div>';
        scored.forEach(function (s) {
          var c = s.ai_score >= 70 ? 'var(--crit)' : s.ai_score >= 40 ? 'var(--high)' : s.ai_score >= 20 ? 'var(--med)' : 'var(--low)';
          html += '<div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid var(--border)">'
            + '<div style="text-align:center;min-width:50px"><div style="font-size:20px;font-weight:700;color:' + c + '">' + s.ai_score + '</div><div style="font-size:9px;color:var(--text3)">AI</div></div>'
            + '<div style="flex:1"><div style="font-size:11px;font-weight:500">' + _esc(s.alert_type || '') + ' — ' + _esc(s.user || '') + '</div>'
            + '<div style="font-size:10px;color:var(--text2);margin-top:2px">' + _esc(s.assessment || '') + '</div>'
            + '<div style="font-size:10px;color:var(--text3)">Rule:' + s.original_score + ' → AI:' + s.ai_score + ' · ' + (s.action || '?') + '</div></div>'
            + (s.likely_benign ? '<span style="font-size:9px;padding:2px 6px;border-radius:4px;background:var(--low)22;color:var(--low)">Benign</span>' : '') + '</div>';
        });
        html += '</div>';
        var r = el('ueba-investigation-result');
        if (r) { r.style.display = 'block'; r.innerHTML = html; }
        toast('Scored ' + scored.length + ' alerts', 'success');
      }).catch(function (e) { toast('Scoring failed: ' + e.message, 'error'); });
  }


  // ═══════════════════════════════════════════════════════════════════
  //  HELPERS
  // ═══════════════════════════════════════════════════════════════════

  function _miniStat(l, v, c) {
    return '<div style="background:var(--bg3);border-radius:var(--r);padding:10px;text-align:center"><div style="font-size:18px;font-weight:700;color:' + c + '">' + v + '</div><div style="font-size:9px;color:var(--text3);margin-top:2px">' + l + '</div></div>';
  }
  function _riskGauge(score, color) {
    var a = (Math.min(score,100) / 100) * 180;
    return '<div style="width:50px;height:28px;flex-shrink:0"><svg viewBox="0 0 50 28" width="50" height="28"><path d="M5 25 A20 20 0 0 1 45 25" fill="none" stroke="var(--border)" stroke-width="3" stroke-linecap="round"/><path d="M5 25 A20 20 0 0 1 45 25" fill="none" stroke="' + color + '" stroke-width="3" stroke-linecap="round" stroke-dasharray="' + (a/180*62.8).toFixed(1) + ' 62.8"/></svg></div>';
  }
  function _calcRisk(p) {
    var s = 0;
    s += (p.off_hours_pct || 0) * 30;
    s += (p.fail_ratio || 0) * 40;
    s += Math.min((p.ip_count || 0), 10) * 2;
    s += Math.min(Object.keys(p.tactics_seen || {}).length * 5, 20);
    s += Math.min((p.severity_profile || {}).critical || 0, 5) * 3;
    return Math.min(Math.round(s), 100);
  }
  function _fmtNum(n) { return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : n+''; }

  function rebuildBaselines() {
    var btn = el('ueba-rebuild-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Building...'; }
    apiFetch('/api/v1/ueba/ai/rebuild-baselines', { method: 'POST', body: JSON.stringify({ days: 30 }) })
      .then(function (d) { if (btn) { btn.disabled = false; btn.textContent = 'Rebuild Baselines'; } toast('Built ' + d.profiles_built + ' profiles', 'success'); loadAll(); })
      .catch(function (e) { if (btn) { btn.disabled = false; btn.textContent = 'Rebuild Baselines'; } toast('Error: ' + e.message, 'error'); });
  }

  function loadAll() { loadSummary(); loadAIProfiles(); }
  function init() { console.log('[CvUEBA] AI-UEBA v2 module loaded'); }

  return {
    init:init, loadAll:loadAll, loadSummary:loadSummary, loadAIProfiles:loadAIProfiles,
    investigateUser:investigateUser, showPeers:showPeers, showHeatmap:showHeatmap,
    showTimeline:showTimeline, scoreAlerts:scoreAlerts, rebuildBaselines:rebuildBaselines,
    blockUser:blockUser, toggleCard:toggleCard,
  };
})();

if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', CvUEBA.init); }
else { CvUEBA.init(); }
