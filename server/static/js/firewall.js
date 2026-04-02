/**
 * Cibervault Firewall Management Module
 * Manages server-side IP blocks, fail2ban integration, IP enrichment
 */
var CvFirewall = (function() {
  'use strict';

  function apiFetch(url, opts) {
    var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
    opts = opts || {};
    opts.headers = Object.assign({'Authorization':'Bearer '+token,'Content-Type':'application/json'}, opts.headers||{});
    return fetch(url, opts).then(function(r){ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); });
  }
  function el(id){ return document.getElementById(id); }
  function setHtml(id,h){ var e=el(id); if(e) e.innerHTML=h; }
  function toast(m,t){ if(typeof window.toast==='function') window.toast(m,t); }
  function _esc(t){ var d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function _ago(iso){
    if(!iso) return '';
    try{ var d=(Date.now()-new Date(iso).getTime())/1000;
      if(d<60) return 'just now'; if(d<3600) return Math.floor(d/60)+'m ago';
      if(d<86400) return Math.floor(d/3600)+'h ago'; return Math.floor(d/86400)+'d ago';
    }catch(e){ return iso.slice(0,16); }
  }

  // ═══════════════════════════════════════════════════════════════════
  //  STATS
  // ═══════════════════════════════════════════════════════════════════

  function loadStats() {
    apiFetch('/api/v1/server/firewall-stats').then(function(d) {
      var html = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px">'
        + _stat('Active Blocks', d.active_blocks||0, d.active_blocks>0?'var(--crit)':'var(--low)')
        + _stat('iptables Rules', d.iptables_rules||0, 'var(--accent)')
        + _stat('Fail2ban', d.fail2ban_active||0, 'var(--med)')
        + _stat('Expired', d.expired_total||0, 'var(--text3)')
        + '</div>';
      setHtml('fw-stats', html);
    }).catch(function(){ setHtml('fw-stats',''); });
  }

  function _stat(l,v,c){
    return '<div style="background:var(--bg3);border-radius:var(--r);padding:14px;text-align:center">'
      +'<div style="font-size:24px;font-weight:700;color:'+c+'">'+v+'</div>'
      +'<div style="font-size:11px;color:var(--text3);margin-top:2px">'+l+'</div></div>';
  }

  // ═══════════════════════════════════════════════════════════════════
  //  BLOCKED IP LIST
  // ═══════════════════════════════════════════════════════════════════

  function loadBlocked() {
    apiFetch('/api/v1/server/blocked-ips').then(function(d) {
      var blocked = d.blocked || [];
      if(!blocked.length) {
        setHtml('fw-blocked-list','<div class="empty" style="padding:30px"><div class="empty-icon" style="font-size:28px">&#128274;</div><div class="empty-title">No blocked IPs</div><div style="font-size:11px;color:var(--text3)">Firewall is clean</div></div>');
        return;
      }

      var html = '<table style="width:100%;font-size:12px;border-collapse:collapse">'
        +'<tr style="color:var(--text3);font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--border)">'
        +'<th style="padding:6px;text-align:left">IP Address</th>'
        +'<th style="padding:6px;text-align:left">Reason</th>'
        +'<th style="padding:6px;text-align:center">Source</th>'
        +'<th style="padding:6px;text-align:center">Events</th>'
        +'<th style="padding:6px;text-align:center">Blocked</th>'
        +'<th style="padding:6px;text-align:center">Expires</th>'
        +'<th style="padding:6px;text-align:center">Actions</th></tr>';

      blocked.forEach(function(b) {
        var srcBadge = {'manual':'var(--accent)','SOAR':'var(--med)','UEBA-AI':'var(--high)','fail2ban':'var(--low)','iptables':'var(--text3)'}[b.source||'']||'var(--text3)';
        html += '<tr style="border-bottom:1px solid var(--border)">'
          +'<td style="padding:8px 6px"><span style="font-family:var(--mono);font-weight:600;cursor:pointer;color:var(--accent)" onclick="CvFirewall.showIPInfo(\''+_esc(b.ip)+'\')">'+_esc(b.ip)+'</span>'
          +(b.in_iptables===false?'<span style="font-size:9px;color:var(--crit);margin-left:6px">NOT IN IPTABLES</span>':'')+'</td>'
          +'<td style="padding:8px 6px;font-size:11px;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+_esc(b.reason||'—')+'</td>'
          +'<td style="padding:8px 6px;text-align:center"><span style="font-size:10px;padding:2px 6px;border-radius:3px;background:'+srcBadge+'22;color:'+srcBadge+'">'+(b.source||'unknown')+'</span></td>'
          +'<td style="padding:8px 6px;text-align:center;font-family:var(--mono)">'+(b.event_count||0)+'</td>'
          +'<td style="padding:8px 6px;text-align:center;font-size:10px;color:var(--text3)">'+_ago(b.blocked_at)+'</td>'
          +'<td style="padding:8px 6px;text-align:center;font-size:10px">'+(b.expires_at?_ago(b.expires_at):'<span style="color:var(--crit)">permanent</span>')+'</td>'
          +'<td style="padding:8px 6px;text-align:center">'
          +'<button class="btn btn-sm" style="font-size:10px" onclick="CvFirewall.unblockIP(\''+_esc(b.ip)+'\')">Unblock</button>'
          +'</td></tr>';
      });
      html += '</table>';
      setHtml('fw-blocked-list', html);
    }).catch(function(e) { setHtml('fw-blocked-list','<div class="empty">Error: '+e.message+'</div>'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  BLOCK / UNBLOCK
  // ═══════════════════════════════════════════════════════════════════

  function blockIP() {
    var ip = (el('fw-block-ip')||{}).value||'';
    var reason = (el('fw-block-reason')||{}).value||'Manual block';
    var hours = parseInt((el('fw-block-hours')||{value:'0'}).value)||0;
    var agents = (el('fw-block-agents')||{}).checked||false;
    if(!ip.trim()){ toast('Enter an IP address','error'); return; }

    apiFetch('/api/v1/server/block-ip',{
      method:'POST',
      body:JSON.stringify({ip:ip.trim(), reason:reason, duration_hours:hours, blocked_by:'admin', block_agents:agents, source:'manual'})
    }).then(function(d){
      if(d.status==='blocked'){
        toast('Blocked '+ip+(d.agents_blocked?' + '+d.agents_blocked+' agents':''),'success');
      } else if(d.status==='already_blocked'){
        toast(ip+' is already blocked','info');
      }
      loadAll();
      if(el('fw-block-ip')) el('fw-block-ip').value='';
      if(el('fw-block-reason')) el('fw-block-reason').value='';
    }).catch(function(e){ toast('Block failed: '+e.message,'error'); });
  }

  function unblockIP(ip) {
    if(!confirm('Unblock '+ip+'?')) return;
    apiFetch('/api/v1/server/unblock-ip',{
      method:'POST',
      body:JSON.stringify({ip:ip, unblocked_by:'admin'})
    }).then(function(){
      toast(ip+' unblocked','success');
      loadAll();
    }).catch(function(e){ toast('Unblock failed: '+e.message,'error'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  IP ENRICHMENT
  // ═══════════════════════════════════════════════════════════════════

  function showIPInfo(ip) {
    var panel = el('fw-ip-detail');
    if(panel){ panel.style.display='block'; panel.innerHTML='<div style="padding:20px;text-align:center;color:var(--text3)">Loading info for '+_esc(ip)+'...</div>'; }

    apiFetch('/api/v1/server/ip-info/'+encodeURIComponent(ip)).then(function(d) {
      var html = '<div style="padding:16px">'
        +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'
        +'<div><span style="font-size:16px;font-weight:700;font-family:var(--mono)">'+_esc(d.ip)+'</span>'
        +(d.blocked?'<span style="margin-left:8px;font-size:10px;padding:2px 8px;border-radius:4px;background:var(--crit);color:#fff">BLOCKED</span>':'<span style="margin-left:8px;font-size:10px;padding:2px 8px;border-radius:4px;background:var(--low)22;color:var(--low)">NOT BLOCKED</span>')
        +'</div>'
        +(d.blocked
          ?'<button class="btn btn-sm" onclick="CvFirewall.unblockIP(\''+_esc(ip)+'\')">Unblock</button>'
          :'<button class="btn btn-sm" style="background:var(--crit);color:#fff" onclick="CvFirewall.quickBlock(\''+_esc(ip)+'\')">Block Now</button>')
        +'</div>';

      // Stats grid
      html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px">'
        +_stat('Total Events', d.total_events||0, 'var(--text1)')
        +_stat('Hosts Targeted', (d.targeted_hosts||[]).length, 'var(--accent)')
        +_stat('MITRE Techniques', (d.mitre_techniques||[]).length, 'var(--med)')
        +_stat('Users Targeted', (d.users_targeted||[]).length, 'var(--high)')
        +'</div>';

      // Timeline
      if(d.first_seen){
        html += '<div style="font-size:11px;color:var(--text3);margin-bottom:10px">First seen: '+_esc(d.first_seen).slice(0,19)+' &middot; Last seen: '+_esc(d.last_seen||'').slice(0,19)+'</div>';
      }

      // Event types
      if(d.event_types && Object.keys(d.event_types).length){
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">EVENT TYPES</div>';
        Object.keys(d.event_types).forEach(function(et){
          var c = et.includes('failure')?'var(--crit)':et.includes('success')?'var(--low)':'var(--text2)';
          html += '<span style="display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;background:var(--bg3);margin:2px;color:'+c+'">'+_esc(et)+': '+d.event_types[et]+'</span>';
        });
        html += '</div>';
      }

      // Severity
      if(d.severity_breakdown && Object.keys(d.severity_breakdown).length){
        var sevC = {critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)'};
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">SUSPICIOUS EVENT SEVERITY</div>';
        Object.keys(d.severity_breakdown).forEach(function(s){
          html += '<span style="display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;background:'+(sevC[s]||'var(--text3)')+'22;color:'+(sevC[s]||'var(--text3)')+';margin:2px">'+s+': '+d.severity_breakdown[s]+'</span>';
        });
        html += '</div>';
      }

      // MITRE
      if(d.mitre_techniques && d.mitre_techniques.length){
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">MITRE TECHNIQUES</div>';
        d.mitre_techniques.forEach(function(t){
          html += '<span style="display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;background:var(--accent)22;color:var(--accent);margin:2px">'+_esc(t)+'</span>';
        });
        html += '</div>';
      }

      // Users targeted
      if(d.users_targeted && d.users_targeted.length){
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">USERS TARGETED</div>'
          +'<div style="font-size:11px">'+d.users_targeted.map(function(u){ return _esc(u); }).join(', ')+'</div></div>';
      }

      // Hosts
      if(d.targeted_hosts && d.targeted_hosts.length){
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">TARGETED HOSTS</div>'
          +'<div style="font-size:11px">'+d.targeted_hosts.map(function(h){ return _esc(h); }).join(', ')+'</div></div>';
      }

      // Block history
      if(d.block_history && d.block_history.length){
        html += '<div style="margin-bottom:12px"><div style="font-size:10px;font-weight:600;color:var(--text3);margin-bottom:4px">BLOCK HISTORY</div>';
        d.block_history.forEach(function(b){
          var sc = b.status==='active'?'var(--crit)':b.status==='unblocked'?'var(--low)':'var(--text3)';
          html += '<div style="font-size:11px;padding:3px 0"><span style="color:'+sc+';font-weight:600">'+_esc(b.status)+'</span> by '+_esc(b.blocked_by||'')+' '+_ago(b.blocked_at)+' — '+_esc(b.reason||'')+'</div>';
        });
        html += '</div>';
      }

      html += '</div>';
      if(panel) panel.innerHTML = html;
    }).catch(function(e){ if(panel) panel.innerHTML='<div style="padding:16px;color:var(--crit)">Error: '+e.message+'</div>'; });
  }

  function quickBlock(ip) {
    apiFetch('/api/v1/server/block-ip',{
      method:'POST',
      body:JSON.stringify({ip:ip, reason:'Quick block from IP info panel', blocked_by:'admin', source:'manual'})
    }).then(function(){
      toast(ip+' blocked','success');
      showIPInfo(ip);
      loadAll();
    }).catch(function(e){ toast('Block failed: '+e.message,'error'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  FAIL2BAN
  // ═══════════════════════════════════════════════════════════════════

  function loadFail2ban() {
    apiFetch('/api/v1/server/fail2ban/status').then(function(d) {
      if(!d.installed){
        setHtml('fw-f2b','<div style="padding:12px;font-size:12px;color:var(--text3)">fail2ban not installed. Install with: <code style="background:var(--bg3);padding:2px 6px;border-radius:3px">apt install fail2ban</code></div>');
        return;
      }
      if(!d.running){
        setHtml('fw-f2b','<div style="padding:12px;font-size:12px;color:var(--med)">fail2ban installed but not running. Start with: <code style="background:var(--bg3);padding:2px 6px;border-radius:3px">systemctl start fail2ban</code></div>');
        return;
      }

      var html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'
        +'<span style="font-size:11px;color:var(--low);font-weight:600">fail2ban active</span>'
        +'<button class="btn btn-sm" onclick="CvFirewall.syncFail2ban()">Sync to Cibervault</button></div>';

      if(d.jails && d.jails.length){
        d.jails.forEach(function(j){
          html += '<div style="display:flex;align-items:center;gap:10px;padding:6px;border-bottom:1px solid var(--border)">'
            +'<span style="font-size:12px;font-weight:600;min-width:80px">'+_esc(j.name)+'</span>'
            +'<span style="font-size:11px;color:var(--crit)">'+j.currently_banned+' banned</span>'
            +'<span style="font-size:11px;color:var(--text3)">'+j.total_failed+' failures</span>'
            +'</div>';
          if(j.banned_ips && j.banned_ips.length){
            j.banned_ips.forEach(function(ip){
              html += '<div style="font-size:11px;padding:2px 0 2px 20px;font-family:var(--mono);color:var(--text2)">'
                +_esc(ip)
                +' <button class="btn btn-sm" style="font-size:9px;padding:0 4px;margin-left:4px" onclick="CvFirewall.showIPInfo(\''+_esc(ip)+'\')">Info</button>'
                +'</div>';
            });
          }
        });
      } else {
        html += '<div style="font-size:11px;color:var(--text3)">No jails configured</div>';
      }
      setHtml('fw-f2b', html);
    }).catch(function(){ setHtml('fw-f2b','<div style="font-size:11px;color:var(--text3)">Could not check fail2ban</div>'); });
  }

  function syncFail2ban() {
    toast('Syncing fail2ban bans...','info');
    apiFetch('/api/v1/server/fail2ban/sync',{method:'POST'}).then(function(d){
      toast('Synced '+d.synced+' bans from '+d.jails+' jails','success');
      loadAll();
    }).catch(function(e){ toast('Sync failed: '+e.message,'error'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  HISTORY
  // ═══════════════════════════════════════════════════════════════════

  function loadHistory() {
    apiFetch('/api/v1/server/block-history?limit=30').then(function(d) {
      var history = d.history || [];
      if(!history.length){ setHtml('fw-history','<div class="empty" style="padding:20px"><div class="empty-title">No block history</div></div>'); return; }

      var html = '';
      history.forEach(function(b){
        var sc = {active:'var(--crit)',unblocked:'var(--low)',expired:'var(--text3)'}[b.status]||'var(--text3)';
        html += '<div style="display:flex;align-items:center;gap:10px;padding:6px;border-bottom:1px solid var(--border)">'
          +'<div style="width:8px;height:8px;border-radius:50%;background:'+sc+';flex-shrink:0"></div>'
          +'<span style="font-family:var(--mono);font-size:12px;min-width:110px;cursor:pointer;color:var(--accent)" onclick="CvFirewall.showIPInfo(\''+_esc(b.ip)+'\')">'+_esc(b.ip)+'</span>'
          +'<span style="font-size:10px;color:'+sc+';font-weight:600;min-width:60px">'+_esc(b.status||'')+'</span>'
          +'<span style="font-size:10px;color:var(--text3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+_esc(b.reason||'')+'</span>'
          +'<span style="font-size:10px;color:var(--text3)">'+_esc(b.source||'')+'</span>'
          +'<span style="font-size:10px;color:var(--text3)">'+_ago(b.blocked_at)+'</span>'
          +'</div>';
      });
      setHtml('fw-history', html);
    }).catch(function(){ setHtml('fw-history','<div class="empty">Error loading history</div>'); });
  }

  // ═══════════════════════════════════════════════════════════════════
  //  LOAD ALL
  // ═══════════════════════════════════════════════════════════════════

  function loadAll() {
    loadStats();
    loadBlocked();
    loadFail2ban();
    loadHistory();
  }

  function init() { console.log('[CvFirewall] Firewall module loaded'); }

  return {
    init:init, loadAll:loadAll, loadStats:loadStats, loadBlocked:loadBlocked,
    blockIP:blockIP, unblockIP:unblockIP, showIPInfo:showIPInfo, quickBlock:quickBlock,
    loadFail2ban:loadFail2ban, syncFail2ban:syncFail2ban, loadHistory:loadHistory,
  };
})();

if(document.readyState==='loading'){ document.addEventListener('DOMContentLoaded', CvFirewall.init); }
else { CvFirewall.init(); }
