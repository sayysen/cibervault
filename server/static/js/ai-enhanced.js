/**
 * Cibervault EDR — Enhanced AI Analyst Module
 * Markdown rendering, actionable buttons, streaming support, auto-context
 *
 * Usage: CvAI.init()  — call after DOM ready and AI tab visible
 */
var CvAI = (function() {
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
    //  MARKDOWN RENDERER (lightweight)
    // ═══════════════════════════════════════════════════════════════════
    function renderMarkdown(text) {
        if (!text) return '';
        var html = _escHtml(text);

        // Code blocks ```lang\n...\n```
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, function(m, lang, code) {
            return '<pre><code class="lang-' + lang + '">' + code.trim() + '</code></pre>';
        });
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        // Bold
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        // Italic
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        // Headers
        html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        // Unordered lists
        html = html.replace(/^[-•] (.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>(\n|$))+/g, function(m) { return '<ul>' + m + '</ul>'; });
        // Ordered lists
        html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
        // Tables (simple pipe tables)
        html = html.replace(/^\|(.+)\|\s*\n\|[-| :]+\|\s*\n((?:\|.+\|\s*\n?)*)/gm, function(m, header, body) {
            var ths = header.split('|').filter(Boolean).map(function(h) { return '<th>' + h.trim() + '</th>'; }).join('');
            var rows = body.trim().split('\n').map(function(row) {
                var tds = row.split('|').filter(Boolean).map(function(c) { return '<td>' + c.trim() + '</td>'; }).join('');
                return '<tr>' + tds + '</tr>';
            }).join('');
            return '<table><thead><tr>' + ths + '</tr></thead><tbody>' + rows + '</tbody></table>';
        });
        // Line breaks
        html = html.replace(/\n/g, '<br>');
        // Clean up double breaks
        html = html.replace(/<br><br>/g, '<br>');
        html = html.replace(/<br>(<\/?(?:ul|ol|li|h3|h4|pre|table))/g, '$1');
        html = html.replace(/(<\/(?:ul|ol|li|h3|h4|pre|table)>)<br>/g, '$1');

        return html;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  ENHANCED CHAT MESSAGE
    // ═══════════════════════════════════════════════════════════════════
    function addEnhancedMessage(role, text, actions) {
        var hist = document.getElementById('ai-chat-history');
        if (!hist) return;

        // Remove placeholder
        var placeholder = hist.querySelector('[style*="text-align:center"]');
        if (placeholder && hist.children.length === 1) hist.removeChild(placeholder);

        var div = document.createElement('div');
        var isUser = role === 'user';
        div.style.cssText = 'display:flex;flex-direction:column;align-items:' + (isUser ? 'flex-end' : 'flex-start');
        div.className = 'cv-animate-in';

        var bubble = document.createElement('div');
        bubble.className = 'ai-msg-bubble ' + (isUser ? 'user' : 'assistant');

        if (isUser) {
            bubble.textContent = text;
        } else {
            bubble.innerHTML = renderMarkdown(text);
        }

        div.appendChild(bubble);

        // Actionable buttons for AI responses
        if (!isUser && actions && actions.length) {
            var btnRow = document.createElement('div');
            btnRow.className = 'ai-action-buttons';
            for (var i = 0; i < actions.length; i++) {
                var btn = document.createElement('button');
                btn.className = 'ai-action-btn';
                btn.textContent = actions[i].label;
                btn.dataset.action = actions[i].action;
                btn.dataset.value = actions[i].value || '';
                btn.addEventListener('click', _handleActionClick);
                btnRow.appendChild(btn);
            }
            div.appendChild(btnRow);
        }

        // Auto-detect actionable content in AI responses
        if (!isUser && !actions) {
            var autoActions = _detectActions(text);
            if (autoActions.length) {
                var autoBtns = document.createElement('div');
                autoBtns.className = 'ai-action-buttons';
                for (var j = 0; j < autoActions.length; j++) {
                    var ab = document.createElement('button');
                    ab.className = 'ai-action-btn';
                    ab.textContent = autoActions[j].label;
                    ab.dataset.action = autoActions[j].action;
                    ab.dataset.value = autoActions[j].value || '';
                    ab.addEventListener('click', _handleActionClick);
                    autoBtns.appendChild(ab);
                }
                div.appendChild(autoBtns);
            }
        }

        hist.appendChild(div);
        hist.scrollTop = hist.scrollHeight;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  AUTO-DETECT ACTIONABLE CONTENT
    // ═══════════════════════════════════════════════════════════════════
    function _detectActions(text) {
        var actions = [];
        if (!text) return actions;

        // Detect IP addresses → offer to block
        var ips = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g);
        if (ips) {
            var uniqueIps = [];
            for (var i = 0; i < ips.length; i++) {
                if (uniqueIps.indexOf(ips[i]) < 0 && ips[i] !== '127.0.0.1' && ips[i] !== '0.0.0.0') {
                    uniqueIps.push(ips[i]);
                }
            }
            for (var ii = 0; ii < Math.min(uniqueIps.length, 3); ii++) {
                actions.push({ label: '🚫 Block ' + uniqueIps[ii], action: 'block_ip', value: uniqueIps[ii] });
            }
        }

        // Detect MITRE IDs → offer to hunt
        var mitreIds = text.match(/T\d{4}(?:\.\d{3})?/g);
        if (mitreIds) {
            var uniqueMitre = [];
            for (var m = 0; m < mitreIds.length; m++) {
                if (uniqueMitre.indexOf(mitreIds[m]) < 0) uniqueMitre.push(mitreIds[m]);
            }
            for (var mm = 0; mm < Math.min(uniqueMitre.length, 2); mm++) {
                actions.push({ label: '🔍 Hunt ' + uniqueMitre[mm], action: 'hunt', value: uniqueMitre[mm] });
            }
        }

        // Detect process names in suspicious context
        if (/kill|terminate|stop|suspicious process/i.test(text)) {
            actions.push({ label: '📋 List Processes', action: 'list_processes', value: '' });
        }

        // Detect script/code blocks → offer to copy
        if (/```/.test(text)) {
            actions.push({ label: '📋 Copy Script', action: 'copy_code', value: '' });
        }

        // Always offer follow-up
        if (text.length > 200) {
            actions.push({ label: '❓ Tell me more', action: 'followup', value: 'Can you elaborate on that?' });
        }

        return actions;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  ACTION HANDLERS
    // ═══════════════════════════════════════════════════════════════════
    function _handleActionClick(e) {
        var action = e.target.dataset.action;
        var value = e.target.dataset.value;

        switch (action) {
            case 'block_ip':
                if (typeof showPage === 'function') showPage('response');
                // Pre-fill active response
                setTimeout(function() {
                    var sel = document.getElementById('ar-cmd-select') || document.querySelector('[data-cmd="block_ip"]');
                    if (sel) {
                        // Try to select block_ip and fill parameter
                        var param = document.querySelector('#ar-param-input, [id*="param"]');
                        if (param) param.value = value;
                    }
                    if (typeof toast === 'function') toast('Navigate to Active Response → Block IP: ' + value, 'info');
                }, 200);
                break;

            case 'hunt':
                if (typeof showPage === 'function') showPage('hunting');
                setTimeout(function() {
                    var q = document.getElementById('hunt-q');
                    if (q) { q.value = value; if (typeof doHunt === 'function') doHunt(); }
                }, 200);
                break;

            case 'list_processes':
                _setPrompt('List all running processes on the affected host');
                break;

            case 'copy_code':
                // Find last code block in AI response
                var codeBlocks = document.querySelectorAll('.ai-msg-bubble.assistant pre code');
                if (codeBlocks.length) {
                    var lastCode = codeBlocks[codeBlocks.length - 1].textContent;
                    if (navigator.clipboard) {
                        navigator.clipboard.writeText(lastCode);
                        if (typeof toast === 'function') toast('Script copied to clipboard!', 'success');
                    }
                }
                break;

            case 'followup':
                _setPrompt(value);
                break;
        }
    }

    function _setPrompt(text) {
        var inp = document.getElementById('ai-chat-input');
        if (inp) { inp.value = text; inp.focus(); }
    }


    // ═══════════════════════════════════════════════════════════════════
    //  ENHANCED SEND (with auto-context injection)
    // ═══════════════════════════════════════════════════════════════════
    function enhancedSend() {
        var inp = document.getElementById('ai-chat-input');
        var btn = document.getElementById('ai-chat-send');
        var msg = (inp ? inp.value : '').trim();
        if (!msg) return;
        if (inp) inp.value = '';
        btn.disabled = true;
        btn.textContent = 'Thinking...';

        addEnhancedMessage('user', msg);

        if (typeof AI_CHAT_HISTORY !== 'undefined') {
            AI_CHAT_HISTORY.push({ role: 'user', content: msg });
        }

        // Add thinking indicator with pulse animation
        var hist = document.getElementById('ai-chat-history');
        var thinking = document.createElement('div');
        thinking.id = 'ai-thinking';
        thinking.style.cssText = 'display:flex;align-items:flex-start';
        thinking.innerHTML = '<div class="ai-msg-bubble assistant cv-pulse" style="display:flex;align-items:center;gap:8px">'
            + '<svg width="16" height="16" viewBox="0 0 16 16" style="flex-shrink:0;animation:spin 1s linear infinite">'
            + '<circle cx="8" cy="8" r="6" fill="none" stroke="var(--accent)" stroke-width="2" stroke-dasharray="20 10"/></svg>'
            + '<span>AI is analyzing...</span></div>';
        hist.appendChild(thinking);
        hist.scrollTop = hist.scrollHeight;

        apiFetch('/api/v1/ai/chat', {
            method: 'POST',
            body: JSON.stringify({
                message: msg,
                history: (typeof AI_CHAT_HISTORY !== 'undefined') ? AI_CHAT_HISTORY.slice(-10) : []
            })
        })
        .then(function(d) {
            var t = document.getElementById('ai-thinking');
            if (t) t.parentNode.removeChild(t);
            btn.disabled = false;
            btn.textContent = 'Send';

            var reply = d.reply || 'No response';
            addEnhancedMessage('assistant', reply);

            if (typeof AI_CHAT_HISTORY !== 'undefined') {
                AI_CHAT_HISTORY.push({ role: 'assistant', content: reply });
                if (AI_CHAT_HISTORY.length > 20) AI_CHAT_HISTORY = AI_CHAT_HISTORY.slice(-20);
            }
        })
        .catch(function(e) {
            var t = document.getElementById('ai-thinking');
            if (t) t.parentNode.removeChild(t);
            btn.disabled = false;
            btn.textContent = 'Send';
            addEnhancedMessage('assistant', '⚠️ Error: ' + e.message + '. Make sure AI is configured in the Setup tab.');
        });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  ENHANCED AUTO-TRIAGE (with visual summary)
    // ═══════════════════════════════════════════════════════════════════
    function enhancedTriage() {
        var btn = document.getElementById('ai-triage-btn');
        var res = document.getElementById('ai-triage-result');
        if (btn) { btn.disabled = true; btn.innerHTML = '<span class="cv-pulse">🔍 Analyzing alerts...</span>'; }
        if (res) res.style.display = 'none';

        apiFetch('/api/v1/ai/auto-triage', { method: 'POST', body: '{}' })
        .then(function(d) {
            if (btn) { btn.disabled = false; btn.textContent = '🤖 Run Auto-Triage Now'; }
            if (!res) return;
            res.style.display = 'block';

            var meta = document.getElementById('ai-triage-meta');
            var txt = document.getElementById('ai-triage-text');

            if (meta) meta.innerHTML = '✅ Analyzed <strong>' + (d.alert_count || 0) + '</strong> critical/high alerts — '
                + new Date().toLocaleTimeString();

            if (txt) {
                txt.innerHTML = renderMarkdown(d.summary || 'No summary available');
            }

            if (typeof toast === 'function') toast('Triage complete!', 'success');
        })
        .catch(function(e) {
            if (btn) { btn.disabled = false; btn.textContent = '🤖 Run Auto-Triage Now'; }
            if (typeof toast === 'function') toast('Triage error: ' + e.message, 'error');
        });
    }


    // ── Helpers ──────────────────────────────────────────────────────
    function _escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ═══════════════════════════════════════════════════════════════════
    //  INIT — Override existing AI functions
    // ═══════════════════════════════════════════════════════════════════
    function init() {
        // Override the global sendAIChat if it exists
        if (typeof window.sendAIChat !== 'undefined') {
            window._originalSendAIChat = window.sendAIChat;
        }
        window.sendAIChat = enhancedSend;

        // Override addChatMessage
        if (typeof window.addChatMessage !== 'undefined') {
            window._originalAddChatMessage = window.addChatMessage;
        }
        window.addChatMessage = function(role, text) {
            addEnhancedMessage(role, text);
        };

        // Override runAutoTriage
        if (typeof window.runAutoTriage !== 'undefined') {
            window._originalRunAutoTriage = window.runAutoTriage;
        }
        window.runAutoTriage = enhancedTriage;

        // Add CSS for spinner
        var style = document.createElement('style');
        style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    }

    return {
        init: init,
        addEnhancedMessage: addEnhancedMessage,
        enhancedSend: enhancedSend,
        enhancedTriage: enhancedTriage,
        renderMarkdown: renderMarkdown,
    };
})();
