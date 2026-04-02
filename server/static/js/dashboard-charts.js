/**
 * Cibervault EDR — Dashboard Charts Module
 * Requires Chart.js 4.x loaded via CDN
 * 
 * Usage: after DOM ready, call CvCharts.init()
 */
var CvCharts = (function() {
    'use strict';

    // Chart.js default overrides for dark theme
    var COLORS = {
        critical: '#ff453a',
        high:     '#ff9f0a',
        medium:   '#ffd60a',
        low:      '#32d74b',
        info:     '#636366',
        accent:   getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#64d2ff',
        bg:       getComputedStyle(document.documentElement).getPropertyValue('--bg2').trim() || '#1c1c1e',
        border:   getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#38383a',
        text1:    getComputedStyle(document.documentElement).getPropertyValue('--text1').trim() || '#f5f5f7',
        text3:    getComputedStyle(document.documentElement).getPropertyValue('--text3').trim() || '#636366',
        grid:     'rgba(255,255,255,0.04)',
    };

    var _charts = {};     // store Chart instances for destroy/update
    var _timeRange = 24;  // default hours
    var _refreshTimer = null;

    // ── Helpers ──────────────────────────────────────────────────────────
    function apiFetch(url) {
        var token = localStorage.getItem('cv_token') || sessionStorage.getItem('cv_token') || '';
        return fetch(url, {
            headers: { 'Authorization': 'Bearer ' + token }
        }).then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        });
    }

    function destroyChart(id) {
        if (_charts[id]) {
            _charts[id].destroy();
            delete _charts[id];
        }
    }

    function shortNum(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return n;
    }

    function formatTime(iso) {
        if (!iso) return '';
        var d = new Date(iso);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // ── Chart.js Global Config ──────────────────────────────────────────
    function configureChartDefaults() {
        if (!window.Chart) return;
        Chart.defaults.color = COLORS.text3;
        Chart.defaults.borderColor = COLORS.grid;
        Chart.defaults.font.family = "'SF Mono', 'Fira Code', 'Cascadia Code', monospace";
        Chart.defaults.font.size = 10;
        Chart.defaults.plugins.legend.labels.boxWidth = 10;
        Chart.defaults.plugins.legend.labels.padding = 12;
        Chart.defaults.plugins.tooltip.backgroundColor = '#2c2c2e';
        Chart.defaults.plugins.tooltip.titleColor = '#f5f5f7';
        Chart.defaults.plugins.tooltip.bodyColor = '#aeaeb2';
        Chart.defaults.plugins.tooltip.borderColor = '#48484a';
        Chart.defaults.plugins.tooltip.borderWidth = 1;
        Chart.defaults.plugins.tooltip.cornerRadius = 6;
        Chart.defaults.plugins.tooltip.padding = 10;
    }


    // ═══════════════════════════════════════════════════════════════════
    //  1. SEVERITY DONUT CHART
    // ═══════════════════════════════════════════════════════════════════
    function renderSeverityDonut(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<canvas id="cv-severity-donut"></canvas>';

        apiFetch('/api/v1/charts/severity-distribution?hours=' + _timeRange)
        .then(function(d) {
            var dist = d.distribution || {};
            var total = d.total || 0;
            destroyChart('severity-donut');

            var ctx = document.getElementById('cv-severity-donut');
            if (!ctx) return;

            _charts['severity-donut'] = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [dist.critical, dist.high, dist.medium, dist.low, dist.info],
                        backgroundColor: [COLORS.critical, COLORS.high, COLORS.medium, COLORS.low, COLORS.info],
                        borderWidth: 0,
                        hoverBorderWidth: 2,
                        hoverBorderColor: '#fff',
                        spacing: 2,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    cutout: '68%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 16, usePointStyle: true, pointStyle: 'circle' }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(ctx) {
                                    var pct = total ? Math.round(ctx.raw / total * 100) : 0;
                                    return ctx.label + ': ' + ctx.raw + ' (' + pct + '%)';
                                }
                            }
                        }
                    }
                },
                plugins: [{
                    // Center text plugin
                    id: 'donutCenter',
                    beforeDraw: function(chart) {
                        var width  = chart.width;
                        var height = chart.height;
                        var ctx2   = chart.ctx;
                        ctx2.restore();
                        ctx2.fillStyle = COLORS.text1;
                        ctx2.font = 'bold 22px ' + Chart.defaults.font.family;
                        ctx2.textBaseline = 'middle';
                        ctx2.textAlign = 'center';
                        ctx2.fillText(shortNum(total), width / 2, height / 2 - 8);
                        ctx2.font = '10px ' + Chart.defaults.font.family;
                        ctx2.fillStyle = COLORS.text3;
                        ctx2.fillText('ALERTS', width / 2, height / 2 + 12);
                        ctx2.save();
                    }
                }]
            });
        })
        .catch(function(e) { el.innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:40px">Error loading severity data</div>'; });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  2. EVENT TREND LINE CHART
    // ═══════════════════════════════════════════════════════════════════
    function renderEventTrend(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<canvas id="cv-event-trend"></canvas>';

        var bucket = _timeRange <= 6 ? 15 : _timeRange <= 24 ? 60 : 360;
        apiFetch('/api/v1/charts/event-trend?hours=' + _timeRange + '&bucket_minutes=' + bucket)
        .then(function(d) {
            var series = d.series || [];
            destroyChart('event-trend');

            var labels     = series.map(function(s) { return formatTime(s.time); });
            var totalData  = series.map(function(s) { return s.total; });
            var suspData   = series.map(function(s) { return s.suspicious; });
            var critData   = series.map(function(s) { return s.critical; });

            var ctx = document.getElementById('cv-event-trend');
            if (!ctx) return;

            _charts['event-trend'] = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Total Events',
                            data: totalData,
                            borderColor: COLORS.accent,
                            backgroundColor: COLORS.accent + '18',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                        },
                        {
                            label: 'Suspicious',
                            data: suspData,
                            borderColor: COLORS.medium,
                            backgroundColor: COLORS.medium + '12',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 1.5,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                        },
                        {
                            label: 'Critical',
                            data: critData,
                            borderColor: COLORS.critical,
                            backgroundColor: COLORS.critical + '10',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 1.5,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { maxTicksLimit: 12 }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: COLORS.grid },
                            ticks: { callback: shortNum }
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            align: 'end',
                            labels: { usePointStyle: true, pointStyle: 'line', padding: 14 }
                        }
                    }
                }
            });
        })
        .catch(function(e) { el.innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:40px">Error loading trend data</div>'; });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  3. TOP HOSTS BAR CHART
    // ═══════════════════════════════════════════════════════════════════
    function renderTopHosts(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<canvas id="cv-top-hosts"></canvas>';

        apiFetch('/api/v1/charts/top-hosts?hours=' + _timeRange + '&limit=8')
        .then(function(d) {
            var hosts = d.hosts || [];
            destroyChart('top-hosts');
            if (!hosts.length) {
                el.innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:40px">No host data</div>';
                return;
            }

            var ctx = document.getElementById('cv-top-hosts');
            if (!ctx) return;

            _charts['top-hosts'] = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: hosts.map(function(h) { return h.hostname; }),
                    datasets: [
                        {
                            label: 'Critical',
                            data: hosts.map(function(h) { return h.critical; }),
                            backgroundColor: COLORS.critical + 'cc',
                            borderRadius: 2,
                        },
                        {
                            label: 'High',
                            data: hosts.map(function(h) { return h.high; }),
                            backgroundColor: COLORS.high + 'cc',
                            borderRadius: 2,
                        },
                        {
                            label: 'Medium',
                            data: hosts.map(function(h) { return h.medium; }),
                            backgroundColor: COLORS.medium + '88',
                            borderRadius: 2,
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    scales: {
                        x: {
                            stacked: true,
                            grid: { color: COLORS.grid },
                            ticks: { callback: shortNum }
                        },
                        y: {
                            stacked: true,
                            grid: { display: false },
                            ticks: { font: { size: 11 } }
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                            align: 'end',
                            labels: { usePointStyle: true, pointStyle: 'rectRounded', padding: 12 }
                        }
                    }
                }
            });
        })
        .catch(function() { el.innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:40px">Error loading host data</div>'; });
    }


    // ═══════════════════════════════════════════════════════════════════
    //  4. EVENT TYPE BREAKDOWN
    // ═══════════════════════════════════════════════════════════════════
    function renderEventTypes(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<canvas id="cv-event-types"></canvas>';

        apiFetch('/api/v1/charts/event-types?hours=' + _timeRange)
        .then(function(d) {
            var types = d.types || [];
            destroyChart('event-types');
            if (!types.length) { el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:11px">No data</div>'; return; }

            var palette = [
                '#64d2ff', '#ff453a', '#ffd60a', '#32d74b', '#bf5af2',
                '#ff9f0a', '#ff375f', '#0a84ff', '#30d158', '#ac8e68',
                '#5e5ce6', '#ff6482', '#66d4cf', '#da8fff', '#ffa733'
            ];
            var ctx = document.getElementById('cv-event-types');
            if (!ctx) return;

            _charts['event-types'] = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: types.map(function(t) { return t.type.replace(/_/g, ' '); }),
                    datasets: [
                        {
                            label: 'Total',
                            data: types.map(function(t) { return t.total; }),
                            backgroundColor: types.map(function(t, i) { return palette[i % palette.length] + '66'; }),
                            borderColor: types.map(function(t, i) { return palette[i % palette.length]; }),
                            borderWidth: 1,
                            borderRadius: 3,
                        },
                        {
                            label: 'Suspicious',
                            data: types.map(function(t) { return t.suspicious; }),
                            backgroundColor: COLORS.critical + '55',
                            borderColor: COLORS.critical,
                            borderWidth: 1,
                            borderRadius: 3,
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { display: false }, ticks: { maxRotation: 45, font: { size: 9 } } },
                        y: { grid: { color: COLORS.grid }, ticks: { callback: shortNum } }
                    },
                    plugins: {
                        legend: { position: 'top', align: 'end', labels: { usePointStyle: true, pointStyle: 'rectRounded' } }
                    }
                }
            });
        })
        .catch(function() {});
    }


    // ═══════════════════════════════════════════════════════════════════
    //  5. MITRE TACTIC BAR (dashboard mini version)
    // ═══════════════════════════════════════════════════════════════════
    function renderMitreTacticBar(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;
        el.innerHTML = '<canvas id="cv-mitre-bar"></canvas>';

        apiFetch('/api/v1/charts/mitre-heatmap?hours=' + (_timeRange * 7))
        .then(function(d) {
            var tactics = (d.tactics || []).filter(function(t) { return t.count > 0; });
            destroyChart('mitre-bar');
            if (!tactics.length) { el.innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px;font-size:11px">No MITRE data</div>'; return; }

            var ctx = document.getElementById('cv-mitre-bar');
            if (!ctx) return;

            var maxC = Math.max.apply(null, tactics.map(function(t) { return t.count; }));

            _charts['mitre-bar'] = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: tactics.map(function(t) { return t.tactic; }),
                    datasets: [{
                        data: tactics.map(function(t) { return t.count; }),
                        backgroundColor: tactics.map(function(t) {
                            var ratio = t.count / (maxC || 1);
                            if (ratio > 0.7) return COLORS.critical + 'bb';
                            if (ratio > 0.4) return COLORS.high + '99';
                            return COLORS.medium + '77';
                        }),
                        borderRadius: 3,
                        borderWidth: 0,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { display: false }, ticks: { maxRotation: 55, font: { size: 9 } } },
                        y: { grid: { color: COLORS.grid }, beginAtZero: true }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        })
        .catch(function() {});
    }


    // ═══════════════════════════════════════════════════════════════════
    //  6. ENHANCED STAT CARDS
    // ═══════════════════════════════════════════════════════════════════
    function renderEnhancedStats(containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        apiFetch('/api/v1/charts/summary')
        .then(function(d) {
            var html = ''
                + _statCard('🛡️', d.agents_online + '/' + d.agents_total, 'Agents Online', 'var(--accent)', 'bg:rgba(100,210,255,0.1)')
                + _statCard('🔥', d.critical_high_24h, 'Critical/High (24h)', 'var(--crit)', 'bg:rgba(255,69,58,0.1)')
                + _statCard('⚠️', d.suspicious_24h, 'Alerts (24h)', 'var(--med)', 'bg:rgba(255,214,10,0.1)')
                + _statCard('📊', d.avg_risk_score, 'Avg Risk Score', d.avg_risk_score >= 70 ? 'var(--crit)' : d.avg_risk_score >= 40 ? 'var(--med)' : 'var(--low)', 'bg:var(--bg3)')
                + _statCard('🎯', d.top_tactic, 'Top Tactic', 'var(--cyan,#00d4ff)', 'bg:rgba(0,212,255,0.08)', true)
                + _statCard('📋', d.unresolved_alerts, 'Unresolved', 'var(--high)', 'bg:rgba(255,159,10,0.1)');
            el.innerHTML = html;
        })
        .catch(function() {});
    }

    function _statCard(icon, value, label, color, bgStyle, small) {
        return '<div class="stat-card-enhanced cv-animate-in">'
            + '<div class="stat-icon" style="background:' + (bgStyle ? bgStyle.replace('bg:','') : 'var(--bg3)') + '">' + icon + '</div>'
            + '<div class="stat-value" style="color:' + color + ';' + (small ? 'font-size:16px' : '') + '">' + value + '</div>'
            + '<div class="stat-label">' + label + '</div>'
            + '</div>';
    }


    // ═══════════════════════════════════════════════════════════════════
    //  TIME RANGE CONTROLS
    // ═══════════════════════════════════════════════════════════════════
    function setTimeRange(hours) {
        _timeRange = hours;
        // Update active button
        var btns = document.querySelectorAll('.chart-timerange button');
        for (var i = 0; i < btns.length; i++) {
            btns[i].classList.toggle('active', parseInt(btns[i].dataset.hours) === hours);
        }
        refreshAll();
    }

    function refreshAll() {
        renderEnhancedStats('cv-stats-grid');
        renderSeverityDonut('cv-donut-container');
        renderEventTrend('cv-trend-container');
        renderTopHosts('cv-hosts-container');
        renderEventTypes('cv-types-container');
        renderMitreTacticBar('cv-mitre-container');
    }

    // ═══════════════════════════════════════════════════════════════════
    //  INIT — Call this from dashboard page load
    // ═══════════════════════════════════════════════════════════════════
    function init() {
        configureChartDefaults();
        refreshAll();
        // Auto-refresh every 60s
        if (_refreshTimer) clearInterval(_refreshTimer);
        _refreshTimer = setInterval(refreshAll, 60000);
    }

    function destroy() {
        if (_refreshTimer) clearInterval(_refreshTimer);
        Object.keys(_charts).forEach(destroyChart);
    }

    // Public API
    return {
        init: init,
        destroy: destroy,
        refreshAll: refreshAll,
        setTimeRange: setTimeRange,
        renderSeverityDonut: renderSeverityDonut,
        renderEventTrend: renderEventTrend,
        renderTopHosts: renderTopHosts,
        renderEventTypes: renderEventTypes,
        renderMitreTacticBar: renderMitreTacticBar,
        renderEnhancedStats: renderEnhancedStats,
    };
})();
