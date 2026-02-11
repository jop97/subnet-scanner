/**
 * Subnet Scanner v1.1.7 — Frontend Controller
 * Handles WebSocket communication, UI updates, grid/list views, and host detail modals.
 */

(function () {
    'use strict';

    // ── State ───────────────────────────────────────────────────────────────
    const state = {
        socket: null,
        scanning: false,
        scanId: null,
        results: {},           // ip -> result
        currentFilter: 'all',
        currentView: 'grid',
        dataTable: null,
        detailIp: null,
        detailScanId: 0,       // monotonic ID to discard stale detail results
        detailTimeout: null,   // client-side timeout for detail scan
        detailTimeoutSeconds: 180,  // current detail scan timeout setting
        liveUpdate: false,
        liveTimeout: null,
        scanCompleted: false,  // true after first scan is done
        fullScanPending: false, // true when Full Scan button was clicked
        sweepProgress: 0,      // tracks highest sweep % (never goes backward)
    };

    // ── DOM References ──────────────────────────────────────────────────────
    const dom = {
        scanForm:        () => document.getElementById('scanForm'),
        subnetInput:     () => document.getElementById('subnetInput'),
        btnScan:         () => document.getElementById('btnScan'),
        btnStop:         () => document.getElementById('btnStop'),
        btnClear:        () => document.getElementById('btnClear'),
        btnGridView:     () => document.getElementById('btnGridView'),
        btnListView:     () => document.getElementById('btnListView'),
        gridViewCard:    () => document.getElementById('gridViewCard'),
        listViewCard:    () => document.getElementById('listViewCard'),
        ipGrid:          () => document.getElementById('ipGrid'),
        emptyState:      () => document.getElementById('emptyState'),
        resultsTableBody:() => document.getElementById('resultsTableBody'),
        statTotal:       () => document.getElementById('statTotal'),
        statOnline:      () => document.getElementById('statOnline'),
        statOffline:     () => document.getElementById('statOffline'),
        statusText:      () => document.getElementById('statusText'),
        statusCard:      () => document.getElementById('statusCard'),
        progressFill:    () => document.getElementById('progressFill'),
        connectionDot:   () => document.getElementById('connectionDot'),
        connectionText:  () => document.getElementById('connectionText'),
        hostDetailModal: () => document.getElementById('hostDetailModal'),
        hostDetailTitle: () => document.getElementById('hostDetailTitle'),
        hostDetailBody:  () => document.getElementById('hostDetailBody'),
        btnFullScan:     () => document.getElementById('btnFullScan'),
        btnFullScanMain: () => document.getElementById('btnFullScanMain'),
    };

    // ── Well-Known Port → Protocol Map ────────────────────────────────────
    const WELL_KNOWN_PORTS = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
        110: 'POP3', 111: 'RPC', 119: 'NNTP', 123: 'NTP', 135: 'RPC',
        137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
        161: 'SNMP', 162: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 520: 'RIP', 546: 'DHCPv6',
        547: 'DHCPv6', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS',
        995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1434: 'MSSQL',
        1521: 'Oracle', 1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS',
        2181: 'ZooKeeper', 3306: 'MySQL', 3389: 'RDP', 3478: 'STUN',
        5060: 'SIP', 5432: 'PostgreSQL', 5672: 'AMQP', 5900: 'VNC',
        5984: 'CouchDB', 6379: 'Redis', 6443: 'K8s-API', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 8883: 'MQTT-TLS', 8888: 'HTTP-Alt',
        9090: 'Prometheus', 9092: 'Kafka', 9200: 'Elasticsearch',
        9418: 'Git', 11211: 'Memcached', 27017: 'MongoDB',
        5353: 'mDNS', 548: 'AFP', 554: 'RTSP', 873: 'Rsync',
        1194: 'OpenVPN', 1701: 'L2TP', 5222: 'XMPP', 5269: 'XMPP',
        6660: 'IRC', 6667: 'IRC', 6697: 'IRC-TLS',
        8000: 'HTTP-Alt', 8081: 'HTTP-Alt', 8008: 'HTTP-Alt',
        9000: 'HTTP-Alt', 9443: 'HTTPS-Alt',
        50000: 'SAP', 50070: 'HDFS', 27018: 'MongoDB', 27019: 'MongoDB',
    };

    /**
     * Format a port number for display.
     * Well-known ports get their protocol name, others get the raw number.
     * Returns an HTML string with appropriate styling.
     */
    function formatPortTag(port) {
        const num = parseInt(port, 10);
        const proto = WELL_KNOWN_PORTS[num];
        if (proto) {
            return `<span class="port-tag port-tag-known" title="Port ${num}">${proto}</span>`;
        }
        return `<span class="port-tag">${num}</span>`;
    }

    /**
     * Render an array of port numbers as HTML tags.
     * @param {number[]} ports - array of port numbers
     * @param {number} [max=5] - max ports to show
     */
    function renderPortTags(ports, max) {
        max = max || 5;
        let html = ports.slice(0, max).map(p => formatPortTag(p)).join(' ');
        if (ports.length > max) {
            html += ` <span class="text-muted">+${ports.length - max}</span>`;
        }
        return html;
    }

    // ── Settings Defaults & Persistence ────────────────────────────────────
    const SETTINGS_KEY = 'subnetScannerSettings';

    const SETTINGS_DEFAULTS = {
        // Scan Profile
        profile:            'normal',
        // Quick Sweep
        pingTimeout:        1000,
        threads:            50,
        sweepPingCount:     1,
        // Full Scan (Table)
        nmapTopPorts:       '20',
        nmapTiming:         'T4',
        // Detail Modal
        detailTopPorts:     '2500',
        detailTimeout:      180,
        // Deep Probes
        deepTimeout:        5,
        ssdpTimeout:        4,
        deepHttp:           true,
        deepSsl:            false,
        deepBanners:        false,
        deepSsdp:           false,
        deepMacVendor:      true,
        // Display
        autoScroll:         true,
        showOffline:        true,
        animations:         true,
        // Notifications
        toasts:             true,
        sounds:             false,
        // Live Update
        liveInterval:       '60',
        livePingCount:      2,
    };

    // Profile presets
    const PROFILES = {
        fast: {
            pingTimeout:        500,
            threads:            100,
            sweepPingCount:     1,
            nmapTopPorts:       '20',
            nmapTiming:         'T5',
            detailTopPorts:     '1000',
            detailTimeout:      120,
            deepTimeout:        3,
            ssdpTimeout:        2,
            description:        'Fastest scanning — may miss slow hosts or ports.',
        },
        normal: {
            pingTimeout:        1000,
            threads:            50,
            sweepPingCount:     1,
            nmapTopPorts:       '20',
            nmapTiming:         'T4',
            detailTopPorts:     '2500',
            detailTimeout:      180,
            deepTimeout:        5,
            ssdpTimeout:        4,
            description:        'Balanced speed and coverage for typical networks.',
        },
        thorough: {
            pingTimeout:        2000,
            threads:            25,
            sweepPingCount:     2,
            nmapTopPorts:       '100',
            nmapTiming:         'T3',
            detailTopPorts:     '5000',
            detailTimeout:      300,
            deepTimeout:        8,
            ssdpTimeout:        6,
            description:        'Slow but thorough — best for unreliable networks.',
        },
    };

    /** Read settings from localStorage or return defaults. */
    function loadSettings() {
        try {
            const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY));
            return saved ? Object.assign({}, SETTINGS_DEFAULTS, saved) : Object.assign({}, SETTINGS_DEFAULTS);
        } catch (e) {
            return Object.assign({}, SETTINGS_DEFAULTS);
        }
    }

    /** Write current UI values to localStorage. */
    function saveSettings() {
        const s = readSettingsFromUI();
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
    }

    /** Gather all setting values from the DOM inputs. */
    function readSettingsFromUI() {
        const activeProfile = document.querySelector('.profile-btn.active');
        return {
            profile:            activeProfile ? activeProfile.dataset.profile : 'normal',
            pingTimeout:        parseInt(document.getElementById('settingTimeout').value, 10) || SETTINGS_DEFAULTS.pingTimeout,
            threads:            parseInt(document.getElementById('settingThreads').value, 10) || SETTINGS_DEFAULTS.threads,
            sweepPingCount:     parseInt(document.getElementById('settingSweepPingCount').value, 10) || SETTINGS_DEFAULTS.sweepPingCount,
            nmapTopPorts:       document.getElementById('settingNmapTopPorts').value,
            nmapTiming:         document.getElementById('settingNmapTiming').value,
            detailTopPorts:     document.getElementById('settingDetailTopPorts').value,
            detailTimeout:      parseInt(document.getElementById('settingDetailTimeout').value, 10) || SETTINGS_DEFAULTS.detailTimeout,
            deepTimeout:        parseInt(document.getElementById('settingDeepTimeout').value, 10) || SETTINGS_DEFAULTS.deepTimeout,
            ssdpTimeout:        parseInt(document.getElementById('settingSsdpTimeout').value, 10) || SETTINGS_DEFAULTS.ssdpTimeout,
            deepHttp:           document.getElementById('settingDeepHttp').checked,
            deepSsl:            document.getElementById('settingDeepSsl').checked,
            deepBanners:        document.getElementById('settingDeepBanners').checked,
            deepSsdp:           document.getElementById('settingDeepSsdp').checked,
            deepMacVendor:      document.getElementById('settingDeepMacVendor').checked,
            autoScroll:         document.getElementById('settingAutoScroll').checked,
            showOffline:        document.getElementById('settingShowOffline').checked,
            animations:         document.getElementById('settingAnimations').checked,
            toasts:             document.getElementById('settingToasts').checked,
            sounds:             document.getElementById('settingSounds').checked,
            liveInterval:       document.getElementById('settingLiveInterval').value,
            livePingCount:      parseInt(document.getElementById('settingLivePingCount').value, 10) || SETTINGS_DEFAULTS.livePingCount,
        };
    }

    /** Apply a settings object to all DOM inputs. */
    function applySettingsToUI(s) {
        // Profile buttons
        document.querySelectorAll('.profile-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.profile === s.profile);
        });
        updateProfileDescription(s.profile);

        document.getElementById('settingTimeout').value         = s.pingTimeout;
        document.getElementById('settingThreads').value         = s.threads;
        document.getElementById('settingSweepPingCount').value  = s.sweepPingCount;
        document.getElementById('settingNmapTopPorts').value    = s.nmapTopPorts;
        document.getElementById('settingNmapTiming').value      = s.nmapTiming;
        document.getElementById('settingDetailTopPorts').value  = s.detailTopPorts;
        document.getElementById('settingDetailTimeout').value   = s.detailTimeout;
        document.getElementById('settingDeepTimeout').value     = s.deepTimeout;
        document.getElementById('settingSsdpTimeout').value     = s.ssdpTimeout;
        document.getElementById('settingDeepHttp').checked      = s.deepHttp;
        document.getElementById('settingDeepSsl').checked       = s.deepSsl;
        document.getElementById('settingDeepBanners').checked   = s.deepBanners;
        document.getElementById('settingDeepSsdp').checked      = s.deepSsdp;
        document.getElementById('settingDeepMacVendor').checked = s.deepMacVendor;
        document.getElementById('settingAutoScroll').checked    = s.autoScroll;
        document.getElementById('settingShowOffline').checked   = s.showOffline;
        document.getElementById('settingAnimations').checked    = s.animations;
        document.getElementById('settingToasts').checked        = s.toasts;
        document.getElementById('settingSounds').checked        = s.sounds;
        document.getElementById('settingLiveInterval').value    = s.liveInterval;
        document.getElementById('settingLivePingCount').value   = s.livePingCount;

        // Apply display effects immediately
        applyDisplaySettings(s);
    }

    /** Update profile description text. */
    function updateProfileDescription(profileName) {
        const desc = document.getElementById('profileDescription');
        if (desc && PROFILES[profileName]) {
            desc.textContent = PROFILES[profileName].description;
        }
    }

    /** Apply a profile preset to the UI. */
    function applyProfile(profileName) {
        const preset = PROFILES[profileName];
        if (!preset) return;

        // Update profile buttons
        document.querySelectorAll('.profile-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.profile === profileName);
        });
        updateProfileDescription(profileName);

        // Apply preset values
        document.getElementById('settingTimeout').value         = preset.pingTimeout;
        document.getElementById('settingThreads').value         = preset.threads;
        document.getElementById('settingSweepPingCount').value  = preset.sweepPingCount;
        document.getElementById('settingNmapTopPorts').value    = preset.nmapTopPorts;
        document.getElementById('settingNmapTiming').value      = preset.nmapTiming;
        document.getElementById('settingDetailTopPorts').value  = preset.detailTopPorts;
        document.getElementById('settingDetailTimeout').value   = preset.detailTimeout;
        document.getElementById('settingDeepTimeout').value     = preset.deepTimeout;
        document.getElementById('settingSsdpTimeout').value     = preset.ssdpTimeout;

        saveSettings();
    }

    /** Build nmap arguments string for batch full scan. */
    function buildNmapArgs(s) {
        return `-sV --top-ports ${s.nmapTopPorts} ${s.nmapTiming}`;
    }

    /** Apply display-related settings (animations, showOffline). */
    function applyDisplaySettings(s) {
        document.body.classList.toggle('no-animations', !s.animations);
    }

    /** Get current settings object (from UI). */
    function getSettings() {
        return readSettingsFromUI();
    }

    // ── Initialize ──────────────────────────────────────────────────────────
    function init() {
        applySettingsToUI(loadSettings());
        connectSocket();
        bindEvents();
        // Disable live update toggle until first scan completes
        setLiveUpdateEnabled(false);
    }

    // ── WebSocket ───────────────────────────────────────────────────────────
    function connectSocket() {
        state.socket = io();

        state.socket.on('connect', () => {
            setConnectionStatus(true);
        });

        state.socket.on('disconnect', () => {
            setConnectionStatus(false);
        });

        state.socket.on('connected', (data) => {
            console.log('Server:', data.status);
        });

        state.socket.on('scan_started', (data) => {
            console.log('Scan started:', data.subnet);
            showToast('Scan started for ' + data.subnet, 'info');
            state.sweepProgress = 0;
            setStatus('Sweeping...', 'scanning');
            dom.progressFill().style.width = '0%';
        });

        state.socket.on('host_result', (data) => {
            handleHostResult(data);
        });

        state.socket.on('scan_complete', (data) => {
            handleScanComplete(data);
        });

        state.socket.on('scan_error', (data) => {
            handleScanError(data);
        });

        state.socket.on('scan_stopped', () => {
            setScanningState(false);
            setStatus('Stopped', 'idle');
            dom.progressFill().style.width = '0%';
            showToast('Scan stopped', 'warning');
        });

        state.socket.on('host_detail_scanning', (data) => {
            showDetailLoading(data.ip);
        });

        state.socket.on('host_detail_progress', (data) => {
            if (data.ip !== state.detailIp) return;
            // Reset client-side timeout on any progress event
            resetDetailTimeout();
            updateDetailProgress(data);
        });

        state.socket.on('host_detail_result', (data) => {
            clearDetailTimeout();
            if (data.ip !== state.detailIp) return;  // Stale result
            renderHostDetail(data);
        });

        state.socket.on('host_detail_error', (data) => {
            clearDetailTimeout();
            if (data.ip && data.ip !== state.detailIp) return;  // Stale error
            showDetailError(data.error);
        });

        state.socket.on('live_update_result', (data) => {
            handleLiveUpdateResult(data);
        });

        state.socket.on('live_update_progress', (data) => {
            if (state.liveUpdate) {
                setStatus('Pinging ' + data.done + '/' + data.total, 'live');
                dom.progressFill().style.width = data.progress + '%';
            }
        });

        state.socket.on('live_update_complete', () => {
            if (state.liveUpdate) {
                const interval = (parseInt(document.getElementById('settingLiveInterval').value, 10) || 60) * 1000;
                setStatus('Live • Next in ' + Math.round(interval / 1000) + 's', 'live');
                dom.progressFill().style.width = '100%';
                setTimeout(() => { dom.progressFill().style.width = '0%'; }, 1500);
                // Schedule next round after the configured delay
                state.liveTimeout = setTimeout(() => {
                    if (state.liveUpdate) runLiveUpdate();
                }, interval);
            }
        });

        // Batch nmap scan events
        state.socket.on('batch_nmap_result', (data) => {
            handleBatchNmapResult(data);
        });

        state.socket.on('batch_nmap_progress', (data) => {
            setStatus('Nmap ' + data.done + '/' + data.total, 'scanning');
            dom.progressFill().style.width = data.progress + '%';
        });

        state.socket.on('batch_nmap_complete', () => {
            state.scanning = false;
            const btn = dom.btnFullScanMain();
            btn.innerHTML = '<i class="fas fa-crosshairs mr-2"></i>Full Scan';
            btn.disabled = false;
            setStatus('Done ✔', 'done');
            dom.progressFill().style.width = '100%';
            setTimeout(() => { dom.progressFill().style.width = '0%'; }, 1500);
            showToast('Nmap scan complete — all hosts scanned', 'success');
            playScanCompleteSound();
            setScanningState(false);
            setLiveUpdateEnabled(true);
            initDataTable();
        });

        // Batch full scan (nmap + deep probes) events
        state.socket.on('batch_full_scan_result', (data) => {
            handleBatchFullScanResult(data);
        });

        state.socket.on('batch_full_scan_progress', (data) => {
            if (data.done === 0 && data.phase) {
                setStatus(data.phase, 'scanning');
            } else {
                setStatus('Deep Scan ' + data.done + '/' + data.total, 'scanning');
            }
            dom.progressFill().style.width = data.progress + '%';
        });

        state.socket.on('batch_full_scan_complete', () => {
            state.scanning = false;
            const btn = dom.btnFullScanMain();
            btn.innerHTML = '<i class="fas fa-crosshairs mr-2"></i>Full Scan';
            btn.disabled = false;
            setScanningState(false);
            setStatus('Done ✔', 'done');
            dom.progressFill().style.width = '100%';
            setTimeout(() => { dom.progressFill().style.width = '0%'; }, 1500);
            showToast('Full scan complete — all hosts deep-scanned', 'success');
            playScanCompleteSound();
            setLiveUpdateEnabled(true);
            initDataTable();
        });
    }

    function setConnectionStatus(connected) {
        const dot = dom.connectionDot();
        const text = dom.connectionText();
        if (connected) {
            dot.className = 'conn-dot connected';
            text.textContent = 'Connected';
        } else {
            dot.className = 'conn-dot disconnected';
            text.textContent = 'Disconnected';
        }
    }

    // ── Event Binding ───────────────────────────────────────────────────────
    function bindEvents() {
        // Scan form
        dom.scanForm().addEventListener('submit', (e) => {
            e.preventDefault();
            startScan();
        });

        // Stop button
        dom.btnStop().addEventListener('click', stopScan);

        // Clear button
        dom.btnClear().addEventListener('click', clearResults);

        // View toggle
        dom.btnGridView().addEventListener('click', () => switchView('grid'));
        dom.btnListView().addEventListener('click', () => switchView('list'));

        // Filter buttons
        document.querySelectorAll('.btn-filter').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                state.currentFilter = e.target.dataset.filter;
                applyFilter();
            });
        });

        // Full scan button in modal
        dom.btnFullScan().addEventListener('click', () => {
            if (state.detailIp) {
                requestHostDetail(state.detailIp, 'full');
            }
        });

        // Full Scan button (next to Start Scan)
        dom.btnFullScanMain().addEventListener('click', startFullScan);

        // Clear detail timeout when modal is closed
        $('#hostDetailModal').on('hidden.bs.modal', function () {
            clearDetailTimeout();
        });

        // Keyboard shortcut
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.ctrlKey) {
                e.preventDefault();
                startScan();
            }
            if (e.key === 'Escape' && state.scanning) {
                stopScan();
            }
        });

        // Live update toggle
        document.getElementById('settingLiveUpdate').addEventListener('change', (e) => {
            state.liveUpdate = e.target.checked;
            if (state.liveUpdate) {
                startLiveUpdate();
            } else {
                stopLiveUpdate();
            }
        });

        // Settings modal — auto-save on every change
        const settingsModal = document.getElementById('settingsModal');
        if (settingsModal) {
            settingsModal.querySelectorAll('input, select').forEach(el => {
                el.addEventListener('change', () => {
                    saveSettings();
                    applyDisplaySettings(readSettingsFromUI());
                });
            });

            // Profile buttons
            settingsModal.querySelectorAll('.profile-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    applyProfile(btn.dataset.profile);
                });
            });
        }

        // Settings reset button
        const btnReset = document.getElementById('btnResetSettings');
        if (btnReset) {
            btnReset.addEventListener('click', () => {
                applySettingsToUI(SETTINGS_DEFAULTS);
                saveSettings();
                showToast('Settings restored to defaults', 'info');
            });
        }
    }

    // ── Scan Control ────────────────────────────────────────────────────────
    function startScan() {
        const subnet = dom.subnetInput().value.trim();
        if (!subnet) {
            dom.subnetInput().focus();
            dom.subnetInput().classList.add('is-invalid');
            setTimeout(() => dom.subnetInput().classList.remove('is-invalid'), 2000);
            return;
        }

        // Validate CIDR pattern
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
        if (!cidrRegex.test(subnet)) {
            showToast('Invalid subnet format. Use CIDR notation (e.g. 192.168.1.0/24)', 'error');
            return;
        }

        clearResults();
        setScanningState(true);

        // Stop live update during scan
        stopLiveUpdate();
        document.getElementById('settingLiveUpdate').checked = false;
        state.liveUpdate = false;
        setLiveUpdateEnabled(false);

        state.scanId = subnet;

        const s = getSettings();
        state.socket.emit('start_scan', {
            subnet: subnet,
            scan_id: subnet,
            ping_timeout: s.pingTimeout,
            threads: s.threads,
        });
    }

    function stopScan() {
        if (state.scanId) {
            state.socket.emit('stop_scan', { scan_id: state.scanId });
        }
        // Also stop any batch scan in progress
        state.socket.emit('stop_batch_scan');
        state.fullScanPending = false;
        setScanningState(false);

        // Reset Full Scan button
        const btnFull = dom.btnFullScanMain();
        btnFull.innerHTML = '<i class="fas fa-crosshairs mr-2"></i>Full Scan';
        btnFull.disabled = false;
    }

    function setScanningState(scanning) {
        state.scanning = scanning;
        const btnScan = dom.btnScan();
        const btnStop = dom.btnStop();
        const btnFull = dom.btnFullScanMain();

        if (scanning) {
            btnScan.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Sweeping...';
            btnScan.classList.add('scanning');
            btnScan.disabled = true;
            btnFull.disabled = true;
            btnStop.classList.remove('d-none');
            dom.subnetInput().disabled = true;
        } else {
            btnScan.innerHTML = '<i class="fas fa-bolt mr-2"></i>Quick Sweep';
            btnScan.classList.remove('scanning');
            btnScan.disabled = false;
            btnFull.disabled = false;
            btnStop.classList.add('d-none');
            dom.subnetInput().disabled = false;
        }
    }

    function clearResults() {
        state.results = {};
        dom.ipGrid().innerHTML = `
            <div class="empty-state" id="emptyState">
                <div class="empty-icon"><i class="fas fa-satellite-dish"></i></div>
                <h4>Ready to Scan</h4>
                <p>Enter a subnet in CIDR notation and hit <strong>Quick Sweep</strong> to discover hosts on your network.</p>
            </div>`;
        dom.resultsTableBody().innerHTML = '';
        updateStats(0, 0, 0, 0);
        setStatus('Idle', 'idle');
        dom.progressFill().style.width = '0%';

        // Reset Full Scan button
        const btnFull = dom.btnFullScanMain();
        btnFull.innerHTML = '<i class="fas fa-crosshairs mr-2"></i>Full Scan';
        btnFull.disabled = false;

        if (state.dataTable) {
            try { state.dataTable.destroy(); } catch (e) { /* ignore */ }
            state.dataTable = null;
        }
    }

    // ── Handle Results ──────────────────────────────────────────────────────
    function handleHostResult(data) {
        state.results[data.ip] = data;

        // Remove empty state
        const emptyState = dom.emptyState();
        if (emptyState) emptyState.remove();

        // Update grid
        addOrUpdateGridBlock(data);

        // Update list
        addOrUpdateTableRow(data);

        // Auto-scroll to latest result
        if (document.getElementById('settingAutoScroll').checked && data.alive) {
            const block = document.getElementById('block-' + data.ip.replace(/\./g, '-'));
            if (block) block.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        // Update stats — progress only goes forward
        const all = Object.values(state.results);
        const online = all.filter(r => r.alive).length;
        const offline = all.filter(r => !r.alive).length;
        animateNumber(dom.statTotal(), data.total || all.length);
        animateNumber(dom.statOnline(), online);
        animateNumber(dom.statOffline(), offline);

        // Monotonic progress: never decrease
        const pct = Math.round(data.progress || 0);
        if (pct > state.sweepProgress) state.sweepProgress = pct;
        setStatus('Sweep ' + state.sweepProgress + '%', 'scanning');
        dom.progressFill().style.width = state.sweepProgress + '%';
    }

    function handleScanComplete(data) {
        state.scanCompleted = true;
        state.sweepProgress = 100;
        animateNumber(dom.statTotal(), data.total);
        animateNumber(dom.statOnline(), data.alive);
        animateNumber(dom.statOffline(), data.dead);

        if (state.fullScanPending) {
            // Full Scan was clicked — auto-start deep scan phase
            state.fullScanPending = false;
            setStatus('Sweep done — starting deep scan...', 'scanning');
            dom.progressFill().style.width = '100%';
            showToast(`Ping complete — ${data.alive} online. Starting deep scan...`, 'info');
            startBatchFullScan();
            return;
        }

        setScanningState(false);
        setStatus('Done ✔', 'done');
        dom.progressFill().style.width = '100%';
        setTimeout(() => { dom.progressFill().style.width = '0%'; }, 1500);
        showToast(`Scan complete — ${data.alive} hosts online, ${data.dead} offline`, 'success');
        playScanCompleteSound();

        // Enable live update toggle now that a scan has completed
        setLiveUpdateEnabled(true);

        // Initialize or refresh DataTable
        initDataTable();
    }

    function handleScanError(data) {
        setScanningState(false);
        setStatus('Error', 'error');
        dom.progressFill().style.width = '0%';
        showToast('Error: ' + data.error, 'error');
    }

    // ── Grid View ───────────────────────────────────────────────────────────
    function addOrUpdateGridBlock(data) {
        const grid = dom.ipGrid();
        let block = document.getElementById('block-' + data.ip.replace(/\./g, '-'));

        if (!block) {
            block = document.createElement('div');
            block.id = 'block-' + data.ip.replace(/\./g, '-');
            block.className = 'ip-block';
            block.style.animationDelay = (Math.random() * 0.2) + 's';

            // Insert in sorted position
            const existingBlocks = grid.querySelectorAll('.ip-block');
            let inserted = false;
            for (const existing of existingBlocks) {
                if (compareIPs(data.ip, existing.dataset.ip) < 0) {
                    grid.insertBefore(block, existing);
                    inserted = true;
                    break;
                }
            }
            if (!inserted) grid.appendChild(block);
        }

        block.dataset.ip = data.ip;
        block.dataset.alive = data.alive ? 'true' : 'false';
        block.className = `ip-block ${data.alive ? 'online' : 'offline'}`;

        block.innerHTML = `
            <span class="ip-status-dot"></span>
            <div class="ip-addr">${formatIP(data.ip)}</div>
        `;

        block.onclick = () => openHostDetail(data.ip);

        // Apply filter
        applyFilterToBlock(block);
    }

    function formatIP(ip) {
        // Show only last two octets for cleaner grid
        const parts = ip.split('.');
        return parts[2] + '.' + parts[3];
    }

    function compareIPs(a, b) {
        const pa = a.split('.').map(Number);
        const pb = b.split('.').map(Number);
        for (let i = 0; i < 4; i++) {
            if (pa[i] !== pb[i]) return pa[i] - pb[i];
        }
        return 0;
    }

    // ── List View ───────────────────────────────────────────────────────────
    function addOrUpdateTableRow(data) {
        const tbody = dom.resultsTableBody();
        let row = document.getElementById('row-' + data.ip.replace(/\./g, '-'));

        if (!row) {
            row = document.createElement('tr');
            row.id = 'row-' + data.ip.replace(/\./g, '-');
            tbody.appendChild(row);
        }

        row.dataset.alive = data.alive ? 'true' : 'false';
        row.className = data.alive ? '' : 'text-muted';

        const statusBadge = data.alive
            ? '<span class="status-badge online"><span class="dot"></span>Online</span>'
            : '<span class="status-badge offline"><span class="dot"></span>Offline</span>';

        const responseTime = data.response_time !== null
            ? `<span class="text-cyan font-weight-bold">${data.response_time} ms</span>`
            : '<span class="text-muted">—</span>';

        // TTL-based OS guess shown immediately during ping sweep
        const osGuess = data.ttl_os_guess
            ? `<span class="text-muted" title="Guessed from TTL=${data.ttl}">${data.ttl_os_guess} <i class="fas fa-question-circle" style="font-size:0.65rem;opacity:0.5"></i></span>`
            : '<span class="text-muted">—</span>';

        row.innerHTML = `
            <td>${statusBadge}</td>
            <td><strong>${data.ip}</strong></td>
            <td>${data.hostname || '<span class="text-muted">—</span>'}</td>
            <td>${responseTime}</td>
            <td><span class="text-muted" id="ports-${data.ip.replace(/\./g, '-')}">—</span></td>
            <td id="os-${data.ip.replace(/\./g, '-')}">${osGuess}</td>
            <td><span class="text-muted" id="mac-${data.ip.replace(/\./g, '-')}">—</span></td>
            <td>
                <button class="btn btn-detail" onclick="SubnetScanner.openHostDetail('${data.ip}')">
                    <i class="fas fa-search mr-1"></i>Details
                </button>
            </td>
        `;

        // Apply filter
        applyFilterToRow(row);
    }

    function initDataTable() {
        // Destroy existing instance if present
        if (state.dataTable) {
            try { state.dataTable.destroy(); } catch (e) { /* ignore */ }
            state.dataTable = null;
        }

        // Custom IP address sorting (numeric octets)
        if ($.fn.dataTable && !$.fn.dataTable.ext.type.order['ip-address-pre']) {
            $.fn.dataTable.ext.type.order['ip-address-pre'] = function (d) {
                const text = $('<span>').html(d).text();
                const m = text.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
                if (!m) return 0;
                return ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]);
            };
        }

        const rowCount = document.querySelectorAll('#resultsTable tbody tr').length;
        if (rowCount > 0) {
            state.dataTable = $('#resultsTable').DataTable({
                paging: false,
                ordering: true,
                searching: true,
                responsive: true,
                order: [[1, 'asc']],
                columnDefs: [
                    { type: 'ip-address', targets: 1 },
                ],
                dom: '<"row"<"col-sm-12"f>>rt',
                language: {
                    search: '<i class="fas fa-search mr-1"></i>',
                    emptyTable: 'No results yet — start a scan',
                },
            });
        }
    }

    // ── Filters ─────────────────────────────────────────────────────────────
    function applyFilter() {
        // Grid
        document.querySelectorAll('.ip-block').forEach(block => applyFilterToBlock(block));
        // Table
        document.querySelectorAll('#resultsTableBody tr').forEach(row => applyFilterToRow(row));
    }

    function applyFilterToBlock(block) {
        const filter = state.currentFilter;
        const showOffline = document.getElementById('settingShowOffline').checked;
        const isAlive = block.dataset.alive === 'true';

        if (!isAlive && !showOffline && filter !== 'offline') {
            block.style.display = 'none';
            return;
        }

        if (filter === 'all') {
            block.style.display = '';
        } else if (filter === 'online') {
            block.style.display = isAlive ? '' : 'none';
        } else if (filter === 'offline') {
            block.style.display = !isAlive ? '' : 'none';
        }
    }

    function applyFilterToRow(row) {
        const filter = state.currentFilter;
        if (filter === 'all') {
            row.style.display = '';
        } else if (filter === 'online') {
            row.style.display = row.dataset.alive === 'true' ? '' : 'none';
        } else if (filter === 'offline') {
            row.style.display = row.dataset.alive === 'false' ? '' : 'none';
        }
    }

    // ── View Switching ──────────────────────────────────────────────────────
    function switchView(view) {
        state.currentView = view;
        dom.btnGridView().classList.toggle('active', view === 'grid');
        dom.btnListView().classList.toggle('active', view === 'list');
        if (view === 'grid') {
            dom.gridViewCard().classList.remove('d-none');
            dom.listViewCard().classList.add('d-none');
        } else {
            dom.gridViewCard().classList.add('d-none');
            dom.listViewCard().classList.remove('d-none');
            initDataTable();
        }
    }

    // ── Stats ───────────────────────────────────────────────────────────────
    function updateStats(total, online, offline, progress) {
        animateNumber(dom.statTotal(), total);
        animateNumber(dom.statOnline(), online);
        animateNumber(dom.statOffline(), offline);
        if (progress !== undefined && progress !== null) {
            dom.progressFill().style.width = progress + '%';
        }
    }

    function setStatus(text, type) {
        // type: 'idle' | 'scanning' | 'live' | 'done' | 'error'
        const el = dom.statusText();
        const card = dom.statusCard();
        el.textContent = text;
        card.className = 'stat-card stat-status';
        if (type) card.classList.add('stat-status-' + type);
    }

    function animateNumber(el, target) {
        const current = parseInt(el.textContent) || 0;
        if (current === target) return;

        const diff = target - current;
        const steps = Math.min(Math.abs(diff), 15);
        const stepSize = diff / steps;
        let step = 0;

        const interval = setInterval(() => {
            step++;
            if (step >= steps) {
                el.textContent = target;
                clearInterval(interval);
            } else {
                el.textContent = Math.round(current + stepSize * step);
            }
        }, 30);
    }

    // ── Host Detail Modal ───────────────────────────────────────────────────
    function openHostDetail(ip) {
        state.detailIp = ip;
        state.detailScanId++;
        dom.hostDetailTitle().innerHTML = `<i class="fas fa-info-circle mr-2"></i>${ip}`;

        // Show basic info from cached results first
        const cached = state.results[ip];
        if (cached) {
            renderQuickInfo(cached);
        }

        $('#hostDetailModal').modal('show');

        // Always request a full nmap scan for detail modal
        requestHostDetail(ip, 'full');
    }

    function requestHostDetail(ip, scanType) {
        showDetailLoading(ip);
        clearDetailTimeout();
        const s = getSettings();
        const hostTimeout = s.detailTimeout || 180;
        state.detailTimeoutSeconds = hostTimeout;  // Store for progress resets
        state.socket.emit('scan_host_detail', {
            ip: ip,
            scan_type: scanType,
            top_ports: parseInt(s.detailTopPorts, 10) || 2500,
            host_timeout: hostTimeout,
            deep_timeout: s.deepTimeout,
            ssdp_timeout: s.ssdpTimeout,
            deep_http: s.deepHttp,
            deep_ssl: s.deepSsl,
            deep_banners: s.deepBanners,
            deep_ssdp: s.deepSsdp,
            deep_mac_vendor: s.deepMacVendor,
        });
        // Start client-side timeout based on settings
        resetDetailTimeout();
    }

    /** Reset the client-side detail scan timeout (called on every progress event). */
    function resetDetailTimeout() {
        clearDetailTimeout();
        const seconds = state.detailTimeoutSeconds || 180;
        const ms = (seconds + 60) * 1000;  // Add 60s buffer beyond host-timeout
        state.detailTimeout = setTimeout(() => {
            // Only fire if we're still showing the loading state
            const body = dom.hostDetailBody();
            if (body && body.querySelector('.detail-loading-container')) {
                showDetailError('Scan timed out — the server stopped responding. Try again or scan a different host.');
            }
        }, ms);
    }

    /** Clear the client-side detail scan timeout. */
    function clearDetailTimeout() {
        if (state.detailTimeout) {
            clearTimeout(state.detailTimeout);
            state.detailTimeout = null;
        }
    }

    /** Get detail phase labels (port count from settings). */
    function getDetailPhases() {
        const s = getSettings();
        const topPorts = s.detailTopPorts || 2500;
        return [
            { icon: 'fa-network-wired', label: 'DNS, NetBIOS & WHOIS' },
            { icon: 'fa-search',        label: `Nmap scan (top ${topPorts} ports)` },
            { icon: 'fa-shield-alt',    label: 'HTTP, SSL & banner probes' }
        ];
    }

    function showDetailLoading(ip) {
        const detailPhases = getDetailPhases();
        const stepsHtml = detailPhases.map((p, i) => `
            <div class="detail-progress-step" id="detail-step-${i}" data-step="${i}">
                <div class="detail-step-icon pending">
                    <i class="fas ${p.icon}"></i>
                </div>
                <div class="detail-step-info">
                    <div class="detail-step-label">${p.label}</div>
                    <div class="detail-step-status text-muted">Waiting...</div>
                </div>
            </div>`).join('');

        dom.hostDetailBody().innerHTML = `
            <div class="detail-loading-container">
                <div class="detail-loading-header">
                    <div class="scanner-animation" style="margin: 0 auto;"></div>
                    <p class="mt-3 mb-1">
                        <i class="fas fa-satellite-dish fa-spin mr-1 text-cyan"></i>
                        Scanning <strong class="text-cyan">${ip}</strong>
                    </p>
                    <p class="text-muted detail-loading-subtitle" id="detail-progress-text">Initializing...</p>
                </div>
                <div class="detail-progress-steps">
                    ${stepsHtml}
                </div>
                <div class="detail-progress-bar-wrap">
                    <div class="detail-progress-bar" id="detail-progress-fill" style="width: 0%"></div>
                </div>
            </div>`;
    }

    function updateDetailProgress(data) {
        if (data.ip !== state.detailIp) return;
        const phase = data.phase;       // 1-based
        const total = data.total || 3;
        const label = data.label || '';

        // Update header subtitle
        const subtitle = document.getElementById('detail-progress-text');
        if (subtitle) subtitle.textContent = label;

        // Update progress bar — interpolate within phase when sub_progress present
        const fill = document.getElementById('detail-progress-fill');
        if (fill) {
            let pct = ((phase - 1) / total) * 100;
            if (data.sub_progress !== undefined) {
                pct += (data.sub_progress / 100) * (100 / total);
            }
            fill.style.width = Math.round(pct) + '%';
        }

        // Mark previous steps as complete
        for (let i = 0; i < phase - 1; i++) {
            const step = document.getElementById('detail-step-' + i);
            if (step) {
                step.querySelector('.detail-step-icon').className = 'detail-step-icon completed';
                step.querySelector('.detail-step-icon i').className = 'fas fa-check';
                step.querySelector('.detail-step-status').innerHTML = '<span class="text-green">Done</span>';
            }
        }

        // Mark current step as active with optional port progress
        const current = document.getElementById('detail-step-' + (phase - 1));
        if (current) {
            current.querySelector('.detail-step-icon').className = 'detail-step-icon active';
            let statusHtml;
            if (data.ports_done !== undefined) {
                statusHtml = '<span class="text-cyan"><i class="fas fa-circle-notch fa-spin mr-1"></i>~' + data.ports_done + '/' + data.ports_total + ' ports</span>';
            } else {
                statusHtml = '<span class="text-cyan"><i class="fas fa-circle-notch fa-spin mr-1"></i>In progress...</span>';
            }
            current.querySelector('.detail-step-status').innerHTML = statusHtml;
        }
    }

    function showDetailError(error) {
        dom.hostDetailBody().innerHTML = `
            <div class="text-center py-5">
                <i class="fas fa-exclamation-triangle fa-3x text-orange mb-3"></i>
                <p class="text-muted">${error}</p>
            </div>`;
    }

    function renderQuickInfo(data) {
        const detailPhases = getDetailPhases();
        const stepsHtml = detailPhases.map((p, i) => `
            <div class="detail-progress-step" id="detail-step-${i}" data-step="${i}">
                <div class="detail-step-icon pending">
                    <i class="fas ${p.icon}"></i>
                </div>
                <div class="detail-step-info">
                    <div class="detail-step-label">${p.label}</div>
                    <div class="detail-step-status text-muted">Waiting...</div>
                </div>
            </div>`).join('');

        dom.hostDetailBody().innerHTML = `
            <div class="detail-section">
                <div class="detail-section-title">
                    <i class="fas fa-info-circle"></i> Basic Information
                </div>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="label">IP Address</div>
                        <div class="value highlight">${data.ip}</div>
                    </div>
                    <div class="detail-item">
                        <div class="label">Status</div>
                        <div class="value">${data.alive
                            ? '<span class="text-green"><i class="fas fa-check-circle mr-1"></i>Online</span>'
                            : '<span class="text-red"><i class="fas fa-times-circle mr-1"></i>Offline</span>'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="label">Hostname</div>
                        <div class="value">${data.hostname || '<span class="text-muted">Unknown</span>'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="label">Response Time</div>
                        <div class="value">${data.response_time !== null ? data.response_time + ' ms' : '—'}</div>
                    </div>
                </div>
            </div>
            <div class="detail-loading-container" style="padding-top: 0.5rem;">
                <div class="detail-loading-header" style="padding-top: 0;">
                    <p class="mb-1 text-muted detail-loading-subtitle" id="detail-progress-text">Running detailed scan...</p>
                </div>
                <div class="detail-progress-steps">
                    ${stepsHtml}
                </div>
                <div class="detail-progress-bar-wrap">
                    <div class="detail-progress-bar" id="detail-progress-fill" style="width: 0%"></div>
                </div>
            </div>`;
    }

    function formatUptime(seconds) {
        if (!seconds) return null;
        const s = parseInt(seconds, 10);
        if (isNaN(s)) return null;
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        const parts = [];
        if (d > 0) parts.push(d + 'd');
        if (h > 0) parts.push(h + 'h');
        if (m > 0) parts.push(m + 'm');
        return parts.length ? parts.join(' ') : '< 1m';
    }

    function renderHttpSection(info, label, icon) {
        if (!info || !info.status_code) return '';
        const portNote = info.port ? ` <span class="text-muted">(port ${info.port})</span>` : '';
        let h = `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-${icon}"></i> ${label}${portNote}</div>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="label">Status Code</div>
                        <div class="value">${info.status_code}</div>
                    </div>`;
        if (info.server) {
            h += `
                    <div class="detail-item">
                        <div class="label">Server</div>
                        <div class="value">${escapeHtml(info.server)}</div>
                    </div>`;
        }
        if (info.powered_by) {
            h += `
                    <div class="detail-item">
                        <div class="label">Powered By</div>
                        <div class="value">${escapeHtml(info.powered_by)}</div>
                    </div>`;
        }
        if (info.title) {
            h += `
                    <div class="detail-item">
                        <div class="label">Page Title</div>
                        <div class="value">${escapeHtml(info.title)}</div>
                    </div>`;
        }
        if (info.content_type) {
            h += `
                    <div class="detail-item">
                        <div class="label">Content-Type</div>
                        <div class="value">${escapeHtml(info.content_type)}</div>
                    </div>`;
        }
        if (info.redirect) {
            h += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">Redirect</div>
                        <div class="value" style="word-break:break-all;">${escapeHtml(info.redirect)}</div>
                    </div>`;
        }
        if (info.headers && Object.keys(info.headers).length > 0) {
            h += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">Response Headers</div>
                        <pre style="color: var(--text-secondary); font-size: 0.75rem; white-space: pre-wrap; margin:0; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-top: 4px;">`;
            for (const [hdr, val] of Object.entries(info.headers)) {
                h += `${escapeHtml(hdr)}: ${escapeHtml(val)}\n`;
            }
            h += `</pre></div>`;
        }
        h += `</div></div>`;
        return h;
    }

    function renderHostDetail(data) {
        // Merge any cached deep scan data for this host
        const cached = state.results[data.ip];
        if (cached && cached.deep) {
            if (!data.http_info && cached.deep.http_info) data.http_info = cached.deep.http_info;
            if (!data.https_info && cached.deep.https_info) data.https_info = cached.deep.https_info;
            if (!data.ssl_info && cached.deep.ssl_info) data.ssl_info = cached.deep.ssl_info;
            if (!data.banners && cached.deep.banners) data.banners = cached.deep.banners;
            if (!data.mac_from_arp && cached.deep.mac_from_arp) data.mac_from_arp = cached.deep.mac_from_arp;
            if (!data.mac_vendor && cached.deep.mac_vendor) data.mac_vendor = cached.deep.mac_vendor;
            if (!data.ssdp_info && cached.deep.ssdp_info) data.ssdp_info = cached.deep.ssdp_info;
        }
        // Merge response_time from cached ping data
        if (cached && cached.response_time !== undefined && data.response_time === undefined) {
            data.response_time = cached.response_time;
        }

        let html = '';

        // ── Basic Information
        html += `
        <div class="detail-section">
            <div class="detail-section-title"><i class="fas fa-info-circle"></i> Basic Information</div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="label">IP Address</div>
                    <div class="value highlight">${data.ip}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Status</div>
                    <div class="value">${data.state === 'up'
                        ? '<span class="text-green"><i class="fas fa-check-circle mr-1"></i>Up</span>'
                        : '<span class="text-red"><i class="fas fa-times-circle mr-1"></i>Down</span>'}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Hostname</div>
                    <div class="value">${data.hostname || data.reverse_dns || '<span class="text-muted">Unknown</span>'}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Response Time</div>
                    <div class="value">${data.response_time != null ? '<span class="text-cyan">' + data.response_time + ' ms</span>' : '<span class="text-muted">—</span>'}</div>
                </div>
                <div class="detail-item">
                    <div class="label">Reverse DNS</div>
                    <div class="value">${data.reverse_dns || '<span class="text-muted">—</span>'}</div>
                </div>`;

        if (data.mac_address || data.mac_from_arp) {
            html += `
                <div class="detail-item">
                    <div class="label">MAC Address</div>
                    <div class="value"><code style="color:var(--text);background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;">${data.mac_address || data.mac_from_arp || '—'}</code></div>
                </div>`;
            // Update list view MAC
            const macEl = document.getElementById('mac-' + data.ip.replace(/\./g, '-'));
            if (macEl) macEl.textContent = data.mac_address || data.mac_from_arp || '—';
        }

        const vendorName = data.mac_vendor || data.vendor;
        if (vendorName) {
            html += `
                <div class="detail-item">
                    <div class="label">Vendor (OUI)</div>
                    <div class="value">${escapeHtml(vendorName)}</div>
                </div>`;
        }

        if (data.netbios_name) {
            html += `
                <div class="detail-item">
                    <div class="label">NetBIOS Name</div>
                    <div class="value">${escapeHtml(data.netbios_name)}</div>
                </div>`;
        }

        if (data.workgroup) {
            html += `
                <div class="detail-item">
                    <div class="label">Workgroup</div>
                    <div class="value">${escapeHtml(data.workgroup)}</div>
                </div>`;
        }

        html += `</div></div>`;

        // ── All Hostnames (nmap)
        if (data.hostnames && data.hostnames.length > 0) {
            const hasNames = data.hostnames.some(h => h.name);
            if (hasNames) {
                html += `
                <div class="detail-section">
                    <div class="detail-section-title"><i class="fas fa-tags"></i> Hostnames</div>
                    <div class="detail-grid">`;
                data.hostnames.forEach(h => {
                    if (h.name) {
                        html += `
                        <div class="detail-item">
                            <div class="label">${escapeHtml(h.type || 'hostname')}</div>
                            <div class="value">${escapeHtml(h.name)}</div>
                        </div>`;
                    }
                });
                html += `</div></div>`;
            }
        }

        // ── SSDP / UPnP Discovery
        if (data.ssdp_info) {
            const ssdp = data.ssdp_info;
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-broadcast-tower"></i> UPnP / SSDP</div>
                <div class="detail-grid">`;
            if (ssdp.server) {
                html += `
                    <div class="detail-item">
                        <div class="label">Server</div>
                        <div class="value">${escapeHtml(ssdp.server)}</div>
                    </div>`;
            }
            if (ssdp.location) {
                html += `
                    <div class="detail-item">
                        <div class="label">Location</div>
                        <div class="value" style="word-break:break-all;">${escapeHtml(ssdp.location)}</div>
                    </div>`;
            }
            if (ssdp.services && ssdp.services.length > 0) {
                html += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">Services (${ssdp.services.length})</div>
                        <div class="value" style="font-size:0.78rem;">${ssdp.services.map(s => escapeHtml(s)).join('<br>')}</div>
                    </div>`;
            }
            html += `</div></div>`;
        }

        // ── DNS Records
        if ((data.dns_names && data.dns_names.length > 0) || (data.ptr_records && data.ptr_records.length > 0)) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-globe"></i> DNS Information</div>
                <div class="detail-grid">`;
            if (data.dns_names && data.dns_names.length) {
                html += `
                    <div class="detail-item">
                        <div class="label">DNS Names</div>
                        <div class="value">${data.dns_names.map(n => escapeHtml(n)).join('<br>')}</div>
                    </div>`;
            }
            if (data.ptr_records && data.ptr_records.length) {
                html += `
                    <div class="detail-item">
                        <div class="label">PTR Records</div>
                        <div class="value">${data.ptr_records.map(p => escapeHtml(p)).join('<br>')}</div>
                    </div>`;
            }
            html += `</div></div>`;
        }

        // ── OS Detection (with OS classes)
        if (data.os_matches && data.os_matches.length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-desktop"></i> OS Detection</div>
                <div class="detail-grid">`;
            data.os_matches.slice(0, 5).forEach(os => {
                html += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">OS Match (${os.accuracy}% accuracy)</div>
                        <div class="value">${escapeHtml(os.name)}</div>`;
                // Show OS classes
                if (os.os_classes && os.os_classes.length > 0) {
                    html += `<div style="margin-top:6px;">`;
                    os.os_classes.forEach(cls => {
                        const parts = [];
                        if (cls.type) parts.push(`<span class="text-muted">Type:</span> ${escapeHtml(cls.type)}`);
                        if (cls.vendor) parts.push(`<span class="text-muted">Vendor:</span> ${escapeHtml(cls.vendor)}`);
                        if (cls.osfamily) parts.push(`<span class="text-muted">Family:</span> ${escapeHtml(cls.osfamily)}`);
                        if (cls.osgen) parts.push(`<span class="text-muted">Gen:</span> ${escapeHtml(cls.osgen)}`);
                        if (cls.accuracy) parts.push(`<span class="text-muted">Acc:</span> ${cls.accuracy}%`);
                        if (parts.length) {
                            html += `<div style="font-size:0.78rem; color: var(--text-secondary); padding: 2px 0;">${parts.join(' &nbsp;·&nbsp; ')}</div>`;
                        }
                        // CPE inside OS class
                        if (cls.cpe && cls.cpe.length > 0) {
                            cls.cpe.forEach(c => {
                                html += `<div style="font-size:0.72rem; color: var(--text-dim); padding-left: 8px;"><i class="fas fa-tag mr-1"></i>${escapeHtml(c)}</div>`;
                            });
                        }
                    });
                    html += `</div>`;
                }
                html += `</div>`;
            });
            html += `</div></div>`;

            // Update list view OS
            const osEl = document.getElementById('os-' + data.ip.replace(/\./g, '-'));
            if (osEl && data.os_matches.length > 0) {
                osEl.innerHTML = `<span title="${escapeHtml(data.os_matches[0].name)}">${truncate(data.os_matches[0].name, 25)}</span>`;
            }
        }

        // ── Open Ports Summary
        if (data.open_ports && data.open_ports.length > 0) {
            // Update list view ports
            const portsEl = document.getElementById('ports-' + data.ip.replace(/\./g, '-'));
            if (portsEl) {
                portsEl.className = '';
                portsEl.innerHTML = renderPortTags(data.open_ports);
            }
        }

        // ── Services / Port Table (with CPE + per-port scripts)
        if (data.services && data.services.length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-plug"></i> Ports & Services (${data.services.length})</div>
                <div class="table-responsive" style="max-height: 500px; overflow-y: auto;">
                    <table class="port-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Proto</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Product</th>
                                <th>Version</th>
                                <th>Extra Info</th>
                            </tr>
                        </thead>
                        <tbody>`;

            data.services.forEach(svc => {
                const stateClass = svc.state === 'open' ? 'port-state-open'
                    : svc.state === 'closed' ? 'port-state-closed'
                    : 'port-state-filtered';
                const knownProto = WELL_KNOWN_PORTS[svc.port];
                const svcDisplay = knownProto || svc.service || '—';

                html += `
                            <tr>
                                <td>${formatPortTag(svc.port)}</td>
                                <td>${svc.protocol}</td>
                                <td><span class="${stateClass}">${svc.state}</span></td>
                                <td>${escapeHtml(svcDisplay)}</td>
                                <td>${svc.product ? escapeHtml(svc.product) : '—'}</td>
                                <td>${svc.version ? escapeHtml(svc.version) : '—'}</td>
                                <td>${svc.extrainfo ? escapeHtml(svc.extrainfo) : '—'}</td>
                            </tr>`;

                // CPE row
                if (svc.cpe) {
                    const cpeList = Array.isArray(svc.cpe) ? svc.cpe : [svc.cpe];
                    const filtered = cpeList.filter(c => c);
                    if (filtered.length > 0) {
                        html += `
                            <tr>
                                <td colspan="7" style="padding: 2px 12px 6px; border-top: none;">
                                    <span style="font-size:0.72rem; color: var(--text-dim);"><i class="fas fa-tag mr-1"></i>CPE: ${filtered.map(c => escapeHtml(c)).join(', ')}</span>
                                </td>
                            </tr>`;
                    }
                }

                // Per-port NSE scripts
                if (svc.scripts && Object.keys(svc.scripts).length > 0) {
                    for (const [sid, sout] of Object.entries(svc.scripts)) {
                        html += `
                            <tr>
                                <td colspan="7" style="padding: 4px 12px 8px; border-top: none;">
                                    <div style="font-size:0.75rem;">
                                        <span class="text-cyan"><i class="fas fa-scroll mr-1"></i>${escapeHtml(sid)}</span>
                                        <pre style="color: var(--text-secondary); font-size: 0.73rem; white-space: pre-wrap; margin: 4px 0 0; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px;">${escapeHtml(sout)}</pre>
                                    </div>
                                </td>
                            </tr>`;
                    }
                }
            });

            html += `</tbody></table></div></div>`;
        }

        // ── HTTP Information (with port number)
        html += renderHttpSection(data.http_info, 'HTTP Information', 'globe');

        // ── HTTPS Information (separate section)
        html += renderHttpSection(data.https_info, 'HTTPS Information', 'lock');

        // ── SSL / TLS Certificate (with port number)
        if (data.ssl_info && (data.ssl_info.ssl_version || data.ssl_info.ssl_subject)) {
            const sslPort = data.ssl_info.port ? ` <span class="text-muted">(port ${data.ssl_info.port})</span>` : '';
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-shield-alt"></i> SSL/TLS Certificate${sslPort}</div>
                <div class="detail-grid">`;
            if (data.ssl_info.ssl_version) {
                html += `
                    <div class="detail-item">
                        <div class="label">Protocol</div>
                        <div class="value">${escapeHtml(data.ssl_info.ssl_version)}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_cipher) {
                html += `
                    <div class="detail-item">
                        <div class="label">Cipher</div>
                        <div class="value">${escapeHtml(data.ssl_info.ssl_cipher)}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_subject) {
                html += `
                    <div class="detail-item">
                        <div class="label">Subject (CN)</div>
                        <div class="value">${escapeHtml(String(data.ssl_info.ssl_subject))}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_issuer) {
                html += `
                    <div class="detail-item">
                        <div class="label">Issuer</div>
                        <div class="value">${escapeHtml(String(data.ssl_info.ssl_issuer))}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_not_before) {
                html += `
                    <div class="detail-item">
                        <div class="label">Valid From</div>
                        <div class="value">${data.ssl_info.ssl_not_before}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_not_after) {
                html += `
                    <div class="detail-item">
                        <div class="label">Valid Until</div>
                        <div class="value">${data.ssl_info.ssl_not_after}</div>
                    </div>`;
            }
            if (data.ssl_info.ssl_san && data.ssl_info.ssl_san.length > 0) {
                html += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">Subject Alt Names</div>
                        <div class="value">${data.ssl_info.ssl_san.map(s => escapeHtml(s)).join(', ')}</div>
                    </div>`;
            }
            html += `</div></div>`;
        }

        // ── TCP Banners
        if (data.banners && Object.keys(data.banners).length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-satellite-dish"></i> Service Banners</div>`;
            for (const [port, banner] of Object.entries(data.banners)) {
                const knownName = WELL_KNOWN_PORTS[parseInt(port, 10)];
                const portLabel = knownName ? `Port ${port} (${knownName})` : `Port ${port}`;
                html += `
                <div class="detail-item mb-2" style="grid-column: 1/-1;">
                    <div class="label">${portLabel}</div>
                    <pre style="color: var(--text-secondary); font-size: 0.78rem; white-space: pre-wrap; margin:0; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-top: 4px;">${escapeHtml(banner)}</pre>
                </div>`;
            }
            html += `</div>`;
        }

        // ── Host Scripts (NSE)
        if (data.scripts && Object.keys(data.scripts).length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-terminal"></i> NSE Host Scripts</div>`;
            for (const [scriptId, output] of Object.entries(data.scripts)) {
                html += `
                <div class="detail-item mb-2" style="grid-column: 1/-1;">
                    <div class="label">${escapeHtml(scriptId)}</div>
                    <pre style="color: var(--text-secondary); font-size: 0.78rem; white-space: pre-wrap; margin:0; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-top: 4px;">${escapeHtml(output)}</pre>
                </div>`;
            }
            html += `</div>`;
        }

        // ── Uptime & TCP Sequence
        if (data.uptime || data.tcp_sequence) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-clock"></i> System Information</div>
                <div class="detail-grid">`;
            if (data.uptime) {
                const friendly = formatUptime(data.uptime.seconds);
                html += `
                    <div class="detail-item">
                        <div class="label">Uptime</div>
                        <div class="value">${friendly ? friendly + ' <span class="text-muted">(' + data.uptime.seconds + 's)</span>' : (data.uptime.seconds || '—')}</div>
                    </div>
                    <div class="detail-item">
                        <div class="label">Last Boot</div>
                        <div class="value">${data.uptime.lastboot || '—'}</div>
                    </div>`;
            }
            if (data.tcp_sequence) {
                if (data.tcp_sequence.class) {
                    html += `
                    <div class="detail-item">
                        <div class="label">TCP Seq. Class</div>
                        <div class="value">${escapeHtml(data.tcp_sequence.class)}</div>
                    </div>`;
                }
                if (data.tcp_sequence.difficulty) {
                    html += `
                    <div class="detail-item">
                        <div class="label">TCP Seq. Difficulty</div>
                        <div class="value">${escapeHtml(data.tcp_sequence.difficulty)}</div>
                    </div>`;
                }
                if (data.tcp_sequence.index) {
                    html += `
                    <div class="detail-item">
                        <div class="label">TCP Seq. Index</div>
                        <div class="value">${escapeHtml(String(data.tcp_sequence.index))}</div>
                    </div>`;
                }
                if (data.tcp_sequence.values) {
                    html += `
                    <div class="detail-item" style="grid-column: 1/-1;">
                        <div class="label">TCP Seq. Values</div>
                        <div class="value" style="font-size:0.75rem; word-break:break-all;">${escapeHtml(data.tcp_sequence.values)}</div>
                    </div>`;
                }
            }
            html += `</div></div>`;
        }

        // ── WHOIS Information
        if (data.whois) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-address-card"></i> WHOIS Information</div>
                <pre style="color: var(--text-secondary); font-size: 0.73rem; white-space: pre-wrap; margin:0; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; max-height: 300px; overflow-y: auto;">${escapeHtml(data.whois)}</pre>
            </div>`;
        }

        // Error notice
        if (data.error) {
            html += `
            <div class="detail-section">
                <div class="alert" style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px; color: var(--accent-red); padding: 12px 16px;">
                    <i class="fas fa-exclamation-triangle mr-2"></i>${escapeHtml(data.error)}
                </div>
            </div>`;
        }

        if (!data.scan_complete && !data.error) {
            html += `
            <div class="detail-section">
                <div class="alert" style="background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); border-radius:8px; color: var(--accent-orange); padding: 12px 16px;">
                    <i class="fas fa-info-circle mr-2"></i>Nmap scan returned limited data. Try running a Full Scan for more details.
                    <br><small>Note: Some features require root/sudo privileges (OS detection, SYN scan).</small>
                </div>
            </div>`;
        }

        dom.hostDetailBody().innerHTML = html;
    }

    // ── Utilities ───────────────────────────────────────────────────────────
    function truncate(str, len) {
        return str.length > len ? str.substring(0, len - 1) + '…' : str;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function showToast(message, type) {
        // Respect toast setting (always show errors)
        if (type !== 'error') {
            try { if (!document.getElementById('settingToasts').checked) return; } catch (e) { /* ok */ }
        }

        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        const icons = {
            info: 'fa-info-circle text-blue',
            success: 'fa-check-circle text-green',
            error: 'fa-exclamation-circle text-red',
            warning: 'fa-exclamation-triangle text-orange',
        };

        const toast = document.createElement('div');
        toast.className = 'scan-toast';
        toast.innerHTML = `<i class="fas ${icons[type] || icons.info}"></i> ${message}`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    /** Play a short notification beep when scan completes (if enabled). */
    function playScanCompleteSound() {
        try {
            if (!document.getElementById('settingSounds').checked) return;
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type = 'sine';
            osc.frequency.value = 880;
            gain.gain.value = 0.15;
            osc.start();
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
            osc.stop(ctx.currentTime + 0.3);
        } catch (e) { /* AudioContext not available */ }
    }

    // ── Public API (for onclick handlers in HTML) ───────────────────────────
    window.SubnetScanner = {
        openHostDetail: openHostDetail,
    };

    // ── Batch Nmap Scan ───────────────────────────────────────────────────────
    function startBatchNmapScan() {
        const onlineIps = Object.values(state.results)
            .filter(r => r.alive)
            .map(r => r.ip);

        if (onlineIps.length === 0) {
            showToast('No online hosts to scan', 'warning');
            return;
        }

        // Stop live update
        stopLiveUpdate();
        document.getElementById('settingLiveUpdate').checked = false;
        state.liveUpdate = false;
        setLiveUpdateEnabled(false);
        state.scanning = true;

        const btn = dom.btnFullScanMain();
        btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Scanning...';
        btn.disabled = true;

        showToast('Starting Nmap scan on ' + onlineIps.length + ' hosts...', 'info');
        setStatus('Nmap 0/' + onlineIps.length, 'scanning');

        state.socket.emit('batch_nmap_scan', { ips: onlineIps });
    }

    function handleBatchNmapResult(data) {
        if (!data || !data.ip) return;

        // Update list view columns
        const ipKey = data.ip.replace(/\./g, '-');

        // Open ports
        if (data.open_ports && data.open_ports.length > 0) {
            const portsEl = document.getElementById('ports-' + ipKey);
            if (portsEl) {
                portsEl.className = '';
                portsEl.innerHTML = renderPortTags(data.open_ports);
            }
        }

        // OS
        if (data.os_matches && data.os_matches.length > 0) {
            const osEl = document.getElementById('os-' + ipKey);
            if (osEl) {
                osEl.innerHTML = `<span title="${data.os_matches[0].name}">${truncate(data.os_matches[0].name, 25)}</span>`;
            }
        }

        // MAC
        if (data.mac_address) {
            const macEl = document.getElementById('mac-' + ipKey);
            if (macEl) macEl.textContent = data.mac_address;
        }
    }

    // ── Full Scan (ping → nmap + deep probes) ─────────────────────────────────
    function startFullScan() {
        // If a sweep was already done for the SAME subnet, skip the sweep
        // and go straight to deep scan
        const currentSubnet = dom.subnetInput().value.trim();
        const hasResults = Object.keys(state.results).length > 0;
        if (hasResults && state.scanCompleted && state.scanId === currentSubnet) {
            startBatchFullScan();
            return;
        }
        // Different subnet or no prior sweep — run ping sweep first
        state.fullScanPending = true;
        startScan();
    }

    function startBatchFullScan() {
        const onlineIps = Object.values(state.results)
            .filter(r => r.alive)
            .map(r => r.ip);

        if (onlineIps.length === 0) {
            setScanningState(false);
            setStatus('Done — no hosts online', 'done');
            showToast('No online hosts to deep scan', 'warning');
            return;
        }

        // Keep buttons disabled, update Full Scan button text
        const btnFull = dom.btnFullScanMain();
        btnFull.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Deep Scan...';
        btnFull.disabled = true;
        dom.btnScan().disabled = true;
        dom.btnStop().classList.remove('d-none');
        dom.subnetInput().disabled = true;
        state.scanning = true;

        // Stop live update
        stopLiveUpdate();
        document.getElementById('settingLiveUpdate').checked = false;
        state.liveUpdate = false;
        setLiveUpdateEnabled(false);

        setStatus('Deep Scan 0/' + onlineIps.length, 'scanning');
        dom.progressFill().style.width = '0%';

        const s = getSettings();
        state.socket.emit('batch_full_scan', {
            ips: onlineIps,
            nmap_args:      buildNmapArgs(s),
            deep_timeout:   s.deepTimeout,
            ssdp_timeout:   s.ssdpTimeout,
            deep_http:      s.deepHttp,
            deep_ssl:       s.deepSsl,
            deep_banners:   s.deepBanners,
            deep_ssdp:      s.deepSsdp,
            deep_mac_vendor: s.deepMacVendor,
        });
    }

    function handleBatchFullScanResult(data) {
        if (!data || !data.ip) return;

        const ipKey = data.ip.replace(/\./g, '-');

        // Store deep scan data in state
        if (state.results[data.ip]) {
            state.results[data.ip].deep = data;
            if (data.open_ports) state.results[data.ip].open_ports = data.open_ports;
        }

        // Open Ports
        if (data.open_ports && data.open_ports.length > 0) {
            const portsEl = document.getElementById('ports-' + ipKey);
            if (portsEl) {
                portsEl.className = '';
                portsEl.innerHTML = renderPortTags(data.open_ports);
            }
        } else {
            // No open ports found — show that explicitly
            const portsEl = document.getElementById('ports-' + ipKey);
            if (portsEl) {
                portsEl.className = 'text-muted';
                portsEl.textContent = 'none';
            }
        }

        // OS — prefer nmap, fallback to TTL guess
        const osEl = document.getElementById('os-' + ipKey);
        if (osEl) {
            if (data.os_matches && data.os_matches.length > 0) {
                osEl.innerHTML = `<span title="${data.os_matches[0].name}">${truncate(data.os_matches[0].name, 25)}</span>`;
            } else if (state.results[data.ip] && state.results[data.ip].ttl_os_guess) {
                osEl.innerHTML = `<span class="text-muted" title="Guessed from TTL">${state.results[data.ip].ttl_os_guess} <i class="fas fa-question-circle" style="font-size:0.65rem;opacity:0.5"></i></span>`;
            }
        }

        // MAC + Vendor
        const macEl = document.getElementById('mac-' + ipKey);
        if (macEl) {
            const mac = data.mac_address || data.mac_from_arp;
            if (mac) {
                let macHtml = mac;
                const vendor = data.mac_vendor || data.vendor;
                if (vendor) {
                    macHtml += `<br><small class="text-muted">${truncate(vendor, 30)}</small>`;
                }
                macEl.innerHTML = macHtml;
            }
        }
    }

    // ── Live Update ─────────────────────────────────────────────────────────
    function setLiveUpdateEnabled(enabled) {
        const toggle = document.getElementById('settingLiveUpdate');
        const label = document.getElementById('liveUpdateToggle');
        toggle.disabled = !enabled;
        if (label) label.classList.toggle('disabled', !enabled);
    }

    function startLiveUpdate() {
        stopLiveUpdate();
        if (Object.keys(state.results).length === 0) return;
        setStatus('Live • Starting...', 'live');
        runLiveUpdate();
    }

    function stopLiveUpdate() {
        if (state.liveTimeout) {
            clearTimeout(state.liveTimeout);
            state.liveTimeout = null;
        }
        if (!state.scanning) {
            setStatus('Idle', 'idle');
            dom.progressFill().style.width = '0%';
        }
    }

    function runLiveUpdate() {
        const ips = Object.keys(state.results);
        if (ips.length === 0 || state.scanning) return;
        const pingCount = parseInt(document.getElementById('settingLivePingCount').value, 10) || 2;
        state.socket.emit('live_update', { ips: ips, ping_count: pingCount });
    }

    function handleLiveUpdateResult(data) {
        const prev = state.results[data.ip];
        if (!prev) return;

        const changed = prev.alive !== data.alive || prev.response_time !== data.response_time;
        if (!changed) return;

        // Update cached result (only ping fields)
        prev.alive = data.alive;
        prev.response_time = data.response_time;
        if (data.hostname) prev.hostname = data.hostname;

        // Refresh grid block (only shows IP + online/offline)
        addOrUpdateGridBlock(prev);

        // Update only the volatile table cells — preserve ports/OS/MAC from full scan
        const ipKey = data.ip.replace(/\./g, '-');
        const row = document.getElementById('row-' + ipKey);
        if (row) {
            row.dataset.alive = data.alive ? 'true' : 'false';
            row.className = data.alive ? '' : 'text-muted';

            const cells = row.querySelectorAll('td');
            // Cell 0: status badge
            if (cells[0]) {
                cells[0].innerHTML = data.alive
                    ? '<span class="status-badge online"><span class="dot"></span>Online</span>'
                    : '<span class="status-badge offline"><span class="dot"></span>Offline</span>';
            }
            // Cell 3: response time
            if (cells[3]) {
                cells[3].innerHTML = data.response_time !== null
                    ? '<span class="text-cyan font-weight-bold">' + data.response_time + ' ms</span>'
                    : '<span class="text-muted">—</span>';
            }
            // Cell 2: hostname (only if we got a new one)
            if (cells[2] && data.hostname) {
                cells[2].textContent = data.hostname;
            }

            applyFilterToRow(row);
        }

        // Recount stats
        const all = Object.values(state.results);
        const online = all.filter(r => r.alive).length;
        const offline = all.filter(r => !r.alive).length;
        updateStats(all.length, online, offline, 100);
    }

    // ── Start ───────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', init);

})();
