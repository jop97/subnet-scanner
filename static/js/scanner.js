/**
 * Subnet Scanner — Frontend Controller
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
    };

    // ── DOM References ──────────────────────────────────────────────────────
    const dom = {
        scanForm:        () => document.getElementById('scanForm'),
        subnetInput:     () => document.getElementById('subnetInput'),
        presetSelect:    () => document.getElementById('presetSelect'),
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
        statProgress:    () => document.getElementById('statProgress'),
        progressFill:    () => document.getElementById('progressFill'),
        connectionDot:   () => document.getElementById('connectionDot'),
        connectionText:  () => document.getElementById('connectionText'),
        hostDetailModal: () => document.getElementById('hostDetailModal'),
        hostDetailTitle: () => document.getElementById('hostDetailTitle'),
        hostDetailBody:  () => document.getElementById('hostDetailBody'),
        btnFullScan:     () => document.getElementById('btnFullScan'),
    };

    // ── Initialize ──────────────────────────────────────────────────────────
    function init() {
        connectSocket();
        bindEvents();
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
            showToast('Scan stopped', 'warning');
        });

        state.socket.on('host_detail_scanning', (data) => {
            showDetailLoading(data.ip);
        });

        state.socket.on('host_detail_result', (data) => {
            renderHostDetail(data);
        });

        state.socket.on('host_detail_error', (data) => {
            showDetailError(data.error);
        });
    }

    function setConnectionStatus(connected) {
        const dot = dom.connectionDot();
        const text = dom.connectionText();
        if (connected) {
            dot.className = 'fas fa-circle text-success';
            text.textContent = 'Connected';
        } else {
            dot.className = 'fas fa-circle text-danger';
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

        // Preset select
        dom.presetSelect().addEventListener('change', (e) => {
            if (e.target.value) {
                dom.subnetInput().value = e.target.value;
            }
        });

        // Stop button
        dom.btnStop().addEventListener('click', stopScan);

        // Clear button
        dom.btnClear().addEventListener('click', clearResults);

        // View toggle
        dom.btnGridView().addEventListener('click', () => switchView('grid'));
        dom.btnListView().addEventListener('click', () => switchView('list'));

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
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
        state.scanId = subnet;

        state.socket.emit('start_scan', {
            subnet: subnet,
            scan_id: subnet,
        });
    }

    function stopScan() {
        if (state.scanId) {
            state.socket.emit('stop_scan', { scan_id: state.scanId });
        }
        setScanningState(false);
    }

    function setScanningState(scanning) {
        state.scanning = scanning;
        const btnScan = dom.btnScan();
        const btnStop = dom.btnStop();

        if (scanning) {
            btnScan.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Scanning...';
            btnScan.classList.add('scanning');
            btnScan.disabled = true;
            btnStop.classList.remove('d-none');
            dom.subnetInput().disabled = true;
            dom.presetSelect().disabled = true;
        } else {
            btnScan.innerHTML = '<i class="fas fa-play mr-2"></i>Start Scan';
            btnScan.classList.remove('scanning');
            btnScan.disabled = false;
            btnStop.classList.add('d-none');
            dom.subnetInput().disabled = false;
            dom.presetSelect().disabled = false;
        }
    }

    function clearResults() {
        state.results = {};
        dom.ipGrid().innerHTML = `
            <div class="empty-state" id="emptyState">
                <div class="empty-icon"><i class="fas fa-satellite-dish"></i></div>
                <h4>Ready to Scan</h4>
                <p>Enter a subnet in CIDR notation and hit <strong>Start Scan</strong> to discover hosts on your network.</p>
            </div>`;
        dom.resultsTableBody().innerHTML = '';
        updateStats(0, 0, 0, 0);

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

        // Update stats
        const all = Object.values(state.results);
        const online = all.filter(r => r.alive).length;
        const offline = all.filter(r => !r.alive).length;
        updateStats(data.total || all.length, online, offline, data.progress || 0);
    }

    function handleScanComplete(data) {
        setScanningState(false);
        updateStats(data.total, data.alive, data.dead, 100);
        showToast(`Scan complete — ${data.alive} hosts online, ${data.dead} offline`, 'success');

        // Initialize or refresh DataTable
        initDataTable();
    }

    function handleScanError(data) {
        setScanningState(false);
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

        const hostname = data.hostname ? truncate(data.hostname, 16) : '';
        const timeStr = data.response_time !== null ? data.response_time + ' ms' : '';

        block.innerHTML = `
            <span class="ip-status-dot"></span>
            <div class="ip-addr">${formatIP(data.ip)}</div>
            <div class="ip-hostname" title="${data.hostname || ''}">${hostname}</div>
            <div class="ip-time">${timeStr}</div>
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

        row.innerHTML = `
            <td>${statusBadge}</td>
            <td><strong>${data.ip}</strong></td>
            <td>${data.hostname || '<span class="text-muted">—</span>'}</td>
            <td>${responseTime}</td>
            <td><span class="text-muted" id="ports-${data.ip.replace(/\./g, '-')}">—</span></td>
            <td><span class="text-muted" id="os-${data.ip.replace(/\./g, '-')}">—</span></td>
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

        const rowCount = document.querySelectorAll('#resultsTable tbody tr').length;
        if (rowCount > 0) {
            state.dataTable = $('#resultsTable').DataTable({
                paging: true,
                pageLength: 50,
                ordering: true,
                searching: true,
                responsive: true,
                order: [[1, 'asc']],
                dom: '<"row"<"col-sm-6"l><"col-sm-6"f>>rtip',
                language: {
                    search: '<i class="fas fa-search mr-1"></i>',
                    lengthMenu: 'Show _MENU_ hosts',
                    info: 'Showing _START_ to _END_ of _TOTAL_ hosts',
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
        if (filter === 'all') {
            block.style.display = '';
        } else if (filter === 'online') {
            block.style.display = block.dataset.alive === 'true' ? '' : 'none';
        } else if (filter === 'offline') {
            block.style.display = block.dataset.alive === 'false' ? '' : 'none';
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
        dom.statProgress().innerHTML = Math.round(progress) + '<sup style="font-size:20px">%</sup>';
        dom.progressFill().style.width = progress + '%';
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
        dom.hostDetailTitle().innerHTML = `<i class="fas fa-info-circle mr-2"></i>${ip}`;

        // Show basic info from cached results first
        const cached = state.results[ip];
        if (cached) {
            renderQuickInfo(cached);
        }

        $('#hostDetailModal').modal('show');

        // Request detailed scan
        requestHostDetail(ip, 'quick');
    }

    function requestHostDetail(ip, scanType) {
        showDetailLoading(ip);
        state.socket.emit('scan_host_detail', { ip: ip, scan_type: scanType });
    }

    function showDetailLoading(ip) {
        dom.hostDetailBody().innerHTML = `
            <div class="text-center py-5">
                <div class="scanner-animation" style="margin: 0 auto;"></div>
                <p class="mt-3 text-muted">
                    <i class="fas fa-satellite-dish fa-spin mr-1"></i>
                    Scanning <strong class="text-cyan">${ip}</strong>...
                </p>
                <p class="text-muted" style="font-size:0.8rem;">Running Nmap service & OS detection</p>
            </div>`;
    }

    function showDetailError(error) {
        dom.hostDetailBody().innerHTML = `
            <div class="text-center py-5">
                <i class="fas fa-exclamation-triangle fa-3x text-orange mb-3"></i>
                <p class="text-muted">${error}</p>
            </div>`;
    }

    function renderQuickInfo(data) {
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
            <div class="text-center py-3">
                <div class="scanner-animation" style="margin: 0 auto; width:40px; height:40px;"></div>
                <p class="mt-2 text-muted" style="font-size:0.82rem;">Loading detailed scan data...</p>
            </div>`;
    }

    function renderHostDetail(data) {
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
                    <div class="label">Reverse DNS</div>
                    <div class="value">${data.reverse_dns || '<span class="text-muted">—</span>'}</div>
                </div>`;

        if (data.mac_address || data.mac_from_arp) {
            html += `
                <div class="detail-item">
                    <div class="label">MAC Address</div>
                    <div class="value">${data.mac_address || data.mac_from_arp || '—'}</div>
                </div>`;
            // Update list view MAC
            const macEl = document.getElementById('mac-' + data.ip.replace(/\./g, '-'));
            if (macEl) macEl.textContent = data.mac_address || data.mac_from_arp || '—';
        }

        if (data.vendor) {
            html += `
                <div class="detail-item">
                    <div class="label">Vendor</div>
                    <div class="value">${data.vendor}</div>
                </div>`;
        }

        if (data.netbios_name) {
            html += `
                <div class="detail-item">
                    <div class="label">NetBIOS Name</div>
                    <div class="value">${data.netbios_name}</div>
                </div>`;
        }

        if (data.workgroup) {
            html += `
                <div class="detail-item">
                    <div class="label">Workgroup</div>
                    <div class="value">${data.workgroup}</div>
                </div>`;
        }

        html += `</div></div>`;

        // ── DNS Records
        if (data.dns_names && data.dns_names.length > 0 || data.ptr_records && data.ptr_records.length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-globe"></i> DNS Information</div>
                <div class="detail-grid">`;
            if (data.dns_names && data.dns_names.length) {
                html += `
                    <div class="detail-item">
                        <div class="label">DNS Names</div>
                        <div class="value">${data.dns_names.join('<br>')}</div>
                    </div>`;
            }
            if (data.ptr_records && data.ptr_records.length) {
                html += `
                    <div class="detail-item">
                        <div class="label">PTR Records</div>
                        <div class="value">${data.ptr_records.join('<br>')}</div>
                    </div>`;
            }
            html += `</div></div>`;
        }

        // ── OS Detection
        if (data.os_matches && data.os_matches.length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-desktop"></i> OS Detection</div>
                <div class="detail-grid">`;
            data.os_matches.slice(0, 3).forEach(os => {
                html += `
                    <div class="detail-item">
                        <div class="label">OS Match (${os.accuracy}% accuracy)</div>
                        <div class="value">${os.name}</div>
                    </div>`;
            });
            html += `</div></div>`;

            // Update list view OS
            const osEl = document.getElementById('os-' + data.ip.replace(/\./g, '-'));
            if (osEl && data.os_matches.length > 0) {
                osEl.innerHTML = `<span title="${data.os_matches[0].name}">${truncate(data.os_matches[0].name, 25)}</span>`;
            }
        }

        // ── Open Ports Summary
        if (data.open_ports && data.open_ports.length > 0) {
            // Update list view ports
            const portsEl = document.getElementById('ports-' + data.ip.replace(/\./g, '-'));
            if (portsEl) {
                portsEl.innerHTML = data.open_ports.slice(0, 5).map(p =>
                    `<span class="port-tag">${p}</span>`
                ).join(' ') + (data.open_ports.length > 5 ? ` <span class="text-muted">+${data.open_ports.length - 5}</span>` : '');
            }
        }

        // ── Services / Port Table
        if (data.services && data.services.length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-plug"></i> Ports & Services (${data.services.length})</div>
                <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                    <table class="port-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
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

                html += `
                            <tr>
                                <td><strong>${svc.port}</strong></td>
                                <td>${svc.protocol}</td>
                                <td><span class="${stateClass}">${svc.state}</span></td>
                                <td>${svc.service}</td>
                                <td>${svc.product || '—'}</td>
                                <td>${svc.version || '—'}</td>
                                <td>${svc.extrainfo || '—'}</td>
                            </tr>`;
            });

            html += `</tbody></table></div></div>`;
        }

        // ── Host Scripts
        if (data.scripts && Object.keys(data.scripts).length > 0) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-terminal"></i> NSE Scripts</div>`;
            for (const [scriptId, output] of Object.entries(data.scripts)) {
                html += `
                <div class="detail-item mb-2" style="grid-column: 1/-1;">
                    <div class="label">${scriptId}</div>
                    <pre style="color: var(--text-secondary); font-size: 0.78rem; white-space: pre-wrap; margin:0; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-top: 4px;">${escapeHtml(output)}</pre>
                </div>`;
            }
            html += `</div>`;
        }

        // ── Uptime
        if (data.uptime) {
            html += `
            <div class="detail-section">
                <div class="detail-section-title"><i class="fas fa-clock"></i> Uptime</div>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="label">Seconds</div>
                        <div class="value">${data.uptime.seconds || '—'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="label">Last Boot</div>
                        <div class="value">${data.uptime.lastboot || '—'}</div>
                    </div>
                </div>
            </div>`;
        }

        // Error notice
        if (data.error) {
            html += `
            <div class="detail-section">
                <div class="alert" style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px; color: var(--accent-red); padding: 12px 16px;">
                    <i class="fas fa-exclamation-triangle mr-2"></i>${data.error}
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

    // ── Public API (for onclick handlers in HTML) ───────────────────────────
    window.SubnetScanner = {
        openHostDetail: openHostDetail,
    };

    // ── Start ───────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', init);

})();
