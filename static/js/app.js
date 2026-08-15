let currentScanResult = null;
let currentFinding = null;
let activeFilters = {
    severity: 'ALL',
    confidence: 'ALL',
    status: 'ALL'
};
let ws = null;

document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadSampleRepositories();
});

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/scan`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        document.getElementById('systemStatusText').innerText = 'Agent Connected';
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };

    ws.onclose = () => {
        document.getElementById('systemStatusText').innerText = 'Reconnecting...';
        setTimeout(initWebSocket, 3000);
    };
}

function handleWebSocketMessage(data) {
    if (data.event === 'SCAN_PROGRESS') {
        showProgressBar(data.percent, data.status);
    } else if (data.event === 'SCAN_COMPLETED') {
        showProgressBar(100, 'Scan completed!');
        setTimeout(() => hideProgressBar(), 1200);
        fetchScanResult(data.scan_id);
    } else if (data.event === 'FINDING_UPDATED') {
        if (currentScanResult) {
            fetchScanResult(currentScanResult.scan_id);
        }
    }
}

async function loadSampleRepositories() {
    try {
        const res = await fetch('/api/scans/samples');
        const samples = await res.json();
        const select = document.getElementById('sampleRepoSelect');
        select.innerHTML = '<option value="">-- Choose a sample or enter URL below --</option>';
        samples.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.local_path;
            opt.innerText = `${s.name} (${s.description})`;
            select.appendChild(opt);
        });
    } catch (err) {
        console.error('Error loading sample repos:', err);
    }
}

function onSampleSelected() {
    const val = document.getElementById('sampleRepoSelect').value;
    if (val) {
        document.getElementById('repoUrlInput').value = '';
    }
}

async function startRepositoryScan() {
    const localPath = document.getElementById('sampleRepoSelect').value;
    const repoUrl = document.getElementById('repoUrlInput').value.trim();
    const branch = document.getElementById('branchInput').value.trim() || 'main';

    if (!localPath && !repoUrl) {
        alert('Please select a sample repository or enter a remote Git URL.');
        return;
    }

    const payload = {
        repo_url: repoUrl || null,
        local_path: localPath || null,
        branch: branch
    };

    showProgressBar(10, 'Initializing scan...');
    document.getElementById('startScanBtn').disabled = true;

    try {
        const res = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.json();
            alert(`Scan Error: ${errData.detail || 'Failed to start scan.'}`);
            hideProgressBar();
            return;
        }

        const scanResult = await res.json();
        currentScanResult = scanResult;
        renderScanDashboard(scanResult);
    } catch (err) {
        alert(`Request error: ${err.message}`);
    } finally {
        document.getElementById('startScanBtn').disabled = false;
    }
}

async function fetchScanResult(scanId) {
    try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (res.ok) {
            currentScanResult = await res.json();
            renderScanDashboard(currentScanResult);
        }
    } catch (err) {
        console.error('Failed fetching scan result:', err);
    }
}

function renderScanDashboard(result) {
    // Render metric cards
    document.getElementById('metricTotal').innerText = result.summary.total_findings;
    document.getElementById('metricCritical').innerText = result.summary.by_severity['Critical'] || 0;
    document.getElementById('metricHigh').innerText = result.summary.by_severity['High'] || 0;
    document.getElementById('metricMedium').innerText = result.summary.by_severity['Medium'] || 0;
    document.getElementById('metricFiles').innerText = result.summary.files_scanned;
    document.getElementById('metricDuration').innerText = `${result.summary.scan_duration_seconds}s`;

    filterFindings();
}

function filterFindings() {
    if (!currentScanResult) return;

    const query = document.getElementById('searchInput').value.toLowerCase();
    
    const filtered = currentScanResult.findings.filter(f => {
        if (activeFilters.severity !== 'ALL' && f.severity.toLowerCase() !== activeFilters.severity.toLowerCase()) return false;
        if (activeFilters.confidence !== 'ALL' && f.confidence.toLowerCase() !== activeFilters.confidence.toLowerCase()) return false;
        if (activeFilters.status !== 'ALL' && f.status.toLowerCase() !== activeFilters.status.toLowerCase()) return false;

        if (query) {
            const matchText = `${f.title} ${f.file_path} ${f.cwe_id} ${f.vulnerability_type} ${f.tech_stack}`.toLowerCase();
            if (!matchText.includes(query)) return false;
        }
        return true;
    });

    renderFindingsTable(filtered);
}

function setFilter(type, value, btnElem) {
    activeFilters[type] = value;
    const parent = btnElem.parentElement;
    parent.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    btnElem.classList.add('active');
    filterFindings();
}

function renderFindingsTable(findings) {
    const tbody = document.getElementById('findingsTableBody');
    if (!findings || findings.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center empty-state">
                    No matching security findings found for current filter criteria.
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = findings.map(f => {
        const sevClass = f.severity.toLowerCase();
        return `
            <tr>
                <td><span class="badge badge-${sevClass}">${f.severity}</span></td>
                <td><span class="subtext">${f.confidence}</span></td>
                <td><strong>${f.cwe_id}</strong><br><span class="subtext">${f.tech_stack}</span></td>
                <td><code>${f.file_path}:${f.line_number}</code></td>
                <td>${escapeHtml(f.title)}</td>
                <td><span class="badge ${getStatusBadgeClass(f.status)}">${f.status}</span></td>
                <td>
                    <button class="btn btn-secondary" onclick="openReviewModal('${f.id}')">
                        Review Fix
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function getStatusBadgeClass(status) {
    if (status === 'Fixed') return 'badge-success';
    if (status === 'False Positive') return 'badge-info';
    if (status === 'Accepted Risk') return 'badge-warning';
    return 'badge-critical';
}

async function openReviewModal(findingId) {
    currentFinding = currentScanResult.findings.find(f => f.id === findingId);
    if (!currentFinding) return;

    document.getElementById('modalSeverityBadge').className = `badge badge-${currentFinding.severity.toLowerCase()}`;
    document.getElementById('modalSeverityBadge').innerText = currentFinding.severity;
    document.getElementById('modalTitle').innerText = currentFinding.title;
    document.getElementById('modalCweText').innerText = `${currentFinding.cwe_id} - ${currentFinding.cwe_title}`;
    document.getElementById('modalExplanation').innerText = currentFinding.explanation;
    document.getElementById('modalFilePath').innerText = `${currentFinding.file_path}:${currentFinding.line_number}`;
    document.getElementById('modalContextCode').innerText = currentFinding.surrounding_context;
    document.getElementById('patchEditor').value = currentFinding.proposed_fix;
    document.getElementById('branchInputModal').value = `security-fix/${currentFinding.id.toLowerCase()}`;

    renderTraceTimeline(currentFinding.data_flow_trace);
    await loadDiffPreview(currentFinding.id);

    document.getElementById('verificationBanner').className = 'verification-banner hidden';
    document.getElementById('reviewModal').classList.remove('hidden');
}

function closeReviewModal() {
    document.getElementById('reviewModal').classList.add('hidden');
}

function renderTraceTimeline(traceSteps) {
    const container = document.getElementById('traceContainer');
    if (!traceSteps || traceSteps.length === 0) {
        container.innerHTML = '<p class="subtext">No trace evidence available.</p>';
        return;
    }

    container.innerHTML = traceSteps.map(step => {
        const stepClass = step.step_type === 'source' ? 'trace-step-source' : (step.step_type === 'sink' ? 'trace-step-sink' : '');
        return `
            <div class="trace-step ${stepClass}">
                <div class="trace-header">
                    <span>Step ${step.step_number}: ${step.step_type.toUpperCase()}</span>
                    <span>${step.file_path}:${step.line_number}</span>
                </div>
                <div class="subtext">${escapeHtml(step.description)}</div>
                <pre class="code-badge margin-top-md">${escapeHtml(step.code_excerpt)}</pre>
            </div>
        `;
    }).join('');
}

async function loadDiffPreview(findingId, customPatch = null) {
    try {
        const res = await fetch('/api/remediate/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding_id: findingId, custom_patch: customPatch })
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById('modalDiffPreview').innerText = data.diff_unified;
        }
    } catch (err) {
        console.error('Error generating diff preview:', err);
    }
}

async function applyApprovedFix() {
    if (!currentFinding) return;

    const approvedPatch = document.getElementById('patchEditor').value.trim();
    const branchName = document.getElementById('branchInputModal').value.trim();
    const reviewComment = document.getElementById('reviewComment').value.trim();

    const payload = {
        finding_id: currentFinding.id,
        approved_patch: approvedPatch,
        reviewer: 'Security Reviewer',
        target_branch: branchName || null,
        review_comment: reviewComment
    };

    try {
        const res = await fetch('/api/remediate/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        const banner = document.getElementById('verificationBanner');
        banner.classList.remove('hidden');

        if (data.success && data.post_fix_verification === 'Fixed') {
            banner.className = 'verification-banner success';
            banner.innerText = `Fix Approved & Verified! ${data.message}`;
            currentFinding.status = 'Fixed';
        } else {
            banner.className = 'verification-banner error';
            banner.innerText = `Verification Warning: ${data.message}`;
        }

        setTimeout(() => {
            fetchScanResult(currentScanResult.scan_id);
        }, 1500);
    } catch (err) {
        alert(`Patch Error: ${err.message}`);
    }
}

async function markFindingStatus(status) {
    if (!currentFinding) return;
    const comment = prompt(`Reason for marking as ${status}:`);
    if (comment === null) return;

    try {
        const res = await fetch(`/api/findings/${currentFinding.id}/status?status=${encodeURIComponent(status)}&reviewer=Security%20Reviewer&comment=${encodeURIComponent(comment)}`, {
            method: 'PATCH'
        });
        if (res.ok) {
            currentFinding.status = status;
            closeReviewModal();
            fetchScanResult(currentScanResult.scan_id);
        }
    } catch (err) {
        alert(`Failed to update status: ${err.message}`);
    }
}

async function openAuditModal() {
    try {
        const res = await fetch('/api/audit');
        const logs = await res.json();
        const tbody = document.getElementById('auditTableBody');
        tbody.innerHTML = logs.map(l => `
            <tr>
                <td class="subtext">${new Date(l.timestamp).toLocaleString()}</td>
                <td><strong>${l.action}</strong></td>
                <td>${escapeHtml(l.reviewer)}</td>
                <td><pre class="code-badge">${escapeHtml(JSON.stringify(l.details))}</pre></td>
            </tr>
        `).join('');
        document.getElementById('auditModal').classList.remove('hidden');
    } catch (err) {
        alert(`Error loading audit logs: ${err.message}`);
    }
}

function closeAuditModal() {
    document.getElementById('auditModal').classList.add('hidden');
}

function showProgressBar(percent, statusMsg) {
    const container = document.getElementById('scanProgressContainer');
    container.classList.remove('hidden');
    document.getElementById('scanProgressBar').style.width = `${percent}%`;
    document.getElementById('scanPercentText').innerText = `${percent}%`;
    document.getElementById('scanStatusMsg').innerText = statusMsg;
}

function hideProgressBar() {
    document.getElementById('scanProgressContainer').classList.add('hidden');
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
