document.addEventListener('DOMContentLoaded', function() {
    const targetUrl = document.getElementById('targetUrl');
    const scanBtn = document.getElementById('scanBtn');
    const batchMode = document.getElementById('batchMode');
    const batchInput = document.getElementById('batchInput');
    const batchUrls = document.getElementById('batchUrls');
    const batchScanBtn = document.getElementById('batchScanBtn');
    const results = document.getElementById('results');
    const summaryCards = document.getElementById('summaryCards');
    const detailedResults = document.getElementById('detailedResults');

    // Toggle batch input
    batchMode.addEventListener('change', function() {
        batchInput.style.display = this.checked ? 'block' : 'none';
        targetUrl.style.display = this.checked ? 'none' : 'block';
        scanBtn.style.display = this.checked ? 'none' : 'flex';
    });

    // Single URL scan
    scanBtn.addEventListener('click', function() {
        const url = targetUrl.value.trim();
        if (!url) {
            showError('Please enter a URL');
            return;
        }
        performScan(url);
    });

    // Batch scan
    batchScanBtn.addEventListener('click', function() {
        const urls = batchUrls.value.split('\n')
            .map(u => u.trim())
            .filter(u => u);
        if (urls.length === 0) {
            showError('Please enter at least one URL');
            return;
        }
        performBatchScan(urls);
    });

    // Enter key support
    targetUrl.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });

    function performScan(url) {
        showLoading(true);
        results.style.display = 'none';

        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            showLoading(false);
            displayResults(data);
        })
        .catch(error => {
            showLoading(false);
            showError('Scan failed: ' + error.message);
        });
    }

    function performBatchScan(urls) {
        showLoading(true);
        results.style.display = 'none';

        fetch('/api/batch-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        })
        .then(response => response.json())
        .then(data => {
            showLoading(false);
            displayBatchResults(data);
        })
        .catch(error => {
            showLoading(false);
            showError('Batch scan failed: ' + error.message);
        });
    }

    function displayResults(report) {
        results.style.display = 'block';
        
        if (report.error) {
            displayError(report.error);
            return;
        }

        // Summary cards
        const summary = report.scan_summary || {};
        const riskLevel = summary.risk_level || 'LOW';
        
        summaryCards.innerHTML = `
            <div class="summary-card risk-${riskLevel.toLowerCase()}">
                <div class="number">${summary.missing_headers || 0}</div>
                <div class="label">Missing Headers</div>
            </div>
            <div class="summary-card">
                <div class="number">${summary.disclosures_found || 0}</div>
                <div class="label">Info Disclosures</div>
            </div>
            <div class="summary-card">
                <div class="number">${summary.cookie_issues || 0}</div>
                <div class="label">Cookie Issues</div>
            </div>
            <div class="summary-card">
                <div class="number">${report.status_code || 'N/A'}</div>
                <div class="label">HTTP Status</div>
            </div>
            <div class="summary-card">
                <div class="number">${summary.headers_present || 0}/${summary.total_headers_checked || 0}</div>
                <div class="label">Headers Present</div>
            </div>
            <div class="summary-card risk-${riskLevel.toLowerCase()}">
                <div class="number">${riskLevel}</div>
                <div class="label">Risk Level</div>
            </div>
        `;

        // Detailed results
        let html = `
            <div class="result-section">
                <h3>📋 Security Headers</h3>
        `;

        // Missing headers
        if (report.findings && report.findings.length > 0) {
            report.findings.forEach(f => {
                html += `
                    <div class="result-item">
                        <div class="item-header">
                            <span class="item-name">❌ ${f.item}</span>
                            <span class="severity severity-${f.severity}">${f.severity}</span>
                        </div>
                        <div class="description">${f.description}</div>
                        ${f.recommendation ? `<div class="recommendation">💡 ${f.recommendation}</div>` : ''}
                    </div>
                `;
            });
        }

        // Passed headers
        if (report.passed_checks && report.passed_checks.length > 0) {
            report.passed_checks.forEach(p => {
                html += `
                    <div class="result-item passed-header">
                        <div class="item-header">
                            <span class="item-name">✅ ${p.header}</span>
                            <span style="color: #2ed573; font-size: 0.8rem;">Present</span>
                        </div>
                        <div class="description">Value: ${p.value}</div>
                    </div>
                `;
            });
        }
        html += '</div>';

        // Cookie issues
        if (report.cookie_issues && report.cookie_issues.length > 0) {
            html += `
                <div class="result-section">
                    <h3>🍪 Cookie Security Issues</h3>
            `;
            report.cookie_issues.forEach(c => {
                html += `
                    <div class="result-item">
                        <div class="item-header">
                            <span class="item-name">⚠️ ${c.cookie_name}</span>
                            <span class="severity severity-${c.severity}">${c.severity}</span>
                        </div>
                        ${c.issues.map(issue => `<div class="description">• ${issue}</div>`).join('')}
                        ${c.recommendation ? `<div class="recommendation">💡 ${c.recommendation}</div>` : ''}
                    </div>
                `;
            });
            html += '</div>';
        }

        // Info disclosures
        if (report.disclosures && report.disclosures.length > 0) {
            html += `
                <div class="result-section">
                    <h3>🔍 Information Disclosures</h3>
            `;
            report.disclosures.forEach(d => {
                html += `
                    <div class="result-item">
                        <div class="item-header">
                            <span class="item-name">📢 ${d.header}</span>
                            <span class="severity severity-${d.severity}">${d.severity}</span>
                        </div>
                        <div class="description">Value: ${d.value} - ${d.description}</div>
                        ${d.recommendation ? `<div class="recommendation">💡 ${d.recommendation}</div>` : ''}
                    </div>
                `;
            });
            html += '</div>';
        }

        // Headers present (raw)
        if (report.headers_present) {
            html += `
                <div class="result-section">
                    <h3>📡 All Response Headers</h3>
                    <div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; overflow-x: auto;">
                        <pre style="color: #8892b0; font-size: 0.85rem; margin: 0;">${JSON.stringify(report.headers_present, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        detailedResults.innerHTML = html;
    }

    function displayBatchResults(data) {
        results.style.display = 'block';
        
        let html = `
            <div style="margin-bottom: 20px;">
                <h3>📊 Batch Scan Results (${data.total_scanned} URLs)</h3>
            </div>
        `;

        data.results.forEach((report, index) => {
            html += `
                <div style="margin-bottom: 30px; padding: 20px; background: rgba(255,255,255,0.03); border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
                    <h4 style="color: #00d4ff; margin-bottom: 10px;">${report.target}</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 15px;">
                        <div>Status: ${report.status_code || 'N/A'}</div>
                        <div>Missing Headers: ${report.scan_summary?.missing_headers || 0}</div>
                        <div>Risk Level: <span class="severity severity-${report.scan_summary?.risk_level || 'LOW'}">${report.scan_summary?.risk_level || 'LOW'}</span></div>
                    </div>
                    ${report.error ? `<div style="color: #ff4757;">Error: ${report.error}</div>` : ''}
                </div>
            `;
        });

        detailedResults.innerHTML = html;
        summaryCards.innerHTML = `<div class="summary-card"><div class="number">${data.total_scanned}</div><div class="label">URLs Scanned</div></div>`;
    }

    function showLoading(show) {
        scanBtn.disabled = show;
        batchScanBtn.disabled = show;
        if (show) {
            scanBtn.querySelector('.btn-text').textContent = 'Scanning...';
            scanBtn.querySelector('.spinner').style.display = 'inline-block';
        } else {
            scanBtn.querySelector('.btn-text').textContent = 'Scan Now';
            scanBtn.querySelector('.spinner').style.display = 'none';
        }
    }

    function showError(message) {
        results.style.display = 'block';
        summaryCards.innerHTML = '';
        detailedResults.innerHTML = `
            <div style="padding: 30px; text-align: center; background: rgba(255,71,87,0.1); border-radius: 12px; border: 1px solid rgba(255,71,87,0.2);">
                <div style="color: #ff4757; font-size: 1.2rem; margin-bottom: 10px;">⚠️ ${message}</div>
                <div style="color: #8892b0;">Please check the URL and try again.</div>
            </div>
        `;
    }

    function displayError(message) {
        detailedResults.innerHTML = `
            <div style="padding: 20px; background: rgba(255,71,87,0.1); border-radius: 8px; border: 1px solid rgba(255,71,87,0.2);">
                <div style="color: #ff4757;">Error: ${message}</div>
            </div>
        `;
    }
});