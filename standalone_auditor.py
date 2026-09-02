#!/usr/bin/env python3
"""
Standalone Web Security Auditor
No Flask required - runs a simple HTTP server
"""

import json
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from datetime import datetime
from urllib.parse import urlparse

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": {"severity": "HIGH", "description": "Mitigates XSS attacks.", "recommendation": "Implement a strict CSP policy."},
    "Strict-Transport-Security": {"severity": "HIGH", "description": "Enforces HTTPS connections.", "recommendation": "Set with max-age=31536000."},
    "X-Frame-Options": {"severity": "MEDIUM", "description": "Protects against clickjacking.", "recommendation": "Set to DENY or SAMEORIGIN."},
    "X-Content-Type-Options": {"severity": "MEDIUM", "description": "Prevents MIME-type sniffing.", "recommendation": "Set to 'nosniff'."},
    "Referrer-Policy": {"severity": "LOW", "description": "Controls referrer information.", "recommendation": "Set to 'no-referrer'."},
    "Permissions-Policy": {"severity": "LOW", "description": "Restricts browser features.", "recommendation": "Restrict unnecessary features."},
}

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

class SecurityAuditor:
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
    
    def _normalize_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}"
        return url
    
    def scan(self):
        report = {
            "target": self.target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status_code": None,
            "findings": [],
            "passed_checks": [],
            "cookie_issues": [],
            "disclosures": [],
            "headers_present": {},
            "scan_summary": {}
        }
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=True, allow_redirects=True)
            report["status_code"] = response.status_code
            headers = response.headers
            report["headers_present"] = dict(headers)
            
            missing_headers = []
            for header, meta in RECOMMENDED_HEADERS.items():
                if header not in headers:
                    report["findings"].append({
                        "item": header,
                        "severity": meta["severity"],
                        "description": meta["description"],
                        "recommendation": meta["recommendation"]
                    })
                    missing_headers.append(header)
                else:
                    report["passed_checks"].append({"header": header, "value": headers[header]})
            
            for header in DISCLOSURE_HEADERS:
                if header in headers:
                    report["disclosures"].append({
                        "header": header,
                        "value": headers[header],
                        "severity": "LOW",
                        "description": "Exposes backend technology stack.",
                        "recommendation": f"Remove '{header}' header."
                    })
            
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' flag")
                if not cookie.has_nonstandard_attr("httponly") and not getattr(cookie, "_rest", {}).get("httponly"):
                    issues.append("Missing 'HttpOnly' flag")
                samesite = getattr(cookie, "_rest", {}).get("samesite", None)
                if not samesite:
                    issues.append("Missing 'SameSite' attribute")
                if issues:
                    report["cookie_issues"].append({
                        "cookie_name": cookie.name,
                        "issues": issues,
                        "severity": "MEDIUM",
                        "recommendation": "Set Secure, HttpOnly, and SameSite attributes."
                    })
            
            severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            total_score = sum(severity_weights.get(f["severity"], 0) for f in report["findings"]) + len(report["cookie_issues"]) * 2
            
            report["scan_summary"] = {
                "total_headers_checked": len(RECOMMENDED_HEADERS),
                "missing_headers": len(missing_headers),
                "disclosures_found": len(report["disclosures"]),
                "cookie_issues": len(report["cookie_issues"]),
                "headers_present": len(report["passed_checks"]),
                "risk_level": "CRITICAL" if total_score >= 8 else "HIGH" if total_score >= 5 else "MEDIUM" if total_score >= 3 else "LOW"
            }
            
        except requests.exceptions.SSLError:
            report["error"] = "SSL Certificate verification failed"
        except requests.exceptions.ConnectionError:
            report["error"] = "Connection error - Unable to reach the target URL"
        except requests.exceptions.Timeout:
            report["error"] = "Request timeout"
        except Exception as e:
            report["error"] = str(e)
        
        return report

class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_html()
        elif self.path.startswith('/scan'):
            self.handle_scan()
        elif self.path == '/favicon.ico':
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                url = data.get('url', '')
                if url:
                    auditor = SecurityAuditor(url)
                    result = auditor.scan()
                    self.send_json(200, result)
                else:
                    self.send_json(400, {"error": "URL is required"})
            except:
                self.send_json(400, {"error": "Invalid JSON"})
        else:
            self.send_response(404)
            self.end_headers()
    
    def serve_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = self.get_html()
        self.wfile.write(html.encode())
    
    def handle_scan(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        url = params.get('url', [''])[0]
        if url:
            auditor = SecurityAuditor(url)
            result = auditor.scan()
            self.send_json(200, result)
        else:
            self.send_json(400, {"error": "URL parameter required"})
    
    def send_json(self, status, data):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def get_html(self):
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Web Security Auditor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0e1a 0%, #1a1f35 50%, #0d1528 100%);
            color: #e0e7ff;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid rgba(0, 212, 255, 0.1);
            margin-bottom: 40px;
        }
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #00d4ff, #7b2ffc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle { color: #8892b0; font-size: 1.1rem; margin-top: 10px; }
        .scan-section {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
        }
        .input-group {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
        }
        .url-input {
            flex: 1;
            padding: 14px 20px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        .url-input:focus {
            outline: none;
            border-color: #00d4ff;
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }
        .btn-primary {
            padding: 14px 32px;
            background: linear-gradient(135deg, #00d4ff, #7b2ffc);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 212, 255, 0.3);
        }
        .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 15px;
            text-align: center;
        }
        .summary-card .number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .summary-card .label { color: #8892b0; font-size: 0.9rem; }
        .risk-critical .number { color: #ff4757; }
        .risk-high .number { color: #ff6b6b; }
        .risk-medium .number { color: #ffa502; }
        .risk-low .number { color: #2ed573; }
        .detailed-results {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 25px;
        }
        .result-section { margin-bottom: 25px; }
        .result-section h3 {
            color: #00d4ff;
            font-size: 1.2rem;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        .result-item {
            padding: 12px 15px;
            margin-bottom: 10px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            border-left: 4px solid;
        }
        .result-item .item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        .result-item .item-name { font-weight: 600; }
        .severity {
            font-size: 0.8rem;
            padding: 2px 10px;
            border-radius: 12px;
            font-weight: 500;
        }
        .severity-CRITICAL { background: #ff4757; color: #fff; }
        .severity-HIGH { background: #ff6b6b; color: #fff; }
        .severity-MEDIUM { background: #ffa502; color: #fff; }
        .severity-LOW { background: #2ed573; color: #fff; }
        .result-item .description { color: #8892b0; font-size: 0.9rem; }
        .result-item .recommendation {
            margin-top: 8px;
            padding: 8px 12px;
            background: rgba(0, 212, 255, 0.05);
            border-radius: 6px;
            font-size: 0.9rem;
            color: #00d4ff;
        }
        .passed-header { border-left-color: #2ed573; }
        .passed-header .item-name { color: #2ed573; }
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .error-message {
            padding: 15px;
            background: rgba(255, 71, 87, 0.1);
            border: 1px solid rgba(255, 71, 87, 0.2);
            border-radius: 8px;
            color: #ff4757;
            margin: 10px 0;
        }
        @media (max-width: 768px) {
            h1 { font-size: 1.8rem; }
            .input-group { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Web Security Auditor</h1>
            <p class="subtitle">Lightweight Passive Security & Header Scanner</p>
        </header>
        <main>
            <div class="scan-section">
                <div class="input-group">
                    <input type="text" id="targetUrl" placeholder="Enter URL (e.g., https://example.com)" class="url-input">
                    <button id="scanBtn" class="btn-primary">
                        <span class="btn-text">Scan Now</span>
                        <span class="spinner" style="display: none;"></span>
                    </button>
                </div>
            </div>
            <div id="errorMessage" style="display: none;" class="error-message"></div>
            <div id="results" style="display: none;">
                <div class="summary-cards" id="summaryCards"></div>
                <div class="detailed-results" id="detailedResults"></div>
            </div>
        </main>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const targetUrl = document.getElementById('targetUrl');
            const scanBtn = document.getElementById('scanBtn');
            const results = document.getElementById('results');
            const summaryCards = document.getElementById('summaryCards');
            const detailedResults = document.getElementById('detailedResults');
            const errorMessage = document.getElementById('errorMessage');

            scanBtn.addEventListener('click', function() {
                const url = targetUrl.value.trim();
                if (!url) {
                    showError('Please enter a URL');
                    return;
                }
                performScan(url);
            });

            targetUrl.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') scanBtn.click();
            });

            async function performScan(url) {
                showLoading(true);
                results.style.display = 'none';
                hideError();

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await response.json();
                    showLoading(false);
                    if (data.error) {
                        showError('Error: ' + data.error);
                    } else {
                        displayResults(data);
                    }
                } catch (error) {
                    showLoading(false);
                    showError('Failed to connect to server. Make sure the server is running.');
                    console.error('Error:', error);
                }
            }

            function displayResults(report) {
                results.style.display = 'block';
                const summary = report.scan_summary || {};
                const riskLevel = summary.risk_level || 'LOW';
                
                summaryCards.innerHTML = `
                    <div class="summary-card risk-${riskLevel.toLowerCase()}">
                        <div class="number">${summary.missing_headers || 0}</div>
                        <div class="label">Missing Headers</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">${summary.disclosures_found || 0}</div>
                        <div class="label">Disclosures</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">${summary.cookie_issues || 0}</div>
                        <div class="label">Cookie Issues</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">${report.status_code || 'N/A'}</div>
                        <div class="label">HTTP Status</div>
                    </div>
                    <div class="summary-card risk-${riskLevel.toLowerCase()}">
                        <div class="number">${riskLevel}</div>
                        <div class="label">Risk Level</div>
                    </div>
                `;

                let html = '<div class="result-section"><h3>📋 Security Headers</h3>';
                
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

                if (report.cookie_issues && report.cookie_issues.length > 0) {
                    html += '<div class="result-section"><h3>🍪 Cookie Issues</h3>';
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

                detailedResults.innerHTML = html;
            }

            function showLoading(show) {
                scanBtn.disabled = show;
                if (show) {
                    scanBtn.querySelector('.btn-text').textContent = 'Scanning...';
                    scanBtn.querySelector('.spinner').style.display = 'inline-block';
                } else {
                    scanBtn.querySelector('.btn-text').textContent = 'Scan Now';
                    scanBtn.querySelector('.spinner').style.display = 'none';
                }
            }

            function showError(message) {
                errorMessage.style.display = 'block';
                errorMessage.textContent = message;
            }

            function hideError() {
                errorMessage.style.display = 'none';
            }
        });
    </script>
</body>
</html>
        """

def main():
    port = 8080
    server = HTTPServer(('localhost', port), WebHandler)
    print("=" * 50)
    print("  Web Security Auditor")
    print("=" * 50)
    print(f" Server running at: http://localhost:{port}")
    print(" Enter a URL to scan for security headers")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    webbrowser.open(f'http://localhost:{port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Shutting down server...")
        server.shutdown()

if __name__ == '__main__':
    main()
    