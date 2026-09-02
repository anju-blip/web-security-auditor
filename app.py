#!/usr/bin/env python3
"""
Web Security Auditor - Flask Web Interface
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# Configure CORS properly
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})
# Recommended security headers and their security functions
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
        "recommendation": "Implement a strict CSP policy that restricts script sources."
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces secure (HTTPS) connections and prevents SSL stripping.",
        "recommendation": "Set with max-age=31536000 and includeSubDomains."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Protects against clickjacking by restricting framing permissions.",
        "recommendation": "Set to DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing.",
        "recommendation": "Set to 'nosniff'."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is included with requests.",
        "recommendation": "Set to 'no-referrer' or 'strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Restricts browser features and APIs.",
        "recommendation": "Restrict geolocation, camera, microphone, etc. as needed."
    },
}

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

class SecurityAuditor:
    def __init__(self, target_url: str, timeout: int = 10, user_agent: str = "WebSecurityAuditor/1.0"):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}
        self.findings = []
        self.response = None

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}"
        return url

    def _validate_url(self) -> bool:
        """Validate URL format and accessibility."""
        try:
            parsed = urlparse(self.target_url)
            return all([parsed.scheme, parsed.netloc])
        except:
            return False

    def scan(self) -> dict:
        """Performs HTTP request and evaluates security posture."""
        if not self._validate_url():
            return {
                "error": "Invalid URL format",
                "target": self.target_url,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

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
            # Make request with proper timeout and redirect handling
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
            self.response = response
            report["status_code"] = response.status_code
            resp_headers = response.headers

            # Store all headers for display
            report["headers_present"] = dict(resp_headers)

            # 1. Audit HTTP Security Headers
            missing_headers = []
            for header, meta in RECOMMENDED_HEADERS.items():
                if header not in resp_headers:
                    report["findings"].append({
                        "check": "Missing Security Header",
                        "item": header,
                        "severity": meta["severity"],
                        "description": meta["description"],
                        "recommendation": meta["recommendation"]
                    })
                    missing_headers.append(header)
                else:
                    report["passed_checks"].append({
                        "header": header,
                        "value": resp_headers[header],
                    })

            # 2. Check Information Disclosure Headers
            for disc_header in DISCLOSURE_HEADERS:
                if disc_header in resp_headers:
                    report["disclosures"].append({
                        "header": disc_header,
                        "value": resp_headers[disc_header],
                        "severity": "LOW",
                        "description": f"Exposes backend technology stack.",
                        "recommendation": f"Remove '{disc_header}' header from responses."
                    })

            # 3. Check Cookie Security Flags
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' flag - cookie can be transmitted over plain HTTP")
                if not cookie.has_nonstandard_attr("httponly") and not getattr(cookie, "_rest", {}).get("httponly"):
                    issues.append("Missing 'HttpOnly' flag - cookie accessible via JavaScript")
                
                samesite = getattr(cookie, "_rest", {}).get("samesite", None)
                if not samesite:
                    issues.append("Missing 'SameSite' attribute - potential CSRF exposure")

                if issues:
                    report["cookie_issues"].append({
                        "cookie_name": cookie.name,
                        "issues": issues,
                        "severity": "MEDIUM",
                        "recommendation": "Set Secure, HttpOnly, and SameSite attributes appropriately."
                    })

            # Generate summary
            report["scan_summary"] = {
                "total_headers_checked": len(RECOMMENDED_HEADERS),
                "missing_headers": len(missing_headers),
                "disclosures_found": len(report["disclosures"]),
                "cookie_issues": len(report["cookie_issues"]),
                "headers_present": len(report["passed_checks"]),
                "risk_level": self._calculate_risk_level(report)
            }

        except requests.exceptions.SSLError:
            report["findings"].append({
                "check": "TLS/SSL Error",
                "item": "Certificate Validation",
                "severity": "CRITICAL",
                "description": "Failed to establish a verified SSL/TLS handshake.",
                "recommendation": "Ensure valid SSL certificate is installed."
            })
        except requests.exceptions.ConnectionError:
            report["error"] = "Connection error - Unable to reach the target URL"
        except requests.exceptions.Timeout:
            report["error"] = "Request timeout - Server took too long to respond"
        except requests.exceptions.RequestException as e:
            report["error"] = f"Request failed: {str(e)}"

        return report

    def _calculate_risk_level(self, report: dict) -> str:
        """Calculate overall risk level based on findings."""
        severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        total_score = 0
        
        for finding in report["findings"]:
            total_score += severity_weights.get(finding["severity"], 0)
        
        for cookie in report["cookie_issues"]:
            total_score += severity_weights.get("MEDIUM", 2)
        
        if total_score >= 8:
            return "CRITICAL"
        elif total_score >= 5:
            return "HIGH"
        elif total_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    
    # Validate URL format
    if not re.match(r'^https?://', target_url):
        target_url = f'https://{target_url}'
    
    auditor = SecurityAuditor(target_url)
    report = auditor.scan()
    
    return jsonify(report)

@app.route('/api/batch-scan', methods=['POST'])
def batch_scan():
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    
    results = []
    for url in urls:
        if not url.strip():
            continue
        url = url.strip()
        if not re.match(r'^https?://', url):
            url = f'https://{url}'
        auditor = SecurityAuditor(url)
        report = auditor.scan()
        results.append(report)
    
    return jsonify({"results": results, "total_scanned": len(results)})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)