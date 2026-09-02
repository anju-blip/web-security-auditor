# 🛡️ Web Security Auditor

A lightweight, passive web security scanner that checks for missing security headers, cookie security flags, and information disclosure vulnerabilities.

## Features

- ✅ **Security Header Analysis** - Checks for CSP, HSTS, X-Frame-Options, and more
- 🍪 **Cookie Security** - Validates Secure, HttpOnly, and SameSite flags
- 📢 **Information Disclosure** - Detects server banners and technology stack exposure
- 📊 **Visual Reports** - Clean UI with risk assessment and recommendations
- 🔄 **Batch Scanning** - Scan multiple URLs at once
- 📱 **Responsive Design** - Works on desktop and mobile

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Requests library for HTTP analysis

## Installation

### Prerequisites
- Python 3.6+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/web-security-auditor.git
cd web-security-auditor