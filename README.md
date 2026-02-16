# 🔐 SQL Injection Analyser

A comprehensive Python security tool that detects SQL injection vulnerabilities by simulating attack vectors and mapping findings against OWASP principles.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

⚠️ **EDUCATIONAL USE ONLY** - Only test on applications you own or have explicit permission to test.

---

## 📋 Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Vulnerability Types Detected](#vulnerability-types-detected)
- [OWASP Mapping](#owasp-mapping)
- [Examples](#examples)
- [Report Samples](#report-samples)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## ✨ Features

- **🔍 Comprehensive Detection**
  - Error-based SQL injection
  - Union-based SQL injection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Tautology-based injections

- **📊 Intelligent Analysis**
  - Automatic injection point identification
  - Response comparison and anomaly detection
  - Database fingerprinting
  - Data leakage detection
  - Severity scoring per finding

- **📝 Professional Reporting**
  - Detailed Markdown security audit reports
  - JSON export for CI/CD integration
  - OWASP Top 10 mapping
  - Remediation recommendations
  - Evidence documentation

- **🎯 User-Friendly**
  - Simple CLI interface
  - Configurable payload testing
  - Timeout controls
  - Real-time progress updates

---

## 🔬 How It Works

The SQL Injection Analyser follows a systematic approach:

```
┌─────────────────────────────────────────────────────────────┐
│  1. Input Analysis                                          │
│     └─ Monitors user inputs for unsafe SQL patterns       │
│     └─ Identifies potential injection points              │
├─────────────────────────────────────────────────────────────┤
│  2. Payload Simulation                                      │
│     └─ Injects tautologies and UNION-based payloads       │
│     └─ Tests error-based, time-based, and boolean attacks │
├─────────────────────────────────────────────────────────────┤
│  3. Response Evaluation                                     │
│     └─ Checks for error messages and data leaks           │
│     └─ Compares response times and content changes        │
├─────────────────────────────────────────────────────────────┤
│  4. Vulnerability Mapping                                   │
│     └─ Aligns findings with OWASP A03: Injection          │
│     └─ Assigns severity and confidence scores             │
├─────────────────────────────────────────────────────────────┤
│  5. Report Generation                                       │
│     └─ Creates structured audit report                    │
│     └─ Provides mitigation guidance                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/SQL-Injection-Analyser.git
cd SQL-Injection-Analyser

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

---

## 💻 Usage

### Basic Usage

```bash
# Test a GET parameter
python main.py --url http://example.com/page?id=1

# Test with POST data
python main.py --url http://example.com/login --post "username=admin&password=pass"

# Limit number of payloads (faster testing)
python main.py --url http://example.com/search?q=test --max-payloads 20

# Custom output file
python main.py --url http://example.com/page?id=1 --output my_report.md

# JSON format output
python main.py --url http://example.com/page?id=1 --format json

# Adjust timeout
python main.py --url http://example.com/page?id=1 --timeout 15
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target URL to test (required) | - |
| `--post` | POST data (format: "param1=val1&param2=val2") | None |
| `--max-payloads` | Maximum payloads to test per parameter | All |
| `--timeout` | Request timeout in seconds | 10 |
| `--output` | Output report filename | Auto-generated |
| `--format` | Report format (markdown/json) | markdown |
| `--no-report` | Skip saving report (print summary only) | False |

---

## 📂 Project Structure

```
SQL-Injection-Analyser/
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
│
├── scanner/                         # Core scanning modules
│   ├── __init__.py
│   ├── input_analyser.py           # Input analysis & injection point detection
│   ├── payload_injector.py         # Payload injection engine
│   ├── response_parser.py          # Response analysis & vulnerability detection
│   └── report_generator.py         # Security audit report generation
│
├── payloads/                        # Attack payloads
│   └── sql_payloads.txt            # SQL injection payload database
│
├── reports/                         # Generated reports (auto-created)
│   └── security_audit_report_*.md
│
└── tests/                           # Unit tests (future)
    └── test_scanner.py
```

---

## 🎯 Vulnerability Types Detected

### 1. Error-Based SQL Injection
- Triggers database errors to extract information
- Detects error messages from MySQL, PostgreSQL, MSSQL, Oracle, SQLite

### 2. Union-Based SQL Injection
- Uses UNION operator to combine query results
- Extracts data from other tables

### 3. Boolean-Based Blind SQL Injection
- Infers information by observing response differences
- No direct error messages needed

### 4. Time-Based Blind SQL Injection
- Uses database delay functions (SLEEP, WAITFOR)
- Detects vulnerabilities through response timing

### 5. Tautology-Based Injection
- Always-true conditions (e.g., `' OR '1'='1`)
- Bypasses authentication and filtering

---

## 🛡️ OWASP Mapping

This tool maps findings to:

### OWASP Top 10 2021: **A03:2021 – Injection**

**Description:** Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.

**Risk Factors:**
- **Prevalence:** Common
- **Detectability:** Easy
- **Impact:** Severe

**CWE Mapping:**
- CWE-89: SQL Injection
- CWE-564: SQL Injection: Hibernate
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

---

## 📚 Examples

### Example 1: Testing a Search Page

```bash
python main.py --url "http://example.com/search?q=test&category=all"
```

**Output:**
```
======================================================================
SQL INJECTION ANALYSER
======================================================================

Target URL: http://example.com/search?q=test&category=all
Scan Start Time: 2026-02-10 12:30:45

======================================================================

[*] Step 1: Identifying injection points...
[+] Found 2 potential injection points

[*] Step 2: Getting baseline response...
[+] Baseline response captured

[*] Step 3: Testing injection points...

[*] Testing injection point 1/2
    Type: GET
    Parameter: q
    [!] VULNERABILITY FOUND!
        Type: Error-Based SQLi
        Severity: CRITICAL
        Payload: ' OR '1'='1

[*] Testing injection point 2/2
    Type: GET
    Parameter: category
    ...

[*] Step 4: Generating security audit report...

======================================================================
SQL INJECTION SCAN SUMMARY
======================================================================

Target: http://example.com/search?q=test&category=all
Total Tests: 150
Vulnerabilities Found: 2

Vulnerabilities by Severity:
  🔴 CRITICAL: 1
  🟠 HIGH: 1

======================================================================

[+] Report saved to: reports/security_audit_report_20260210_123045.md
```

### Example 2: Testing Login Form

```bash
python main.py --url "http://example.com/login" \
    --post "username=admin&password=pass123" \
    --max-payloads 50
```

---

## 📄 Report Samples

### Markdown Report Structure

```markdown
# SQL Injection Security Audit Report

## Executive Summary
- Target URL
- Total tests performed
- Vulnerabilities found
- Severity breakdown

## Scan Details
- Scan timestamps
- Duration
- Injection points tested

## Vulnerability Findings
- Detailed vulnerability listings
- Evidence for each finding
- Confidence levels

## OWASP Top 10 Mapping
- A03:2021 – Injection mapping
- CWE references

## Remediation Recommendations
- Immediate actions required
- Code examples (good vs bad)
- Best practices

## Detailed Findings
- Step-by-step evidence
- Payloads used
- Response analysis
```

---

## 🔧 Advanced Configuration

### Custom Payloads

You can modify `payloads/sql_payloads.txt` to add your own payloads:

```
# Custom payload
' OR 1=1 LIMIT 1--
'; SELECT * FROM users--
```

### Integration with CI/CD

```yaml
# Example GitHub Actions workflow
- name: SQL Injection Scan
  run: |
    python main.py --url ${{ secrets.TEST_URL }} \
      --format json \
      --output scan_results.json
```

---

## ⚠️ Disclaimer

**IMPORTANT:** This tool is designed for **educational purposes** and **authorized security testing** only.

- ✅ **DO**: Use on your own applications
- ✅ **DO**: Use with explicit written permission
- ✅ **DO**: Use for learning about web security
- ❌ **DON'T**: Use on applications you don't own
- ❌ **DON'T**: Use without permission
- ❌ **DON'T**: Use for malicious purposes

**Unauthorized testing of web applications is illegal and punishable by law.**

The authors and contributors are not responsible for any misuse or damage caused by this tool.

---

## 🛠️ Future Enhancements

- [ ] Automated form discovery
- [ ] Advanced blind SQLi timing analysis
- [ ] NoSQL injection detection
- [ ] CI/CD pipeline integration
- [ ] Web dashboard visualization
- [ ] Multi-threading support
- [ ] Custom vulnerability plugins
- [ ] Integration with Burp Suite/OWASP ZAP

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Educational Use Only** - This tool is provided for educational purposes and authorized security testing.

---

## 📧 Contact

For questions, suggestions, or security concerns:

- **GitHub Issues:** [Create an issue](https://github.com/yourusername/SQL-Injection-Analyser/issues)
- **Email:** your.email@example.com

---

## 🙏 Acknowledgments

- OWASP Foundation for security guidelines
- Web security research community
- All contributors to this project

---

<div align="center">

**Made with ❤️ for Web Security Education**

[⬆ Back to Top](#-sql-injection-analyser)

</div>
