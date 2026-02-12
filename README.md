# SQL-Injection-Analyser
A Python-based security analysis tool designed to detect and analyze SQL Injection vulnerabilities in web applications by simulating common attack vectors and mapping them against OWASP security principles.

**📌 Project Overview**

SQL Injection remains one of the most critical web security vulnerabilities. This project focuses on identifying unsafe input handling and vulnerable SQL query constructions by analyzing application behavior under simulated SQL injection attacks.

The tool helps developers and security analysts:
Detect potential SQL Injection points
Understand exploitation paths
Apply effective mitigation strategies

**🚀 Features**

🔍 Detection of common SQL Injection patterns
🧪 Simulation of real-world SQL injection payloads
🛡️ OWASP Top 10 aligned vulnerability checks
📊 Security audit report generation
⚠️ Identification of vulnerable parameters and endpoints
✅ Recommendations for secure query handling

**🧠 Methodology**

* Input Analysis
Monitors user-supplied inputs for unsafe SQL patterns.

* Payload Simulation
Injects crafted SQL payloads (e.g., tautologies, UNION-based attacks).

* Response Evaluation
Analyzes server responses for error messages, delays, or data leaks.

* Vulnerability Mapping
Matches detected issues with OWASP SQL Injection guidelines.

* Reporting
Generates a structured audit report with findings and mitigation steps.

**🛠️ Tech Stack**

Programming Language: Python
Security Frameworks: OWASP Top 10
Libraries & Tools:

* `requests`
* `re`
* `sqlite3` / `MySQL connector` (as applicable)
* `BeautifulSoup` (optional for form parsing)

**📂 Project Structure**

```
SQL-Injection-Analyser/
│
├── payloads/
│   └── sql_payloads.txt
│
├── scanner/
│   ├── input_analyser.py
│   ├── payload_injector.py
│   └── response_parser.py
│
├── reports/
│   └── security_audit_report.md
│
├── main.py
├── requirements.txt
└── README.md
```

**⚙️ Installation**

```
git clone https://github.com/your-username/sql-injection-analyser.git
cd sql-injection-analyser
pip install -r requirements.txt
```


**▶️ Usage**
`python main.py --url http://example.com/login`

**Optional arguments:**

`--url` : Target web application URL

`--method` : HTTP method (GET/POST)

`--output` : Generate audit report

**📄 Sample Output**

Vulnerable parameters detected

Type of SQL Injection (Error-based / Union-based / Blind)

Severity level

Suggested remediation steps

**🔐 Security Audit Report**

The tool generates a detailed audit report including:
Identified vulnerabilities
Exploitation techniques
Risk assessment
Preventive measures (prepared statements, input validation, ORM usage)

🧪 OWASP Alignment

This project aligns with:
OWASP Top 10 – A03: Injection
Secure coding and validation best practices
Defense-in-depth principles

**⚠️ Disclaimer**

This tool is intended for educational and ethical testing purposes only.
Use only on applications you own or have explicit permission to test.

**👩‍💻 Author**

Khadija Khan
Portfolio: https://khadijasportfolio.tiiny.site
LinkedIn: https://www.linkedin.com/in/khadija-khan-aaa3a4240/

**⭐ Future Enhancements**

* Automated form discovery
* Blind SQL injection timing analysis
* Dashboard-based visualization
* Integration with CI/CD pipelines
