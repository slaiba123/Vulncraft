# VulnCraft


**Educational Payload Generator Framework**

Developed by **ITSOLERA – Theta Team** | Offensive Security & Penetration Testing Internship


</div>

---
## Overview
A Python based CLI tool that generates annotated, non-executing payload templates for XSS, 
SQLi, and command-injection educational labs, with context-aware variants, 
encoding/obfuscation demonstrations, defensive notes, and export options (JSON / .txt / CLI).

### A) XSS Module
It demonstrates how attackers attempt Cross-Site Scripting (XSS) in different contexts (HTML, attributes, JavaScript, DOM) and how security controls such as output encoding, CSP, and input validation mitigate these risks — strictly for academic learning and defensive research.

### B) SQL Injection Module
It demonstrates how attackers attempt SQLi attacks in web applications and how security controls (WAFs, input validation, filters) respond — strictly for **academic learning and defensive research.  

### C) Command Injection Module
This module demonstrates how insecure system command construction may introduce vulnerabilities and how defensive controls should be applied.

##  Key Features

### A) XSS Module

- Generates context-aware, annotated XSS templates
  - Reflected, Stored, and DOM-based patterns
  - HTML, Attribute, and JavaScript contexts
  
- Demonstrates encoding and obfuscation techniques for defensive awareness (URL, Base64, HTML entity, Hex, case variation, comment insertion)
  
- Each payload includes comprehensive documentation:

```yaml
- id: xss-ref-001                          # Unique identifier
  context: html                            # Injection context
  type: reflected                          # XSS type
  payload: "<script>alert('XSS')</script>" # Actual payload
  payload_label: "⚠️ REFERENCE PATTERN"    # Safety warning
  trigger_type: auto-executing             # Execution type
  explanation: "Classic reflected XSS..."  # How it works
  
  # Security Classification
  owasp_category: "A03:2021 - Injection"
  cwe_id: "CWE-79"
  risk_level: high
  cvss_base: 6.1
  attack_vector: network
  
  # Traditional Defenses
  defensive_notes: "HTML encode all user output..."
  
  # Modern Mitigations (2025+)
  modern_mitigations:
    - technique: "Content Security Policy with Nonces"
      implementation: "script-src 'nonce-{random}'"
      effectiveness: "Blocks inline scripts"
    - technique: "Trusted Types API"
      implementation: "Enable Trusted Types policy"
      effectiveness: "Prevents DOM XSS"
```

### B) SQL Injection Module

- Generates educational SQLi template patterns
  - Error-based
  - Union-based
  - Blind (conceptual)

- Supports multiple database environments:
  - MySQL
  - PostgreSQL
  - MSSQL

- Demonstrates filter evasion concepts for defensive study (encoding, whitespace manipulation, comment insertion)

- Includes metadata for each template:
  - ID,
  - Type
  - Database  
  - Description
  - Bypass logic
  - Defensive notes

### Command Injection Module

- Generates safe, non-executing command-injection templates

- Supports
  - Linux shell environment
  - Windows shell environments

- C) Includes metadata for every payload:
  - ID
  - OS
  - payload
  - explanation
  - defensive notes
 
### Outputs in multiple formats:
  - CLI (console)
  - JSON (`output/output.json`)
  - YAML (`output/output.yaml`)
  - TXT (`output/output.txt`)
    


##  Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/slaiba123/Vulncraft.git
cd Vulncraft

# Install dependencies
pip install -r requirements.txt


```

### Dependencies

```
rich:  A Python library for rich text formatting, beautiful terminal output, tables, progress 
bars, and tracebacks. 
pyfiglet: A Python library that generates ASCII art text banners using FIGlet fonts. 
pyYAML: A Python library for parsing and generating YAML configuration files in Python.

```
### Payload Templates (YAML-Based): 
  - The tool uses a centralized YAML template system to define educational and safe payload examples for all supported modules. These templates are stored as standalone files and loaded dynamically at runtime. 
  - Template files:  
    - xss_templates.yaml 
    - sqli_templates.yaml 
    - Cmdinj_templates.yaml 
  - Each template file contains structured payload definitions designed for security education, testing awareness, and defensive understanding. All templates must remain safe, minimal, and non-destructive. 
 - General Template Rules: 
    - Every entry must include a unique id. 
    - Payloads must be demonstration-safe and must not contain destructive or real exploitation logic. 
    - Templates must focus on illustrating vulnerability mechanics rather than bypassing protections. 
    - Each payload must include an explanation and defensive guidance. 
    - Templates must remain database-, context-, or OS-aware depending on module type. 
    - Raw or unsafe examples must not be included in default distributions.
---

##  Usage
### 1. Generate Payloads by Module

### A) XSS Module
```bash
# All reflected XSS payloads
python payload_gen.py --Module xss --Type reflected

# All stored XSS payloads
python payload_gen.py --Module xss --Type stored

# All DOM-based XSS payloads
python payload_gen.py --Module xss --Type dom
```

### B) SQL Injection Module
```bash
# All SQL Injection Types for MySQL
python VulnCraft.py --Module sqli --db mysql

# Generate With Encoding (All)
python VulnCraft.py --Module sqli --db mysql --Encode all

# - With Obfuscation + Encoding + YAML
python VulnCraft.py --Module sqli --db mysql --Obfuscate case --Encode all --Format yaml
```

### C) Command Injection Module
```bash
# Run Windows templates
python VulnCraft.py -m cmdinj -t windows --Explain

# Run Linux templates
python VulnCraft.py -m cmdinj -t linux --Explain

```

### 2. Encoding Transformations

```bash
# URL encode payload
python VulnCraft.py --Module xss --id xss-ref-001 --Encode url
# Output: %3Cscript%3Ealert('XSS')%3C/script%3E

# Base64 encode payload
python VulnCraft.py --Module xss --id xss-ref-001 --Encode base64
# Output: PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=

# Hex encode payload
python VulnCraft.py --Module xss --id xss-ref-001 --Encode hex
# Output: \x3c\x73\x63\x72\x69\x70\x74...
```

### 3. Export to Tools

```bash
# Export to Burp Suite Intruder
python VulnCraft.py --Module xss --Export burp

# Export to OWASP ZAP fuzzer
python VulnCraft.py --Module xss --Export zap

# Export to Postman collection
python VulnCraft.py --Module xss --Export postman
```

### 4. Output Formats

```bash
# JSON format
python VulnCraft.py -m cmdinj -t linux --Export json

# Plain text format
python VulnCraft.py -m cmdinj -t windows --Export txt

# CSV format for spreadsheets
python VulnCraft.py --Module xss --Output csv > payloads.csv

# Export payload list for Burp
python VulnCraft.py -m cmdinj -t linux --Export burp

# Save export to file
python VulnCraft.py -m cmdinj -t linux --Export json --Out cmdinj.json


```

### 5. Advanced Filtering

```bash
# Reflected XSS in HTML context, URL encoded
python payload_gen.py --Module xss --Type reflected --context html --Encode url

# Critical risk payloads only
python payload_gen.py --Module xss --risk critical --Output json

# Auto-executing payloads
python payload_gen.py --Module xss --trigger auto-executing
```

---


##  Captures


### Available Flags

| Flag | Description |
|------|-------------|
| `-m, --Module ` | Module to generate (required) {xss,sqli,cmdinj} |
| `-t, --Type` | (XSS/SQLI/OS) type/category/os {reflected,stored,dom,linux,windows} |
| `--Context` | (XSS) context to target {html|attribute|js} |
| `--db` | (SQLi) target DB type {mysql|postgresql|mssql} |
| `--Encode` | encoding demonstration {none|url|base64|hex} |
| `--Obfuscate` | obfuscation demo {none|comment-insert|whitespace|mixed} |
| `--Explain` |Displays explanations and defensive notes with each payload |
| `--Export` | Selects export/output format {cli,json,txt,burp} |
| `--risk` | critical, high, medium, low | Filter by risk |
| `--trigger` | auto-executing, user-interaction | Filter by trigger type |
| `--Out FILE` | Saves exported output to a specified file |
| `--Version` | Shows VulnCraft version |
| `-h, --help` | -h, --help |

---

##  Project Structure

```
VulnCraft/
├─ CLI/                   # python package
│  ├─ cli.py                      # argparse / click definitions
│  ├─ modules/
│  │  ├─ xss.py                   # XSS template generator
│  │  ├─ sqli.py                  # SQLi template generator (simulation mode)
│  │  ├─ cmdinj.py                # Command injection pattern generator
│  ├─ encoders/
│  │  ├─ url.py
│  │  ├─ base64.py
│  │  ├─ hex.py
│  ├─ obfuscation/
│  │  ├─ case_variation.py
│  │  ├─ 
│  │  ├─ comment_insertion.py
│  │  ├─ whitespace_abuse.py
│  ├─ exporters/
│  │  ├─ json_export.py
│  │  ├─ txt_export.py
│  │  ├─ burp_export.py           # payload list format only
│  └─ templates/
│     ├─ xss_templates.yaml
│     ├─ sqli_templates.yaml
│     └─ cmdinj_templates.yaml
├─ README.md
└─ setup.py / pyproject.toml
```

---




---

## Sample Outputs

### A) XSS 


```bash
python payload_gen.py --module xss --output json
```

```json
{
  "payloads": [
    {
      "id": "xss-ref-001",
      "payload": "<script>alert('XSS')</script>",
      "context": "html",
      "type": "reflected",
      "risk_level": "high",
      "cvss_base": 6.1,
      "trigger_type": "auto-executing"
    }
  ]
}
```

### B) SQL Injection 



```json
{
  "id":"sqli-union-mysql-001",
  "db":"mysql",
  "category":"union-based",
  "template":"' UNION SELECT 1, 'example' -- ",
  "template_sanitized":"&#39; UNION SELECT 1, &#39;example&#39; -- ",
  "explanation":"Union-based SQLi: attacker appends UNION SELECT to combine attacker rows..."
}
```


### C) Command Injection 



```cli
ID: cmdinj-linux-001
OS: linux
Pattern: separator
Payload: ; [COMMAND]
Explanation: Demonstrates how command separators may allow unintended chained execution.
Defensive Notes: Avoid shell string concatenation and use safe execution APIs.


```

---


## 📚 Best Practices

### For Security Researchers

1. **Always Get Authorization**
   - Written permission from system owner
   - Defined scope and boundaries
   - Clear rules of engagement

2. **Use Isolated Environments**
   - Dedicated lab systems
   - Virtual machines or containers
   - No production data

3. **Document Everything**
   - Test methodology
   - Findings and evidence
   - Remediation recommendations

4. **Report Responsibly**
   - Follow disclosure timelines
   - Provide clear reproduction steps
   - Suggest fixes, not just problems

### For Developers

1. **Output Encoding**
   - Encode for context (HTML, JS, URL)
   - Use framework auto-escaping
   - Don't rely on input filtering alone

2. **Content Security Policy**
   - Implement strict CSP
   - Use nonces for inline scripts
   - Avoid `unsafe-inline` and `unsafe-eval`

3. **Trusted Types**
   - Enable Trusted Types policy
   - Use DOMPurify for sanitization
   - Avoid dangerous sinks (innerHTML, eval)

4. **Secure Cookies**
   - Set HttpOnly flag
   - Use Secure flag (HTTPS only)
   - Enable SameSite=Strict

### For SOC/Detection Teams

1. **Monitor for Patterns**
   - XSS payloads in logs
   - Unusual JavaScript execution
   - Data exfiltration attempts

2. **Risk Prioritization**
   - Critical: Auto-executing, high CVSS
   - High: Stored XSS, cookie theft
   - Medium: User-interaction required

3. **WAF Configuration**
   - Block common XSS patterns
   - Use signature-based detection
   - Implement rate limiting

---

## 📜 Ethical Guidelines

### Code of Conduct

This framework adheres to the [OWASP Code of Ethics](https://owasp.org/www-project-code-of-ethics/).

### Principles

1. **Authorized Testing Only**
   - Never test systems without permission
   - Respect scope boundaries
   - Stop if you cause harm

2. **Responsible Disclosure**
   - Report vulnerabilities privately
   - Give vendors time to patch
   - Don't weaponize findings

3. **Educational Focus**
   - Teach defensive security
   - Share knowledge freely
   - Build better defenses

4. **Legal Compliance**
   - Follow CFAA and local laws
   - Respect data privacy (GDPR, CCPA)
   - Don't enable malicious actors

### Consequences of Misuse

❌ Unauthorized use may result in:
- Criminal prosecution under CFAA
- Civil liability for damages
- Loss of security credentials
- Professional reputation damage

---

## 📖 Resources

### Learning Materials

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - XSS](https://portswigger.net/web-security/cross-site-scripting)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Google: Trusted Types](https://web.dev/trusted-types/)

### Tools & Libraries

- [DOMPurify](https://github.com/cure53/DOMPurify) - HTML sanitization
- [Burp Suite](https://portswigger.net/burp) - Web security testing
- [OWASP ZAP](https://www.zaproxy.org/) - Free security scanner
- [ModSecurity](https://github.com/SpiderLabs/ModSecurity) - Web Application Firewall

### Standards & Compliance

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

### Community

- [OWASP Slack](https://owasp.org/slack/invite)
- [r/netsec](https://www.reddit.com/r/netsec/)
- [BugCrowd Forum](https://forum.bugcrowd.com/)
- [HackerOne Community](https://www.hackerone.com/community)

---

## 📋 Changelog

### Version 2.1 (Current)

- ✅ Added 50 comprehensive XSS payloads
- ✅ Security classification (OWASP, CWE, CVSS)
- ✅ Trigger type analysis (auto-executing vs user-interaction)
- ✅ Modern mitigations (CSP, Trusted Types, secure cookies)
- ✅ CLI tool integration documentation
- ✅ Export formats (Burp, ZAP, Postman)
- ✅ Encoding demonstrations (Base64, Hex, etc.)
- ✅ Test environment requirements
- ✅ Statistics and compliance tracking


## 🙏 Acknowledgments

This framework builds upon the work of:

- **OWASP Foundation** - Web security standards and best practices
- **PortSwigger Research** - XSS attack taxonomy
- **Google Security Team** - Trusted Types specification
- **DOMPurify Team** - HTML sanitization research
- **Security Community** - Collective knowledge and responsible disclosure

---

## 📄 License

**Educational Use License**

This framework is provided for educational and authorized security testing purposes only. By using this framework, you agree to:

- Use only in authorized environments
- Comply with all applicable laws
- Not use for malicious purposes
- Credit OWASP and contributors

See [LICENSE](LICENSE) for full terms.





*Remember: With great power comes great responsibility. Use this knowledge to build a safer web.*



<div align="center">

**Made by ITSOLERA Theta Team**

⭐ Star this repository if you find it helpful!

</div>
