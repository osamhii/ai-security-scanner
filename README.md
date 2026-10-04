![CI Security Audit](https://github.com/osamhii/ai-security-scanner/actions/workflows/security-scan.yml/badge.svg)
# AI-Assisted SAST Scanner (CLI)

An automated static application security testing (SAST) command-line utility built in Python. The tool performs semantic vulnerability analysis on Python source files using the Google GenAI SDK, mapping defects directly to standardized Common Weakness Enumeration (CWE) classifications and enforcing schema-validated output.

## Features
- **Schema-Enforced Outputs:** Employs Pydantic structured data models to eliminate LLM parsing hallucinations and guarantee predictable JSON records.
- **Defensive CWE Mapping:** Detects common application security flaws including Command Injection (CWE-78), SQL Injection (CWE-89), Hardcoded Secrets (CWE-798), and Weak Cryptography (CWE-328).
- **High-Availability Engine:** Built-in exponential backoff and automated failover handling against transient upstream API pressure (503).
- **Rich Terminal Interface:** Visualizes security findings with prioritized severity badges, contextual risk assessments, and syntax-highlighted remediation patches.
- **CI/CD Automation:** Integrates with GitHub Actions to run automated security audits on pull requests and pushes.

## Setup & Installation

```bash
git clone [https://github.com/osamhii/ai-security-scanner.git](https://github.com/osamhii/ai-security-scanner.git)
cd ai-security-scanner
python -m venv venv
venv\Scripts\activate  # On Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the root directory:
```env
GOOGLE_API_KEY=your_gemini_api_key_here
```

## Usage

Audit an individual file:
```bash
python scanner.py samples/vulnerable.py
```

Audit an entire project directory recursively:
```bash
python scanner.py .
```
