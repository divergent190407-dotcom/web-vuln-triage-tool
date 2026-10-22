# web-vuln-triage-tool

# Web Vulnerability Triage Tool

A semi-automated Python tool for discovering and triaging SQL injection vulnerabilities in web applications, combining automated detection with a human-verification workflow — the same way real pentest tools and analysts operate together.

## Problem Statement

Most beginner security scanners either do nothing more than fire a single payload and guess, or they go fully automated and report false positives without evidence. This tool is built around a different idea: **automation should collect evidence, not make verdicts.** It crawls a target, probes for SQL injection using three independent techniques, scores findings by confidence, and generates a manual verification checklist so a human analyst confirms real impact — mirroring how real-world penetration testing actually works (tool finding + analyst verification), rather than a blind "vulnerable: yes/no" scanner.

## Architecture


1. **Crawler** — authenticates to the target, parses forms and input fields, and brute-forces common hidden directories/files.
2. **Probe layer** — tests each input point with three independent SQL injection detection techniques:
   - **Error-based**: injects a breaking character and checks for SQL error signatures
   - **Boolean-based (blind)**: compares TRUE vs FALSE logical payloads for response differences
   - **Time-based (blind)**: measures response delay from a conditional `SLEEP()` payload
3. **Scoring engine** — aggregates results per parameter; 2+ independently confirmed techniques escalate confidence to "CONFIRMED."
4. **Human verification checklist** — generates the exact manual step (e.g., via Burp Suite) a human should perform to confirm each automated finding.
5. **Exploitation module** — once injection is confirmed, determines column count, identifies reflected columns, enumerates database tables via `information_schema`, and extracts real data to demonstrate actual impact.
6. **Reporting** — outputs both `report.json` (structured, machine-readable) and `report.md` (human-readable write-up).

## Usage

```bash
pip install -r requirements.txt
python3 crawler.py <target_url> [--username USERNAME] [--password PASSWORD]
```

Example:
```bash
python3 crawler.py http://127.0.0.1:8081
```

## Sample Output

See `report.md` / `report.json` for an example scan against [DVWA](https://github.com/digininja/DVWA) at low security, showing a confirmed SQL injection finding across all three detection techniques, with extracted table names as evidence of real impact.

## Tech Stack

- Python 3
- `requests` — HTTP session handling
- `beautifulsoup4` — HTML parsing

## Authorization & Ethics

**This tool is for authorized security testing only.** It is intended for use against systems you own, deliberately vulnerable training applications (DVWA, bWAPP, OWASP Juice Shop), or platforms like TryHackMe/HackTheBox where testing is explicitly permitted. Running this against any system without explicit, documented authorization is illegal. The sample scan included in this repo was run against a local DVWA instance.

## Roadmap

- [ ] Extend crawler to test all discovered forms/parameters, not just a single hardcoded target
- [ ] Add XSS and command injection probe modules
- [ ] WAF-evasion payload variants and detection accuracy comparison
- [ ] Threaded directory brute-forcing with a larger wordlist

## License

MIT
