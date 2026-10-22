# Vulnerability Triage Report

**Target:** http://127.0.0.1:8081/vulnerabilities/sqli/

**Scan date:** 2026-10-22 08:39:33

## Findings

- **[HIGH] error-based** on param `id`: Response length changed from error-breaking quote; SQL error text present
- **[HIGH] boolean-based** on param `id`: TRUE length 4550 vs FALSE length 4479
- **[HIGH] time-based** on param `id`: Response delayed 3.01s on SLEEP(3) payload

**Overall assessment:** CONFIRMED (3 technique(s) flagged)

## Manual Verification Checklist

- [ ] **error-based** on `id`: Manually browse to the page with a single quote in the parameter and confirm a real DB error renders (not just a generic error page).
- [ ] **boolean-based** on `id`: Manually test TRUE vs FALSE payloads in the browser/Burp and visually confirm different content is returned (not just length).
- [ ] **time-based** on `id`: Manually resend the SLEEP payload via Burp Repeater and confirm the delay is consistent across 2-3 attempts (rules out network jitter).
