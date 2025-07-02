import typer
from typing import Optional
import re
import csv
import sys
import os

app = typer.Typer(help="Blue Team CLI Toolkit: Parse logs, lookup IOCs, generate IR playbooks, and trigger test alerts.")

# --- Log Parser Logic (from log_parser.py) ---
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

def load_iocs(iocfile: Optional[str]):
    iocs = set()
    if iocfile:
        if iocfile.endswith('.csv'):
            with open(iocfile, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    for cell in row:
                        iocs.add(cell.strip())
        else:
            with open(iocfile) as f:
                for line in f:
                    ioc = line.strip()
                    if ioc:
                        iocs.add(ioc)
    return iocs

def load_regex_patterns(regexfile: Optional[str]):
    patterns = []
    if regexfile:
        with open(regexfile) as f:
            for line in f:
                pattern = line.strip()
                if pattern:
                    try:
                        patterns.append(re.compile(pattern))
                    except re.error as e:
                        print(f"[!] Invalid regex skipped: {pattern} ({e})", file=sys.stderr)
    return patterns

def extract_indicators(line: str):
    indicators = {
        'ip': re.findall(IP_REGEX, line),
        'domain': re.findall(DOMAIN_REGEX, line),
        'hash': re.findall(HASH_REGEX, line),
        'email': re.findall(EMAIL_REGEX, line),
    }
    return indicators

def parse_log(logfile: str, iocs, regex_patterns, output: Optional[str]):
    results = []
    with open(logfile) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip('\n')
            indicators = extract_indicators(line)
            matches = []
            for ind_type, values in indicators.items():
                for val in values:
                    if val in iocs:
                        matches.append((ind_type, val, 'IOC'))
            for pattern in regex_patterns:
                for match in pattern.findall(line):
                    matches.append(('regex', match, 'Pattern'))
            if matches:
                for ind_type, val, match_type in matches:
                    results.append({
                        'line': lineno,
                        'indicator_type': ind_type,
                        'indicator': val,
                        'match_type': match_type,
                        'log': line
                    })
                typer.echo(f"[!] Line {lineno}: {line}")
                for ind_type, val, match_type in matches:
                    typer.echo(f"    -> {match_type} match: {ind_type} = {val}")
    if output:
        with open(output, 'w', newline='') as csvfile:
            fieldnames = ['line', 'indicator_type', 'indicator', 'match_type', 'log']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        typer.echo(f"\n[+] Results written to {output}")

@app.command()
def parse_logs(
    log_file: str = typer.Argument(..., help="Path to log file"),
    ioc_file: Optional[str] = typer.Option(None, help="Path to IOC file (TXT or CSV)"),
    regex_file: Optional[str] = typer.Option(None, help="Path to regex pattern file (one per line)"),
    output: Optional[str] = typer.Option(None, help="CSV output file (optional)")
):
    """Parse logs from a file and print summary."""
    iocs = load_iocs(ioc_file)
    regex_patterns = load_regex_patterns(regex_file)
    parse_log(log_file, iocs, regex_patterns, output)

# --- IR Playbook Generator Logic ---
PLAYBOOKS = {
    "phishing": """## 🛡️ Phishing Incident Response Checklist\n\n1. **Report & Contain**\n   - Notify IT/Security Team immediately\n   - Isolate affected user/email\n\n2. **Investigate**\n   - Review email headers and links\n   - Identify payloads or URLs\n   - Check user activity logs\n\n3. **Remediate**\n   - Reset affected user credentials\n   - Block malicious domains/IPs\n   - Scan affected endpoints\n\n4. **Communicate**\n   - Inform leadership & legal if needed\n   - Notify impacted users\n\n5. **Recover & Review**\n   - Re-enable affected services\n   - Document root cause\n   - Conduct phishing awareness training\n""",
    "ransomware": """## 🔒 Ransomware Incident Response Checklist\n\n1. **Detect & Isolate**\n   - Disconnect affected systems from network\n   - Disable Wi-Fi and Bluetooth\n\n2. **Assess & Notify**\n   - Identify ransomware strain if possible\n   - Notify internal stakeholders & legal\n\n3. **Preserve Evidence**\n   - Do not delete encrypted files\n   - Take memory and disk snapshots\n\n4. **Eradicate & Recover**\n   - Remove ransomware binaries\n   - Restore from clean backups\n\n5. **Post-Mortem**\n   - Update detection rules & patching\n   - Document lessons learned\n""",
    "default": """## 🚨 Incident Response Checklist\n\n1. Identify and categorize the incident.\n2. Contain the threat and prevent spread.\n3. Collect evidence and logs.\n4. Remediate the issue.\n5. Recover affected systems.\n6. Perform post-incident review."""
}

@app.command()
def generate_ir_playbook(incident_type: str = typer.Argument(..., help="Incident type (e.g., phishing, ransomware)")):
    """Generate an incident response playbook for a given incident type."""
    key = incident_type.strip().lower()
    playbook = PLAYBOOKS.get(key, PLAYBOOKS["default"])
    typer.echo(playbook)

@app.command()
def lookup_ioc(ioc: str, ioc_type: Optional[str] = typer.Option(None, help="Type of IOC: ip, domain, hash, etc.")):
    """Lookup an IOC (IP, domain, hash, etc.) using public threat intel sources."""
    typer.echo(f"[lookup_ioc] Looking up IOC: {ioc} (type: {ioc_type}) (stub)")

@app.command()
def trigger_test_alert(alert_type: str = typer.Option("b64_powershell", help="Type of test alert to trigger.")):
    """Trigger a test alert (e.g., simulate base64 PowerShell execution)."""
    typer.echo(f"[trigger_test_alert] Triggering test alert: {alert_type} (stub)")

if __name__ == "__main__":
    app() 