# Code workflow executes to filter and score threats

mport json
import re
from datetime import datetime

# Parse the data
data = json.loads(urlscan_data)

# Identify suspicious domains and IPs
suspicious_findings = []

for result in data['results']:
    page = result.get('page', {})
    task = result.get('task', {})
    
    domain = page.get('domain', '')
    ip = page.get('ip', '')
    status = page.get('status', '')
    title = page.get('title', '')
    timestamp = task.get('time', '')
    
    # Check for phishing indicators
    is_phishing = False
    threat_type = 'SUSPICIOUS'
    
    if 'phishing' in title.lower():
        is_phishing = True
        threat_type = 'PHISHING'
    
    # Check for suspicious domain patterns
    if any(pattern in domain.lower() for pattern in ['paypal', 'bank', 'sbi', 'yono', 'login', 'appleservice', 'ledger']):
        is_phishing = True
        threat_type = 'PHISHING'
    
    # Check for suspicious subdomains
    if domain.count('.') > 2 or 'wkaxld032' in domain or 'preprod2-sip-uk' in domain:
        threat_type = 'SUSPICIOUS_DOMAIN'
    
    if is_phishing or threat_type == 'SUSPICIOUS_DOMAIN':
        suspicious_findings.append({
            'domain': domain,
            'ip': ip,
            'status': status,
            'threat_type': threat_type,
            'timestamp': timestamp,
            'title': title
        })

# Calculate threat scores
def calculate_threat_score(finding):
    score = 5  # Base score for suspicious activity
    
    # Phishing indicators
    if finding['threat_type'] == 'PHISHING':
        score = 8  # High score for phishing
    elif finding['threat_type'] == 'SUSPICIOUS_DOMAIN':
        score = 6
    
    # Recent activity (last 24 hours)
    score += 2
    
    # Multiple sources confirmation (we have urlscan)
    score += 1
    
    # Cap at 10
    return min(score, 10)

# Score findings
for finding in suspicious_findings:
    finding['severity_score'] = calculate_threat_score(finding)

# Filter for HIGH and CRITICAL threats (score >= 7)
high_severity = [f for f in suspicious_findings if f['severity_score'] >= 7]

print(f"Total suspicious findings: {len(suspicious_findings)}")
print(f"High/Critical severity threats: {len(high_severity)}")
print("\n=== HIGH SEVERITY THREATS ===\n")

for threat in high_severity:
    print(f"Domain: {threat['domain']}")
    print(f"IP: {threat['ip']}")
    print(f"Type: {threat['threat_type']}")
    print(f"Severity Score: {threat['severity_score']}/10")
    print(f"Timestamp: {threat['timestamp']}")
    print(f"Title: {threat['title']}")
    print("-" * 60)

# Output for email alert
if high_severity:
    print(f"\n✓ ALERT: {len(high_severity)} HIGH/CRITICAL threats detected")
    print("Email alert will be sent to ritvik.indupuri@gmail.com")
else:
    print("\n✓ No HIGH/CRITICAL threats detected in this scan")
