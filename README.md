# Incident-Response-Playbook-CipherPay
A professional Incident Response Playbook for a fictional fintech company — CipherPay Ltd. Covers Brute Force, Phishing, and Data Breach incidents mapped to NIST SP 800-61, MITRE ATT&amp;CK, ISO 27001, GDPR and PCI-DSS frameworks.

#  Incident Response Playbook — CipherPay Ltd

**Document Type:** Incident Response Playbook
**Prepared By:** Alex Ojo — Junior SOC & GRC Analyst
**Version:** 1.0
**Date:** April 2026
**Classification:** Confidential
**Review Date:** October 2026

---

##  Executive Overview

This Incident Response Playbook has been developed for
CipherPay Ltd — a remote-first fintech startup providing
digital payment solutions across the UK, EU, and Africa.

Following the findings of the CipherPay Ltd Security Audit
(April 2026), which identified significant gaps in the
organisation's security posture, this playbook provides
structured response procedures for the three most critical
incident types facing CipherPay Ltd:

- **Brute Force & Credential Attacks**
- **Phishing Attacks**
- **Data Breach & Unauthorised Access**

This playbook is designed to ensure CipherPay Ltd can
detect, contain, eradicate, and recover from security
incidents effectively — minimising financial loss,
reputational damage, and regulatory penalties under
GDPR and PCI-DSS.

---

##  Purpose & Objectives

The objectives of this playbook are to:

- Provide clear, step-by-step response procedures for
  each incident type
- Define roles and responsibilities during an incident
- Minimise mean time to detect (MTTD) and mean time
  to respond (MTTR)
- Ensure compliance with GDPR 72-hour breach notification
  requirement
- Reduce the impact of security incidents on CipherPay
  Ltd's operations and customers
- Support continuous improvement through lessons learned

---

##  Governing Frameworks

This playbook is aligned with the following industry
standards and frameworks:

| Framework | Application |
|-----------|-------------|
| NIST SP 800-61 | Incident Response lifecycle |
| MITRE ATT&CK | Threat and technique mapping |
| ISO 27001 A.5.24 | Incident management requirements |
| GDPR Article 33 | 72-hour breach notification |
| PCI-DSS Req 12.10 | Incident response plan requirements |

---

##  Incident Response Lifecycle

This playbook follows the **NIST SP 800-61** Incident
Response lifecycle:

PREPARATION
└── Policies, tools, training, communication plans
DETECTION & ANALYSIS
└── Identify indicators, classify severity, alert team
CONTAINMENT
└── Short-term and long-term containment actions
ERADICATION
└── Remove threat, patch vulnerabilities, clean systems
RECOVERY
└── Restore systems, monitor, return to normal operations
LESSONS LEARNED
└── Post-incident review, documentation, improvements


---

##  Incident Severity Classification

All incidents must be classified using the following
severity levels:

| Severity | Level | Description | Response Time |
|----------|-------|-------------|---------------|
| 🔴 Critical | P1 | Active breach, data exfiltration, ransomware | Immediate — 1 hour |
| 🟠 High | P2 | Confirmed attack, system compromise | 4 hours |
| 🟡 Medium | P3 | Suspicious activity, potential threat | 24 hours |
| 🟢 Low | P4 | Minor policy violation, low risk event | 72 hours |

---

##  Incident Response Team

| Role | Responsibility |
|------|---------------|
| Incident Response Lead | Oversee response, make containment decisions |
| SOC Analyst | Detect, investigate, and document incidents |
| IT Administrator | Execute containment and recovery actions |
| Legal & Compliance | Manage regulatory notifications (GDPR, PCI-DSS) |
| Communications Lead | Handle internal and external communications |
| Data Protection Officer | Oversee data breach notifications |

---

##  Emergency Contact List

| Role | Contact Method | Response Time |
|------|---------------|---------------|
| Incident Response Lead | Phone & Email | 24/7 |
| SOC Analyst On-Call | Phone | 24/7 |
| IT Administrator | Phone & Slack | Business hours |
| Legal & Compliance | Email | Business hours |
| DPO | Phone & Email | 24/7 for P1/P2 |

---

##  Related Documents

| Document | Description |
|----------|-------------|
| [CipherPay Security Audit Report](https://github.com/alexojocyber/GRC-Security-Audit-CipherPay) | Full GRC audit and risk assessment |
| CipherPay Information Security Policy | Acceptable use and security guidelines |
| CipherPay Business Continuity Plan | Recovery procedures for major incidents |
| GDPR Data Breach Notification Template | Regulatory notification template |

---


##  Incident Playbook 1 — Brute Force & Credential Attack

---

###  Incident Overview

| Field | Details |
|-------|---------|
| **Incident Type** | Brute Force & Credential Attack |
| **Severity** | 🔴 Critical (P1) |
| **MITRE ATT&CK Tactic** | Credential Access |
| **MITRE ATT&CK Technique** | T1110 — Brute Force |
| **Sub-Technique** | T1110.001 — Password Guessing |
| **Affected Systems** | Web Application, SSH, AWS Console |
| **Regulatory Impact** | PCI-DSS Req 8.4, GDPR Article 32 |

---

###  Incident Description

A brute force attack occurs when an attacker repeatedly
attempts to guess a user's credentials by systematically
trying multiple username and password combinations.

For CipherPay Ltd this represents a critical threat given
the absence of MFA and the sensitivity of customer
payment data accessible through compromised accounts.

**Real World Context:**
This incident type was simulated and detected in the
CipherPay SOC Lab where 7 failed SSH login attempts
from IP address 192.168.0.168 targeting attackeruser
were detected and blocked using Fail2Ban within 5 minutes.

---

###  Indicators of Compromise (IOCs)

The following indicators suggest a brute force attack
is in progress or has occurred:

**Log-Based Indicators:**
- Multiple "Failed password" entries in `/var/log/auth.log`
- Repeated failed login attempts from a single IP address
- High volume of authentication failures in short timeframe
- Failed attempts across multiple usernames from same IP
- Account lockout events triggered repeatedly

**Network-Based Indicators:**
- Unusual spike in inbound traffic on port 22 (SSH)
- High volume of requests to login endpoints
- Traffic from known malicious IP ranges
- Repeated connection attempts from single source IP

**Splunk Detection Query:**
index=main sourcetype=syslog "Failed password"
| stats count by src_ip, user
| where count > 5
| sort - count

---

###  Attack Timeline Example

| Time | Event |
|------|-------|
| T+0:00 | First failed login attempt detected |
| T+0:02 | 3 failed attempts — Fail2Ban threshold reached |
| T+0:03 | Account lockout triggered |
| T+0:05 | SOC analyst alerted via Splunk dashboard |
| T+0:10 | Incident classified as P1 Critical |
| T+0:15 | Containment actions initiated |

---

###  Response Procedures

#### Phase 1 — Preparation 

**Before an incident occurs, ensure:**
- [ ] Fail2Ban is installed and configured on all Linux systems
- [ ] PAM faillock account lockout is enabled
- [ ] Splunk SIEM is monitoring authentication logs
- [ ] MFA is enforced across all systems
- [ ] Baseline of normal login behaviour is established
- [ ] SOC analyst on-call schedule is active
- [ ] Incident response team contacts are up to date

---

#### Phase 2 — Detection & Analysis 

**Step 1 — Identify failed login attempts:**
```bash
grep "Failed password" /var/log/auth.log
```

**Step 2 — Count total failed attempts:**
```bash
grep "Failed password" /var/log/auth.log | wc -l
```

**Step 3 — Identify source IP address:**
```bash
grep "Failed password" /var/log/auth.log | \
awk '{print $11}' | sort | uniq -c | sort -rn
```

**Step 4 — Check if account is locked:**
```bash
faillock --user username
```

**Step 5 — Run Splunk detection query:**
index=main sourcetype=syslog "Failed password"
| stats count by src_ip, user
| where count > 5

**Step 6 — Classify severity:**

| Condition | Severity |
|-----------|---------|
| 5+ failed attempts, no breach | 🟡 Medium P3 |
| 20+ failed attempts, ongoing | 🟠 High P2 |
| Successful login after failures | 🔴 Critical P1 |
| Payment data potentially accessed | 🔴 Critical P1 |

---

#### Phase 3 — Containment 

**Immediate Actions (0-30 minutes):**

- [ ] Block attacking IP address immediately:
```bash
sudo ufw deny from ATTACKER_IP to any
```

- [ ] Reset Fail2Ban to ensure IP is banned:
```bash
sudo fail2ban-client set sshd banip ATTACKER_IP
```

- [ ] Lock compromised user account:
```bash
sudo usermod -L username
```

- [ ] Force password reset on targeted accounts
- [ ] Revoke any active sessions from suspicious IP
- [ ] Notify Incident Response Lead immediately

**Short-Term Actions (30 minutes - 4 hours):**

- [ ] Review all accounts for signs of successful compromise
- [ ] Check AWS CloudTrail logs for unauthorised access
- [ ] Review payment portal access logs
- [ ] Enable enhanced logging across all systems
- [ ] Notify Legal & Compliance if breach is suspected

---

#### Phase 4 — Eradication 

- [ ] Identify and remove any backdoors or malware
- [ ] Reset passwords for all potentially compromised accounts
- [ ] Enforce MFA immediately if not already active
- [ ] Update Fail2Ban rules to lower threshold if needed
- [ ] Patch any vulnerabilities exploited during attack
- [ ] Review and update firewall rules
- [ ] Conduct full audit of user accounts and permissions

---

#### Phase 5 — Recovery 

- [ ] Unlock legitimate user accounts after verification:
```bash
sudo faillock --user username --reset
sudo usermod -U username
```

- [ ] Restore any affected services to normal operation
- [ ] Monitor authentication logs closely for 72 hours
- [ ] Verify Splunk alerts are functioning correctly
- [ ] Confirm Fail2Ban is active and configured correctly
- [ ] Communicate all-clear to incident response team
- [ ] Update stakeholders on resolution

---

#### Phase 6 — Lessons Learned 

**Post-Incident Review (within 72 hours):**

- [ ] Document full incident timeline
- [ ] Identify what detection controls worked
- [ ] Identify any gaps in detection or response
- [ ] Update Fail2Ban and PAM faillock thresholds if needed
- [ ] Review and improve Splunk detection queries
- [ ] Update this playbook with new findings
- [ ] Share findings with full incident response team

---

###  Incident Report Template
INCIDENT REPORT — BRUTE FORCE ATTACK
Date/Time Detected:
Detected By:
Severity Level:
Attacking IP Address:
Targeted Username(s):
Total Failed Attempts:
Successful Login: Yes / No
Systems Affected:
Containment Actions Taken:
Eradication Actions Taken:
Recovery Actions Taken:
GDPR Notification Required: Yes / No
PCI-DSS Notification Required: Yes / No
Lessons Learned:
Report Prepared By:
Date Closed:

---

###  MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Credential Access | T1110 — Brute Force | Repeated login attempts |
| Credential Access | T1110.001 — Password Guessing | Systematic password attempts |
| Defence Evasion | T1078 — Valid Accounts | Using compromised credentials |
| Initial Access | T1078.004 — Cloud Accounts | AWS console access attempts |

---

###  Preventive Controls

| Control | Implementation | Framework |
|---------|---------------|-----------|
| Multi-Factor Authentication | Google Authenticator / AWS MFA | NIST PR.AC-1 |
| Account Lockout | PAM faillock — 3 attempts | NIST PR.AC-7 |
| IP Blocking | Fail2Ban — auto ban after 3 fails | ISO 27001 A.8.5 |
| SIEM Monitoring | Splunk Cloud detection dashboard | NIST DE.CM-1 |
| Strong Password Policy | Minimum 12 characters | PCI-DSS Req 8.3 |

---

---

##  Incident Playbook 2 — Phishing Attack

---

###  Incident Overview

| Field | Details |
|-------|---------|
| **Incident Type** | Phishing Attack |
| **Severity** | 🟠 High (P2) |
| **MITRE ATT&CK Tactic** | Initial Access |
| **MITRE ATT&CK Technique** | T1566 — Phishing |
| **Sub-Technique** | T1566.001 — Spearphishing Attachment |
| **Affected Systems** | Email, Web Application, AWS Console |
| **Regulatory Impact** | GDPR Article 33, PCI-DSS Req 12.10 |

---

###  Incident Description

A phishing attack occurs when an attacker sends
fraudulent emails designed to trick CipherPay Ltd
employees into revealing credentials, clicking
malicious links, or downloading malware.

For CipherPay Ltd this represents a significant threat
given that 50 remote employees communicate primarily
through email and Slack — expanding the attack surface
considerably.

**Common Phishing Scenarios for CipherPay Ltd:**
- Fake IT support emails requesting password resets
- Spoofed AWS billing alerts with malicious links
- Fraudulent payment confirmation emails targeting
  finance team
- CEO impersonation emails requesting urgent wire
  transfers

---

###  Indicators of Compromise (IOCs)

**Email-Based Indicators:**
- Sender email domain does not match display name
- Urgent language pressuring immediate action
- Suspicious attachments — .exe, .zip, .docm files
- Links that do not match the displayed URL
- Poor grammar or unusual formatting
- Requests for credentials or sensitive information
- Emails sent outside business hours

**System-Based Indicators:**
- Unexpected login from new location or device
- New email forwarding rules created by user
- Unusual file downloads or attachments opened
- Credential changes shortly after email received
- New browser extensions installed unexpectedly
- Unusual outbound network traffic

**User-Reported Indicators:**
- Employee reports suspicious email received
- Employee reports clicking a suspicious link
- Employee reports entering credentials on unknown site

---

###  Phishing Attack Timeline Example

| Time | Event |
|------|-------|
| T+0:00 | Phishing email sent to CipherPay employee |
| T+0:30 | Employee clicks malicious link |
| T+0:32 | Employee enters credentials on fake login page |
| T+1:00 | Attacker uses stolen credentials to access AWS |
| T+2:00 | Employee reports suspicious email to SOC |
| T+2:05 | SOC analyst begins investigation |
| T+2:30 | Incident classified as P2 High |
| T+3:00 | Containment actions initiated |

---

###  Response Procedures

#### Phase 1 — Preparation 

**Before an incident occurs, ensure:**
- [ ] Email filtering and anti-phishing tools are active
- [ ] All employees have completed phishing awareness
  training
- [ ] Monthly phishing simulation exercises are running
- [ ] Clear process exists for reporting suspicious emails
- [ ] MFA is enforced to limit credential theft impact
- [ ] SOC monitoring is active on email and login systems
- [ ] Incident reporting channel is communicated to all staff

---

#### Phase 2 — Detection & Analysis 

**Step 1 — Collect the suspicious email:**
- Obtain full email headers from the recipient
- Do not delete the email — preserve as evidence
- Forward to SOC analyst for investigation

**Step 2 — Analyse email headers:**
- Check sender IP address against known malicious IPs
- Verify SPF, DKIM, and DMARC records
- Compare display name against actual sender domain

**Step 3 — Analyse suspicious links:**
- Do NOT click the link directly
- Use a sandbox tool like VirusTotal to check the URL:
  **virustotal.com**
- Check domain registration date — new domains are suspicious

**Step 4 — Check if credentials were compromised:**
- Review authentication logs for unusual logins:
```bash
grep "Accepted password" /var/log/auth.log | \
grep username
```

- Check AWS CloudTrail for unusual API calls
- Review Google Workspace login history

**Step 5 — Classify severity:**

| Condition | Severity |
|-----------|---------|
| Suspicious email reported, no action taken | 🟢 Low P4 |
| Employee clicked link, no credentials entered | 🟡 Medium P3 |
| Employee entered credentials on phishing site | 🟠 High P2 |
| Attacker accessed systems with stolen credentials | 🔴 Critical P1 |
| Payment data or customer PII accessed | 🔴 Critical P1 |

---

#### Phase 3 — Containment 

**Immediate Actions (0-30 minutes):**

- [ ] Isolate affected employee account immediately
- [ ] Reset compromised credentials:
```bash
sudo passwd username
```

- [ ] Revoke all active sessions for compromised account
- [ ] Block malicious sender domain in email gateway
- [ ] Block malicious URL at network firewall level
- [ ] Remove phishing email from all employee inboxes
- [ ] Notify all employees not to open similar emails
- [ ] Notify Incident Response Lead

**Short-Term Actions (30 minutes - 4 hours):**

- [ ] Conduct full review of compromised account activity
- [ ] Check if attacker created any new accounts or rules
- [ ] Review outbound email for signs of data exfiltration
- [ ] Check AWS IAM for unauthorised changes
- [ ] Determine if customer payment data was accessed
- [ ] Notify Legal & Compliance if breach suspected

---

#### Phase 4 — Eradication 

- [ ] Remove any malware installed via phishing attachment
- [ ] Delete any malicious email forwarding rules created
- [ ] Revoke any OAuth tokens granted to malicious apps
- [ ] Remove any unauthorised accounts created by attacker
- [ ] Reset passwords for all potentially affected accounts
- [ ] Enforce MFA on all accounts immediately
- [ ] Block attacker infrastructure at firewall level
- [ ] Conduct full malware scan on affected devices

---

#### Phase 5 — Recovery 

- [ ] Restore compromised accounts after full verification
- [ ] Re-enable employee access with new credentials
- [ ] Confirm MFA is active on all restored accounts
- [ ] Monitor restored accounts closely for 72 hours
- [ ] Run Splunk queries to detect any residual attacker
  activity:
index=main sourcetype=syslog
| search username=compromised_user
| table _time, action, src_ip, dest

- [ ] Communicate resolution to incident response team
- [ ] Assess whether GDPR notification is required

---

#### Phase 6 — Lessons Learned 

**Post-Incident Review (within 72 hours):**

- [ ] Document full incident timeline
- [ ] Identify how phishing email bypassed email filters
- [ ] Review employee phishing awareness training
- [ ] Conduct targeted phishing simulation for affected team
- [ ] Update email filtering rules based on attack patterns
- [ ] Review and strengthen MFA enforcement
- [ ] Update this playbook with new findings

---

###  Incident Report Template
INCIDENT REPORT — PHISHING ATTACK
Date/Time Detected:
Detected By:
Severity Level:
Phishing Email Subject:
Sender Email Address:
Malicious URL/Attachment:
Employees Affected:
Credentials Compromised: Yes / No
Systems Accessed by Attacker:
Customer Data Accessed: Yes / No
Containment Actions Taken:
Eradication Actions Taken:
Recovery Actions Taken:
GDPR 72hr Notification Required: Yes / No
PCI-DSS Notification Required: Yes / No
Lessons Learned:
Report Prepared By:
Date Closed:

---

###  MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1566 — Phishing | Fraudulent emails to gain access |
| Initial Access | T1566.001 — Spearphishing Attachment | Malicious email attachments |
| Credential Access | T1056 — Input Capture | Fake login pages stealing credentials |
| Collection | T1114 — Email Collection | Attacker accessing email after compromise |
| Exfiltration | T1048 — Exfiltration Over Web | Data sent to attacker infrastructure |

---

###  Preventive Controls

| Control | Implementation | Framework |
|---------|---------------|-----------|
| Email Filtering | Anti-phishing gateway | NIST PR.AT-1 |
| MFA Enforcement | Google Authenticator | NIST PR.AC-1 |
| Security Awareness Training | Quarterly phishing simulations | ISO 27001 A.6.3 |
| URL Filtering | Web gateway blocking malicious URLs | ISO 27001 A.8.23 |
| SIEM Monitoring | Splunk detecting unusual logins | NIST DE.CM-1 |
| DMARC/SPF/DKIM | Email authentication protocols | PCI-DSS Req 12.10 |

---

---

##  Incident Playbook 3 — Data Breach & Unauthorised Access

---

###  Incident Overview

| Field | Details |
|-------|---------|
| **Incident Type** | Data Breach & Unauthorised Access |
| **Severity** | 🔴 Critical (P1) |
| **MITRE ATT&CK Tactic** | Collection, Exfiltration |
| **MITRE ATT&CK Technique** | T1530 — Data from Cloud Storage |
| **Sub-Technique** | T1537 — Transfer Data to Cloud Account |
| **Affected Systems** | AWS S3, RDS Database, Payment Portal |
| **Regulatory Impact** | GDPR Article 33, PCI-DSS Req 3, 4, 12 |

---

###  Incident Description

A data breach occurs when an unauthorised party gains
access to CipherPay Ltd's sensitive data including
customer payment information, personal data, or
internal business data.

For CipherPay Ltd this represents the most severe
incident type given the company processes customer
payment card data and personal information subject
to PCI-DSS and GDPR regulations.

**A data breach at CipherPay Ltd could result in:**
- GDPR fines of up to £17.5M or 4% of global turnover
- PCI-DSS fines of up to $100,000 per month
- Loss of payment processing capability
- Severe reputational damage and customer loss
- Legal action from affected customers

**Common Breach Scenarios for CipherPay Ltd:**
- Misconfigured AWS S3 bucket exposing customer data
- Attacker using stolen credentials to access database
- SQL injection attack on payment portal
- Insider threat — employee exfiltrating customer data
- Ransomware encrypting and exfiltrating payment data

---

###  Indicators of Compromise (IOCs)

**System-Based Indicators:**
- Unusual large data downloads from AWS S3 or RDS
- Database queries returning unusually large result sets
- Unexpected outbound network traffic spikes
- New AWS IAM users or roles created without authorisation
- S3 bucket access logging showing unusual activity
- Database access from unexpected IP addresses
- Unusual API calls in AWS CloudTrail logs

**Application-Based Indicators:**
- Unusual number of records accessed in short timeframe
- SQL error messages appearing in application logs
- Unexpected changes to database schema or records
- New admin accounts created in payment portal
- Payment portal returning unusual error responses

**User-Based Indicators:**
- Employee accessing data outside normal working hours
- Employee downloading unusually large amounts of data
- Employee accessing data outside their normal scope
- Reports from customers of fraudulent transactions

---

###  Data Breach Timeline Example

| Time | Event |
|------|-------|
| T+0:00 | Attacker gains access via stolen credentials |
| T+0:15 | Attacker identifies misconfigured S3 bucket |
| T+0:30 | Attacker begins downloading customer payment data |
| T+1:00 | AWS CloudTrail alert triggered on unusual API calls |
| T+1:05 | Splunk alert fired on unusual data volume |
| T+1:10 | SOC analyst begins investigation |
| T+1:30 | Incident classified as P1 Critical |
| T+1:45 | Containment actions initiated |
| T+2:00 | Legal & Compliance notified |
| T+24:00 | GDPR notification assessment completed |
| T+72:00 | GDPR notification submitted if required |

---

###  Response Procedures

#### Phase 1 — Preparation 

**Before an incident occurs, ensure:**
- [ ] AWS S3 Block Public Access is enabled on all buckets
- [ ] AWS CloudTrail logging is active across all regions
- [ ] Splunk is ingesting AWS CloudTrail logs
- [ ] Database access logging is enabled on RDS
- [ ] DLP controls are in place to detect unusual data
  movement
- [ ] GDPR breach notification process is documented
- [ ] PCI-DSS incident response requirements are understood
- [ ] Legal & Compliance team is briefed on notification
  obligations
- [ ] Customer notification templates are prepared

---

#### Phase 2 — Detection & Analysis 

**Step 1 — Identify unusual data access in Splunk:**
index=aws sourcetype=cloudtrail
| search eventName=GetObject OR eventName=ListBucket
| stats count by userIdentity.arn, requestParameters.bucketName
| where count > 100
| sort - count

**Step 2 — Check AWS CloudTrail for suspicious API calls:**
index=aws sourcetype=cloudtrail
| search errorCode=AccessDenied OR
eventName=CreateUser OR
eventName=AttachUserPolicy
| table eventTime, userIdentity.arn,
eventName, sourceIPAddress

**Step 3 — Check for unusual S3 bucket access:**
index=aws sourcetype=s3access
| stats sum(bytes_sent) as total_bytes by requester
| where total_bytes > 1000000000
| sort - total_bytes

**Step 4 — Determine scope of breach:**
- What data was accessed?
- How many records were affected?
- Was payment card data (PAN) accessed?
- Was customer PII accessed?
- Is the breach ongoing or contained?

**Step 5 — Classify severity:**

| Condition | Severity |
|-----------|---------|
| Unauthorised access, no data exfiltration | 🟠 High P2 |
| Internal data accessed without authorisation | 🟠 High P2 |
| Customer PII accessed or exfiltrated | 🔴 Critical P1 |
| Payment card data accessed or exfiltrated | 🔴 Critical P1 |
| Ransomware detected on systems | 🔴 Critical P1 |

---

#### Phase 3 — Containment 

**Immediate Actions (0-60 minutes):**

- [ ] Revoke all access credentials of suspected attacker
- [ ] Disable compromised AWS IAM accounts immediately:
```bash
aws iam update-access-key \
--access-key-id ATTACKER_KEY \
--status Inactive
```

- [ ] Enable S3 Block Public Access on all buckets:
```bash
aws s3api put-public-access-block \
--bucket BUCKET_NAME \
--public-access-block-configuration \
"BlockPublicAcls=true, \
IgnorePublicAcls=true, \
BlockPublicPolicy=true, \
RestrictPublicBuckets=true"
```

- [ ] Isolate affected database from public access
- [ ] Block attacker IP at AWS Security Group level
- [ ] Preserve all logs as forensic evidence
- [ ] Do NOT delete any logs or modify affected systems
- [ ] Notify Incident Response Lead and Legal immediately

**Short-Term Actions (1-4 hours):**

- [ ] Conduct full audit of all AWS IAM permissions
- [ ] Review all active sessions and revoke suspicious ones
- [ ] Assess full scope of data accessed or exfiltrated
- [ ] Determine if breach is ongoing or contained
- [ ] Begin GDPR breach assessment with DPO
- [ ] Engage external forensics if needed

---

#### Phase 4 — Eradication 

- [ ] Remove all unauthorised AWS IAM users and roles
- [ ] Rotate all AWS access keys and secrets
- [ ] Reset all passwords across affected systems
- [ ] Enforce MFA on all AWS accounts immediately
- [ ] Patch any vulnerabilities exploited during breach
- [ ] Remediate misconfigured S3 buckets and RDS instances
- [ ] Conduct full malware scan if ransomware suspected
- [ ] Implement encryption on all data at rest:
  AES-256 for RDS, SSE-S3 for S3 buckets
- [ ] Deploy AWS WAF to protect payment portal

---

#### Phase 5 — Recovery 

- [ ] Restore systems from clean verified backups
- [ ] Verify data integrity before restoring to production
- [ ] Re-enable services with enhanced security controls
- [ ] Monitor all systems intensively for 7 days post
  incident
- [ ] Run enhanced Splunk detection queries:
index=aws sourcetype=cloudtrail
| search userIdentity.arn=* AND
eventName=GetObject
| timechart count by userIdentity.arn

- [ ] Communicate resolution to all stakeholders
- [ ] Complete all regulatory notifications

---

#### Phase 6 — Lessons Learned 

**Post-Incident Review (within 72 hours):**

- [ ] Document full incident timeline and scope
- [ ] Identify root cause of breach
- [ ] Quantify number of records and customers affected
- [ ] Review all AWS security configurations
- [ ] Assess effectiveness of detection and response
- [ ] Update security controls to prevent recurrence
- [ ] Update this playbook with new findings
- [ ] Share findings with board and leadership

---

###  Incident Report Template
INCIDENT REPORT — DATA BREACH
Date/Time Detected:
Detected By:
Severity Level:
Breach Vector:
Systems Affected:
Data Types Accessed:
Number of Records Affected:
Number of Customers Affected:
Payment Card Data Involved: Yes / No
PII Involved: Yes / No
Breach Ongoing: Yes / No
Containment Actions Taken:
Eradication Actions Taken:
Recovery Actions Taken:
GDPR 72hr Notification Required: Yes / No
GDPR Notification Submitted: Yes / No
PCI-DSS Notification Required: Yes / No
Regulatory Bodies Notified:
Customers Notified: Yes / No
Estimated Financial Impact:
Lessons Learned:
Report Prepared By:
Date Closed:

---

###  Regulatory Notification Requirements

**GDPR — Article 33:**

| Requirement | Details |
|-------------|---------|
| Notification deadline | 72 hours from awareness |
| Notify | ICO (UK) or relevant EU DPA |
| Content required | Nature of breach, data affected, measures taken |
| Customer notification | Required if high risk to individuals |

**PCI-DSS — Requirement 12.10:**

| Requirement | Details |
|-------------|---------|
| Notification deadline | Immediately upon confirmation |
| Notify | Payment card brands (Visa, Mastercard) |
| Notify | Acquiring bank |
| Forensic investigation | Required for card data breaches |

---

###  MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1078 — Valid Accounts | Using stolen credentials |
| Discovery | T1619 — Cloud Storage Discovery | Identifying S3 buckets |
| Collection | T1530 — Data from Cloud Storage | Accessing S3 data |
| Exfiltration | T1537 — Transfer to Cloud Account | Moving data externally |
| Impact | T1486 — Data Encrypted for Impact | Ransomware encryption |

---

###  Preventive Controls

| Control | Implementation | Framework |
|---------|---------------|-----------|
| S3 Block Public Access | AWS S3 security configuration | NIST PR.DS-1 |
| Data Encryption | AES-256 at rest, TLS 1.2+ in transit | PCI-DSS Req 3, 4 |
| AWS CloudTrail | Full API logging across all regions | NIST DE.CM-7 |
| MFA on AWS | IAM MFA enforcement | ISO 27001 A.8.5 |
| Least Privilege | IAM role-based access control | NIST PR.AC-4 |
| SIEM Monitoring | Splunk Cloud detection dashboard | NIST DE.AE-2 |
| DLP Controls | Data loss prevention tooling | ISO 27001 A.8.12 |

---

---

##  Communication Templates

---

### Overview

Effective communication during a security incident is
critical to maintaining trust, meeting regulatory
obligations, and coordinating response efforts.

This section provides ready-to-use communication
templates for CipherPay Ltd's incident response team
covering internal notifications, regulatory reporting,
and customer communications.

---

###  Template 1 — Internal Incident Alert

**Purpose:** Notify the internal incident response team
when an incident is detected.

**Send to:** Incident Response Lead, SOC Analyst,
IT Administrator, Legal & Compliance, DPO

---
SUBJECT: [URGENT] Security Incident Alert — [Incident Type]
— [Date/Time]
Hi Team,
A security incident has been detected and requires
immediate attention.
INCIDENT SUMMARY
Incident Type:      [Brute Force / Phishing / Data Breach]
Severity Level:     [P1 Critical / P2 High / P3 Medium]
Date/Time Detected: [DD/MM/YYYY HH:MM]
Detected By:        [Name / System]
Systems Affected:   [List affected systems]
CURRENT STATUS
[Brief description of what has happened so far and
current status of the incident]
IMMEDIATE ACTIONS REQUIRED
[List specific actions each team member needs to take]
NEXT UPDATE
Next update will be provided at: [Time]
Please acknowledge receipt of this message immediately.
[Your Name]
SOC Analyst — CipherPay Ltd

---

###  Template 2 — Management Escalation

**Purpose:** Escalate a P1 Critical incident to senior
leadership and the board.

**Send to:** CEO, CFO, Head of Legal, Board Members

---
SUBJECT: [CRITICAL] Security Incident Escalation —
Immediate Action Required — [Date]
Dear [Name],
I am writing to inform you of a critical security
incident currently affecting CipherPay Ltd that
requires your immediate awareness and decision-making.
INCIDENT OVERVIEW
Incident Type:      [Incident Type]
Severity:           CRITICAL — P1
Time Detected:      [DD/MM/YYYY HH:MM]
Current Status:     [Contained / Ongoing / Under Investigation]
BUSINESS IMPACT

[Describe impact on operations]
[Describe impact on customers]
[Describe potential financial impact]
[Describe regulatory implications]

ACTIONS TAKEN

[List containment actions already taken]
[List notifications already made]

DECISIONS REQUIRED

[List decisions that need leadership approval]
[e.g. Customer notification, external forensics,
regulatory notification]

REGULATORY OBLIGATIONS
GDPR Notification Required:    [Yes / No / Under Assessment]
GDPR Notification Deadline:    [72 hours from DD/MM/YYYY]
PCI-DSS Notification Required: [Yes / No / Under Assessment]
Next update will be provided at: [Time]
[Your Name]
Incident Response Lead — CipherPay Ltd

---

###  Template 3 — GDPR Regulatory Notification

**Purpose:** Notify the ICO (Information Commissioner's
Office) of a personal data breach within 72 hours.

**Send to:** ICO — report.breach@ico.org.uk

---
SUBJECT: Personal Data Breach Notification —
CipherPay Ltd — [Date]
To the Information Commissioner's Office,
CipherPay Ltd hereby notifies the ICO of a personal
data breach in accordance with Article 33 of the
UK GDPR.
ORGANISATION DETAILS
Organisation Name:  CipherPay Ltd
Registered Address: London, United Kingdom
DPO Name:           [DPO Name]
DPO Contact:        [DPO Email and Phone]
BREACH DETAILS
Date/Time of Breach:      [DD/MM/YYYY HH:MM]
Date/Time Discovered:     [DD/MM/YYYY HH:MM]
Date/Time of This Report: [DD/MM/YYYY HH:MM]
NATURE OF THE BREACH
[Describe what happened — e.g. unauthorised access
to customer database via compromised credentials]
CATEGORIES OF DATA AFFECTED
[ ] Names and contact information
[ ] Payment card data
[ ] Financial information
[ ] Authentication credentials
[ ] Other: [Specify]
NUMBER OF INDIVIDUALS AFFECTED
Approximate number of records: [Number]
Approximate number of individuals: [Number]
LIKELY CONSEQUENCES
[Describe the likely consequences of the breach
for affected individuals]
MEASURES TAKEN
[Describe containment, eradication, and recovery
measures taken or planned]
CUSTOMER NOTIFICATION
Customers notified: [Yes / No / Planned]
If planned, expected date: [DD/MM/YYYY]
Please do not hesitate to contact our DPO for
further information.
Yours sincerely,
[DPO Name]
Data Protection Officer — CipherPay Ltd
[Email] | [Phone]

---

###  Template 4 — Customer Notification

**Purpose:** Notify affected customers of a data breach
that may impact their personal or payment data.

**Send to:** All affected customers via email

---
SUBJECT: Important Security Notice — Your CipherPay
Account
Dear [Customer Name],
We are writing to inform you of a security incident
that may have affected your CipherPay account.
WHAT HAPPENED
On [Date], CipherPay Ltd became aware of a security
incident in which unauthorised access to our systems
may have affected some customer accounts.
WHAT INFORMATION WAS INVOLVED
The following types of information may have been
accessed:

[List specific data types affected]

WHAT WE HAVE DONE
Upon discovering this incident we immediately:

Contained the security breach
Launched a full investigation
Notified the relevant regulatory authorities
Strengthened our security controls

WHAT YOU SHOULD DO
We recommend you take the following steps immediately:

Change your CipherPay account password
Enable two-factor authentication on your account
Monitor your bank statements for unusual activity
Contact your bank if you notice any suspicious
transactions
Be alert to phishing emails claiming to be from
CipherPay

HOW TO CONTACT US
If you have any questions or concerns please contact
our dedicated incident support team:
Email:   security@cipherpay.com
Phone:   [Support number]
Hours:   Monday to Friday, 9am to 5pm GMT
We sincerely apologise for any concern or
inconvenience this may cause. The security of your
data is our highest priority and we are taking all
necessary steps to prevent this from happening again.
Yours sincerely,
[CEO Name]
Chief Executive Officer — CipherPay Ltd

---

###  Template 5 — All Staff Security Alert

**Purpose:** Notify all CipherPay Ltd employees of an
active incident and provide guidance on what to do.

**Send to:** All staff via email and Slack

---
SUBJECT: [SECURITY ALERT] Important Notice for All
CipherPay Staff
Hi Team,
Our security team is currently responding to a
security incident affecting CipherPay Ltd systems.
WHAT YOU NEED TO DO RIGHT NOW

Do NOT click any suspicious links or attachments
Do NOT share your login credentials with anyone
Report any suspicious emails to security@cipherpay.com
Log out of all systems if instructed by IT team
Do not discuss this incident on social media or
with external parties

WHAT NOT TO DO

Do not attempt to investigate the incident yourself
Do not delete any emails or files without instruction
Do not access systems unless cleared by IT team

We will provide updates as the situation develops.
If you have any questions contact the IT team
immediately.
Thank you for your cooperation.
[Incident Response Lead]
CipherPay Ltd Security Team

---

###  Communication Timeline by Severity

| Audience | P1 Critical | P2 High | P3 Medium | P4 Low |
|----------|-------------|---------|-----------|--------|
| IR Team | Immediate | 30 mins | 2 hours | 4 hours |
| Management | 1 hour | 2 hours | 4 hours | 24 hours |
| All Staff | 2 hours | 4 hours | 24 hours | As needed |
| Regulators | Within 72hrs | If required | If required | No |
| Customers | If required | If required | No | No |

---

###  Communication Checklist

**During every incident ensure:**

- [ ] IR team notified within required timeframe
- [ ] Management escalated for P1 and P2 incidents
- [ ] All communications logged and timestamped
- [ ] Regulatory notification deadlines tracked
- [ ] Customer notification assessed and actioned
- [ ] All staff briefed if systems are affected
- [ ] External communications approved by Legal
- [ ] No sensitive incident details shared publicly
- [ ] All notifications documented for audit trail

---

---

##  Lessons Learned Framework

---

### Overview

The lessons learned process is one of the most
critical components of effective incident response.
Every security incident — regardless of severity —
provides valuable intelligence that strengthens
CipherPay Ltd's security posture and improves future
response capability.

This framework ensures that every incident is
reviewed, documented, and acted upon systematically.

---

###  Post-Incident Review Process

All incidents must go through a formal post-incident
review within the following timeframes:

| Severity | Review Deadline | Participants |
|----------|----------------|--------------|
| 🔴 P1 Critical | Within 24 hours | Full IR team + Management |
| 🟠 P2 High | Within 48 hours | IR team + relevant department |
| 🟡 P3 Medium | Within 72 hours | SOC Analyst + IT Admin |
| 🟢 P4 Low | Within 1 week | SOC Analyst |

---

###  Post-Incident Review Template
POST-INCIDENT REVIEW REPORT
INCIDENT DETAILS
Incident ID:          [Auto-generated]
Incident Type:        [Brute Force / Phishing / Data Breach]
Severity Level:       [P1 / P2 / P3 / P4]
Date of Incident:     [DD/MM/YYYY]
Date of Review:       [DD/MM/YYYY]
Review Facilitated By:[Name and Role]
Attendees:            [List all participants]
INCIDENT TIMELINE
[Provide a detailed minute-by-minute timeline of
the incident from detection to resolution]
TimeEvent[HH:MM][What happened][HH:MM][What happened][HH:MM][What happened]
DETECTION ANALYSIS
How was the incident detected?
[Describe detection method]
How long did it take to detect from initial compromise?
[Time in hours/minutes]
Were existing detection controls effective?
[ ] Yes — fully effective
[ ] Partially — some gaps identified
[ ] No — controls failed to detect
Detection gaps identified:
[List any gaps in detection capability]
RESPONSE ANALYSIS
How long did it take to contain the incident?
[Time from detection to containment]
Were response procedures followed correctly?
[ ] Yes — fully followed
[ ] Partially — some deviations
[ ] No — significant deviations
Response gaps identified:
[List any gaps in response capability]
IMPACT ASSESSMENT
Systems affected:
[List all affected systems]
Data affected:
[ ] No data affected
[ ] Internal data only
[ ] Customer PII affected
[ ] Payment card data affected
Number of customers affected: [Number or N/A]
Estimated financial impact:   [Amount or N/A]
Regulatory notifications made:[Yes / No / Details]
Reputational impact:          [Low / Medium / High]
ROOT CAUSE ANALYSIS
Primary root cause:
[What was the fundamental cause of the incident]
Contributing factors:

[Factor 1]
[Factor 2]
[Factor 3]

Could this incident have been prevented?
[ ] Yes — with existing controls
[ ] Yes — with additional controls
[ ] No — unavoidable
WHAT WENT WELL

[What worked well during detection]
[What worked well during containment]
[What worked well during communication]
[What worked well during recovery]

WHAT NEEDS IMPROVEMENT

[What could have been done better]
[What gaps were identified]
[What controls failed or were missing]
[What communication gaps existed]

ACTION ITEMS
[All action items must have an owner and deadline]
#Action RequiredOwnerPriorityDeadline1[Action][Name][High/Med/Low][Date]2[Action][Name][High/Med/Low][Date]3[Action][Name][High/Med/Low][Date]
PLAYBOOK UPDATES REQUIRED
Does this incident require updates to the playbook?
[ ] Yes — details below
[ ] No — playbook remains current
Updates required:
[Describe any playbook updates needed]
SIGN OFF
Review completed by: [Name and Role]
Date: [DD/MM/YYYY]
Next review date: [DD/MM/YYYY]

---

###  Incident Metrics Tracking

CipherPay Ltd should track the following metrics
across all incidents to measure improvement over time:

**Key Performance Indicators (KPIs):**

| Metric | Description | Target |
|--------|-------------|--------|
| Mean Time to Detect (MTTD) | Average time from incident start to detection | < 1 hour |
| Mean Time to Respond (MTTR) | Average time from detection to containment | < 4 hours |
| Mean Time to Recover (MTTR) | Average time from containment to full recovery | < 24 hours |
| False Positive Rate | Percentage of alerts that are not real incidents | < 10% |
| Repeat Incidents | Number of same incident type recurring | 0 |
| Playbook Compliance | Percentage of incidents following playbook | > 95% |

---

###  Incident Trend Analysis

**Monthly incident review should track:**

| Month | P1 | P2 | P3 | P4 | Total | MTTD | MTTR |
|-------|----|----|----|----|-------|------|------|
| Jan | | | | | | | |
| Feb | | | | | | | |
| Mar | | | | | | | |
| Apr | | | | | | | |
| May | | | | | | | |
| Jun | | | | | | | |
| Jul | | | | | | | |
| Aug | | | | | | | |
| Sep | | | | | | | |
| Oct | | | | | | | |
| Nov | | | | | | | |
| Dec | | | | | | | |

---

###  Continuous Improvement Cycle
    ┌─────────────────┐
    │   INCIDENT      │
    │   OCCURS        │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │   RESPOND &     │
    │   RECOVER       │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │  POST-INCIDENT  │
    │    REVIEW       │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │   IDENTIFY      │
    │   IMPROVEMENTS  │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │   IMPLEMENT     │
    │   CONTROLS      │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │   UPDATE        │
    │   PLAYBOOK      │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │   TEST &        │
    │   VALIDATE      │
    └────────┬────────┘
             │
             └──────────────► Repeat

---

###  Playbook Review Schedule

This playbook must be reviewed and updated regularly
to remain effective and relevant:

| Review Type | Frequency | Trigger |
|-------------|-----------|---------|
| Scheduled Review | Every 6 months | Calendar |
| Post-Incident Review | After every P1/P2 incident | Incident |
| Threat Landscape Review | Quarterly | New threat intelligence |
| Regulatory Review | Annually | Regulatory changes |
| Technology Review | Annually | New tools or systems |

---

###  Playbook Maintenance Checklist

**Every 6 months verify:**

- [ ] All contact details are current and accurate
- [ ] Severity classification thresholds are appropriate
- [ ] All response procedures reflect current systems
- [ ] Communication templates are up to date
- [ ] Regulatory notification requirements are current
- [ ] All action items from previous reviews are closed
- [ ] New threats and attack techniques are incorporated
- [ ] Splunk detection queries are optimised
- [ ] Lessons learned are reflected in procedures
- [ ] IR team members are aware of their responsibilities

---

---

##  Conclusion

---

### Summary

This Incident Response Playbook has been developed
to provide CipherPay Ltd with a structured, repeatable
framework for detecting, responding to, and recovering
from the three most critical security incident types
facing the organisation.

The playbook addresses the key gaps identified in the
CipherPay Ltd Security Audit (April 2026) — most
critically the complete absence of an Incident Response
Plan which was rated as a **Critical Risk (R-003)**.

**This playbook delivers:**

| Deliverable | Details |
|-------------|---------|
| 3 Incident Playbooks | Brute Force, Phishing, Data Breach |
| 18 Response Checklists | Step by step actions per phase |
| 5 Communication Templates | Internal, Management, Regulatory, Customer |
| MITRE ATT&CK Mapping | 13 techniques mapped across 3 playbooks |
| Framework Alignment | NIST SP 800-61, ISO 27001, GDPR, PCI-DSS |
| Lessons Learned Framework | Post-incident review and KPI tracking |

---

###  Security Posture Impact

Implementing this playbook directly addresses the
following findings from the CipherPay Security Audit:

| Risk ID | Risk Description | Status |
|---------|-----------------|--------|
| R-003 | No Incident Response Plan | ✅ Resolved |
| R-006 | No security monitoring capability | ✅ Partially Addressed |
| R-004 | No Information Security Policy | ⚠️ Partially Addressed |
| R-007 | No Data Protection Officer | ⚠️ In Progress |
| R-009 | No security awareness training | ⚠️ In Progress |

**Updated Security Posture:**

| Metric | Before Playbook | After Playbook |
|--------|----------------|----------------|
| NIST RS.RP-1 — Response Plan | ❌ Not in place | ✅ Implemented |
| NIST RS.CO-1 — Defined Roles | ❌ Not in place | ✅ Implemented |
| NIST RC.RP-1 — Recovery Plan | ❌ Not in place | ✅ Implemented |
| ISO 27001 A.5.24 — Incident Mgmt | ❌ Non-Compliant | ✅ Compliant |
| GDPR Article 33 — Breach Notification | ❌ No process | ✅ Process defined |
| PCI-DSS Req 12.10 — IR Plan | ❌ Not in place | ✅ Implemented |

---

###  Recommended Next Steps

To further strengthen CipherPay Ltd's incident
response capability the following next steps are
recommended:

**Immediate (0-30 days):**
- [ ] Distribute this playbook to all IR team members
- [ ] Conduct tabletop exercise to test Playbook 1
- [ ] Appoint Incident Response Lead formally
- [ ] Set up dedicated security incident reporting channel

**Short Term (30-90 days):**
- [ ] Conduct tabletop exercises for Playbooks 2 and 3
- [ ] Deploy Splunk Cloud SIEM for real-time detection
- [ ] Implement MFA across all systems
- [ ] Launch phishing awareness training for all staff

**Long Term (90 days - 12 months):**
- [ ] Conduct full IR simulation exercise
- [ ] Achieve ISO 27001 certification
- [ ] Complete PCI-DSS compliance assessment
- [ ] Appoint dedicated DPO
- [ ] Review and update playbook every 6 months

---

###  Related Documents

| Document | Description | Link |
|----------|-------------|------|
| CipherPay Security Audit Report | Full GRC audit and risk assessment | [GitHub](https://github.com/alexojocyber/GRC-Security-Audit-CipherPay) |
| Splunk SIEM Lab | Real-time brute force detection dashboard | [GitHub](https://github.com/alexojocyber/Splunk-SIEM-Lab) |
| SSH Brute Force Detection Lab | SSH attack simulation and Fail2Ban defense | [GitHub](https://github.com/alexojocyber/SSH-BruteForce-Detection-Lab) |
| Python Log Parser | Automated log analysis and threat detection | [GitHub](https://github.com/alexojocyber/Python-Log-Parser) |
| Enterprise SIEM Lab | PAM brute force detection and MITRE mapping | [GitHub](https://github.com/alexojocyber/SIEM-Investigation-Lab) |

---

###  Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | April 2026 | Alex Ojo | Initial playbook created |
| 1.1 | October 2026 | TBD | Scheduled 6-month review |

---

### Auditor Statement

> This Incident Response Playbook was prepared by
> **Alex Ojo**, Junior SOC & GRC Analyst, as part of
> the CipherPay Ltd security program. All procedures
> are based on industry best practices and aligned
> with NIST SP 800-61, ISO 27001, GDPR, and PCI-DSS
> requirements. This document should be reviewed and
> tested regularly to ensure its continued effectiveness.

---

**Prepared by:**
Alex Ojo
Junior SOC & GRC Analyst
April 2026

**Document Classification:** Confidential
**Next Review Date:** October 2026

---

##  Author

**Alex Ojo**
Cybersecurity Student | SOC & GRC Analyst Trainee

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://www.linkedin.com/in/alex-ojo-ab9252185?)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black)](https://github.com/alexojocyber)
