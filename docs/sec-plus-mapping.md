# CompTIA Security+ (SY0-701) domain mapping

Every automation maps to the Security+ domain where a working analyst
would file it. Built while studying for the Sec+ — the mappings are the
study notes.

| Automation | Sec+ Domain | What it drills |
|---|---|---|
| Typo Watch | 1.0 Threats, Attacks & Vulnerabilities | Social engineering, phishing, typosquatting, watering-hole precursors |
| URL Intel | 1.0 Threats, Attacks & Vulnerabilities | Malware delivery, phishing indicators, threat-intel corroboration |
| DNS Sentinel | 2.0 Architecture & Design | DNS security, zone integrity, hijack impact |
| TLS Watch | 3.0 Implementation | PKI, certificate lifecycle, weak crypto |
| Port Watch | 4.0 Operations & Incident Response | Attack-surface management, continuous monitoring |
| Auth Watch | 4.0 Operations & Incident Response | Log analysis, brute-force/spray, account hardening |

Domain 5.0 (Governance, Risk & Compliance) is covered operationally: every
finding carries a *recommendation* (the remediation step), reports are
generated per run (audit trail), and `events.jsonl` gives you the
evidence feed an auditor asks for.
