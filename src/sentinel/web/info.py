"""Human-readable metadata for each automation.

Powers the Automations pages: what it does, how it works step-by-step,
what it's hunting, and which CompTIA Security+ domain it maps to.
"""

AUTOMATION_INFO: dict[str, dict] = {
    "typo_watch": {
        "title": "Typo Watch",
        "tagline": "Lookalike & typosquatting domain detection",
        "threat": "Brand impersonation, credential harvesting, BEC",
        "sec_plus": "1.0 Threats, Attacks & Vulnerabilities",
        "how": [
            "Generates ~1,500 lookalike candidates per domain using 12 permutation techniques: omission, transposition, keyboard-substitution, duplication, insertion, hyphenation, homoglyphs (examp1e), bitsquatting, vowel-swap, pluralization, combosquatting (example-login), and TLD-swap.",
            "Resolves each candidate in DNS — a candidate that resolves is registered and live.",
            "Checks MX records: a lookalike that can receive email can phish as your brand. Weighted heavily.",
            "Queries crt.sh Certificate Transparency logs for TLS certs issued to similar names — attackers need HTTPS for convincing phishing pages, and CT logs are public.",
            "Scores 0–100 (DNS +30, MX +25, CT +20, deceptive technique +10) and alerts on anything above the noise floor.",
        ],
    },
    "dns_sentinel": {
        "title": "DNS Sentinel",
        "tagline": "DNS baseline & drift detection",
        "threat": "DNS hijacking, subdomain takeover staging, mail rerouting",
        "sec_plus": "2.0 Architecture & Design",
        "how": [
            "Snapshots the public DNS footprint: A, AAAA, CNAME, MX, TXT, NS records plus the SOA serial as a change canary.",
            "First run stores the snapshot as the known-good baseline (single INFO finding, no alerts).",
            "Every later run diffs live DNS against the baseline. NS/MX changes fire HIGH (zone hijack / mail rerouting = total blast radius); A/AAAA/CNAME drift fires MEDIUM; TXT churn fires LOW.",
            "The original baseline is kept until an operator explicitly approves the new state — drift keeps alerting, it never silently re-baselines.",
        ],
    },
    "tls_watch": {
        "title": "TLS Watch",
        "tagline": "Certificate expiry & misconfiguration monitoring",
        "threat": "Outages from lapsed renewals, MITM, warning-fatigue",
        "sec_plus": "3.0 Implementation",
        "how": [
            "Opens a real TLS handshake to each host:port and pulls the leaf certificate.",
            "Expiry thresholds: ≤14 days CRITICAL, ≤30 days HIGH, ≤60 days MEDIUM — 60d catches Let's Encrypt 90-day certs whose auto-renew broke on first attempt.",
            "Flags already-expired (CRITICAL), self-signed on public hosts (HIGH — misdeployment or MITM infra), weak signature algorithms md5/sha1 (MEDIUM), and SAN/CN hostname mismatches (HIGH).",
            "Most expiries are broken renewal pipelines, not forgotten certs — the recommendation says to check the ACME job first.",
        ],
    },
    "port_watch": {
        "title": "Port Watch",
        "tagline": "Attack-surface drift detection",
        "threat": "Unexpected exposure (RDP/DB/admin ports), service outages",
        "sec_plus": "4.0 Operations & Incident Response",
        "how": [
            "You declare the intended attack surface (expected_open per host). Each run TCP-scans those ports plus a watchlist of commonly-abused ports (23, 445, 3389, 6379, 27017, 9200, ...).",
            "Open-but-unexpected → HIGH. This is how ransomware finds RDP: assume hostile until proven otherwise.",
            "Expected-but-closed → MEDIUM (service down or firewall change).",
            "Grabs up to 1KB of banner on open ports and tracks changes — a changed banner means the service behind the port changed.",
            "Deliberately not a full port scanner: it answers one question — does the live attack surface match the declared one?",
        ],
    },
    "auth_watch": {
        "title": "Auth Watch",
        "tagline": "SSH brute-force & password-spray detection",
        "threat": "Credential stuffing, password spraying, SSH brute force",
        "sec_plus": "4.0 Operations & Incident Response",
        "how": [
            "Tails the auth log using offset+inode tracking — each run processes only new lines, survives log rotation, never re-scans.",
            "Parses failed passwords, invalid users, and accepted logins into structured events.",
            "Sliding-window counting per source IP (default 15 min / 10 failures). Crossing the threshold fires a finding.",
            "Classifies the shape: password-spraying (one IP, ≥5 usernames — the stealthy pattern that evades per-account lockout) vs targeted brute force.",
            "Read-only and safe by design: it never blocks anything. The finding carries the exact firewall commands for the operator.",
            "Also flags first-seen successful logins from new IPs (INFO) — the earliest possible compromise signal.",
        ],
    },
    "url_intel": {
        "title": "URL Intel",
        "tagline": "Malicious URL analysis & unshortening",
        "threat": "Phishing links, malware droppers, credential harvesters",
        "sec_plus": "1.0 Threats, Attacks & Vulnerabilities",
        "how": [
            "Unshortens via redirect-following (capped hops) — shorteners are the #1 phishing obfuscation layer; the final URL is what gets scored.",
            "Deterministic heuristics, each weighted: punycode/IDN (+30), IP-literal host (+25), '@' authority trick (+25), brand string in an unrelated domain (+20), excessive subdomains (+15), abused TLDs like .zip/.mov (+15), phish-kit paths (+10).",
            "Corroborates with urlscan.io's public search API (no key needed): historic malicious verdicts add +30.",
            "Scores 0–100 → severity. The full signal breakdown ships in the evidence so analysts see why, not just a number.",
        ],
    },
}
