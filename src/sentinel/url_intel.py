"""url_intel — URL threat analysis and unshortening.

How it works
------------
1. **Unshorten** — follows redirects (HEAD, capped hops) to reveal the true
   destination behind bit.ly/tinyurl/etc. Shorteners are the #1 phishing
   obfuscation layer; the final URL is what gets scored.
2. **Heuristics** — deterministic checks, each weighted:
   - punycode host (xn--) -> homoglyph domain (+30)
   - IP-literal host -> no domain reputation to burn (+25)
   - '@' in authority -> credential-stuffing trick (+25)
   - excessive subdomains (>3) -> brand-in-subdomain lures (+15)
   - suspicious TLD (.zip .mov .xyz .top ...) -> abused for malware (+15)
   - known brand string in a subdomain of an unrelated domain (+20)
   - URL length > 200 / deep paths -> obfuscation (+5..10)
3. **urlscan.io** — queries the public search API (no key required) for
   prior scans of the domain; any historic malicious verdict is strong
   corroboration (+30).
4. **Verdict** — score 0-100 -> severity. The full breakdown ships in the
   evidence so analysts see *why*, not just a number.

Threat model: phishing links, malware droppers, and credential-harvesting
pages delivered via email/chat/SMS.
See docs/url-intel.md for the full write-up.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import requests

from .findings import Finding, Severity

log = logging.getLogger(__name__)

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "country", "stream",
    "gq", "cf", "tk", "ml", "ga", "buzz", "rest", "review",
}

# Brand strings phishers love to borrow. A hit only counts when the brand
# appears in a *subdomain* of a domain the brand does not own.
BRAND_STRINGS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
    "dhl", "fedex", "ups", "irs", "usps",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
}


def unshorten(url: str, max_hops: int = 5, timeout: float = 8.0) -> tuple[str, list[str]]:
    """Follow redirects to the final destination. Returns (final_url, hop_chain)."""
    hops = [url]
    current = url
    session = requests.Session()
    session.max_redirects = max_hops
    try:
        resp = session.head(current, allow_redirects=True, timeout=timeout)
        current = resp.url
        hops = [h.url for h in resp.history] + [resp.url]
    except requests.TooManyRedirects:
        log.warning("url_intel: redirect loop on %s", url)
    except Exception as exc:
        log.warning("url_intel: unshorten failed for %s: %s", url, exc)
    return current, hops[: max_hops + 1]


def heuristics(url: str) -> list[tuple[int, str]]:
    """Deterministic checks -> [(points, reason)]. Pure function, no network."""
    hits: list[tuple[int, str]] = []
    try:
        p = urlparse(url)
    except Exception:
        return [(20, "unparseable URL")]
    host = (p.hostname or "").lower()

    if host.startswith("xn--") or ".xn--" in host:
        hits.append((30, "punycode (IDN homoglyph) hostname"))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or ":" in host and host.count(":") >= 2:
        hits.append((25, "IP-literal host (no domain reputation)"))
    if "@" in (p.netloc or ""):
        hits.append((25, "'@' trick in authority — displayed host is not the real host"))
    labels = [l for l in host.split(".") if l]
    if len(labels) > 4:  # e.g. a.b.c.d.example.evil.com
        hits.append((15, f"excessive subdomains ({len(labels)} labels)"))
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        hits.append((15, f"suspicious TLD .{tld} (frequently abused)"))
    for brand in BRAND_STRINGS:
        # allow the brand's own regional domains through only if exact-ish
        if (brand in host and not host.endswith(f"{brand}.com") and host != f"{brand}.com"
                and brand not in (labels[-2] if len(labels) >= 2 else "")):
            hits.append((20, f"brand string '{brand}' in unrelated domain"))
            break
    if len(url) > 200:
        hits.append((10, f"overlong URL ({len(url)} chars — obfuscation)"))
    if p.query and len(p.query) > 120:
        hits.append((5, "overlong query string"))
    if re.search(r"(login|verify|secure|account|update|confirm).*\.(php|html?)$",
                 p.path, re.IGNORECASE):
        hits.append((10, "phish-kit style path (login/verify page)"))
    return hits


def check_urlscan(domain: str, timeout: float = 10.0) -> dict:
    """Query urlscan.io public search for historic verdicts on a domain.

    No API key needed for search. Returns {"scans": n, "malicious": n}.
    Best-effort: failures return zeros, never raise.
    """
    result = {"scans": 0, "malicious": 0}
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}"},
            timeout=timeout,
            headers={"User-Agent": "sentinel-url-intel/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        result["scans"] = data.get("total", len(results))
        for r in results:
            verdicts = (r.get("verdicts") or {}).get("overall") or {}
            if verdicts.get("malicious"):
                result["malicious"] += 1
    except Exception as exc:
        log.warning("url_intel: urlscan.io lookup failed for %s: %s", domain, exc)
    return result


def score_url(url: str, do_unshorten: bool = True,
              do_urlscan: bool = True) -> dict:
    """Full analysis pipeline. Returns a serializable analysis dict."""
    original = url
    final_url, hops = (unshorten(url) if do_unshorten else (url, [url]))
    host = (urlparse(final_url).hostname or "").lower()

    hits = heuristics(final_url)
    score = sum(points for points, _ in hits)
    reasons = [reason for _, reason in hits]

    urlscan = check_urlscan(host) if (do_urlscan and host) else {"scans": 0, "malicious": 0}
    if urlscan["malicious"]:
        score += 30
        reasons.append(f"urlscan.io: {urlscan['malicious']} historic malicious verdict(s)")

    if host.split(".")[-1:] and (urlparse(original).hostname or "").lower() in SHORTENERS:
        reasons.append("URL was hidden behind a shortener")
        score += 5

    score = min(score, 100)
    if score >= 75:
        severity = Severity.CRITICAL
    elif score >= 50:
        severity = Severity.HIGH
    elif score >= 25:
        severity = Severity.MEDIUM
    elif score > 0:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    return {
        "original_url": original,
        "final_url": final_url,
        "redirect_hops": hops,
        "host": host,
        "score": score,
        "severity": severity.label,
        "reasons": reasons,
        "urlscan": urlscan,
    }


def run(config: dict, state: dict) -> list[Finding]:
    """Run a url_intel pass over the configured URL list."""
    urls: list[str] = config.get("urls", [])
    do_unshorten: bool = config.get("unshorten", True)
    do_urlscan: bool = config.get("urlscan_lookup", True)
    min_severity = Severity.from_name(config.get("min_severity", "LOW"))

    findings: list[Finding] = []
    for url in urls:
        log.info("url_intel: analyzing %s", url)
        analysis = score_url(url, do_unshorten, do_urlscan)
        severity = Severity.from_name(analysis["severity"])
        if severity < min_severity or severity == Severity.INFO:
            continue
        findings.append(Finding(
            automation="url_intel",
            title=f"Suspicious URL ({analysis['severity']}): {analysis['host'] or url}",
            severity=severity,
            description=(
                f"URL scored {analysis['score']}/100. "
                f"Final destination: {analysis['final_url']}. "
                f"Signals: {'; '.join(analysis['reasons']) or 'none'}."
            ),
            evidence=analysis,
            recommendation=(
                "Do NOT open in a normal browser. Detonate in a sandbox "
                "(urlscan.io / ANY.RUN) if business need exists. Block the "
                "domain at DNS/web-filter, hunt for the URL in mail logs, "
                "and warn recipients if it was delivered internally."
            ),
        ))
    return sorted(findings)
