"""typo_watch — lookalike / typosquatting domain detection.

How it works
------------
1. **Generate** candidate lookalikes of each watched domain using 12
   permutation techniques (omission, insertion, substitution, transposition,
   duplication, hyphenation, bitsquatting, homoglyphs, vowel-swap,
   pluralization, combosquatting, TLD-swap).
2. **Liveness check** — resolve each candidate via DNS. A candidate that
   resolves is *registered and active*, which is the first real signal.
3. **Phishing signal** — check for MX records. A lookalike that can *receive
   mail* can run BEC/credential-phishing as you. This is weighted heavily.
4. **Certificate Transparency** — query crt.sh for certificates issued to
   names similar to the watched domain. Attackers need TLS for convincing
   phishing pages, and CT logs are public, so this catches lookalikes that
   don't resolve to the checked DNS view yet.
5. **Score** every candidate and emit findings for anything above the
   noise floor.

Threat model: brand impersonation, credential harvesting, and BEC.
See docs/typo-watch.md for the full write-up.
"""

from __future__ import annotations

import difflib
import logging
import string
from collections.abc import Iterable

import requests

from .findings import Finding, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Permutation tables
# ---------------------------------------------------------------------------

# QWERTY adjacency for realistic substitution typos.
KEYBOARD_NEIGHBORS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgcv", "g": "ftyhbv", "h": "gyujbn", "i": "ujko", "j": "huiknm",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
    "z": "asx", "0": "9", "1": "2", "2": "13", "3": "24", "4": "35",
    "5": "46", "6": "57", "7": "68", "8": "79", "9": "80",
}

# ASCII confusables actually used in the wild (must stay DNS-legal).
HOMOGLYPHS = {
    "a": ["e"], "b": ["d"], "d": ["b"], "e": ["a"], "g": ["q"],
    "i": ["1", "l"], "l": ["1", "i"], "n": ["m"], "m": ["n"],
    "o": ["0"], "q": ["g"], "u": ["v"], "v": ["u"],
    "0": ["o"], "1": ["l", "i"],
}
# Multi-char confusables, applied as substring replacements.
DIGRAPH_HOMOGLYPHS = {"rn": "m", "m": "rn", "cl": "d", "vv": "w", "w": "vv"}

VOWELS = "aeiou"

# Keywords attackers prepend/append for combosquatting.
COMBO_KEYWORDS = [
    "login", "secure", "account", "support", "verify", "update", "app",
    "web", "portal", "admin", "pay", "billing", "help", "service",
    "online", "mail", "api", "auth", "my", "get",
]

# TLDs commonly abused for lookalikes (original TLD excluded at runtime).
TLD_SWAPS = [
    "com", "net", "org", "io", "co", "ai", "dev", "app", "info",
    "biz", "us", "me", "shop", "site", "online", "xyz", "top",
]

VALID_LABEL_CHARS = set(string.ascii_lowercase + string.digits + "-")


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def _split(domain: str) -> tuple[str, str]:
    """Split 'example.com' -> ('example', 'com')."""
    domain = domain.strip().lower().rstrip(".")
    if "." not in domain:
        raise ValueError(f"not a valid domain: {domain!r}")
    sld, _, tld = domain.rpartition(".")
    return sld, tld


def generate_typos(domain: str, max_candidates: int = 1500) -> dict[str, set[str]]:
    """Generate lookalike candidates, grouped by technique.

    Returns ``{technique: {candidate_domains}}``. Generation is ordered by
    technique priority and stops at ``max_candidates`` total so scheduled
    runs stay bounded.
    """
    sld, tld = _split(domain)
    results: dict[str, set[str]] = {}
    seen: set[str] = set()  # global dedupe across techniques
    total = 0

    def add(technique: str, variants: Iterable[str]) -> bool:
        """Add variants; return False when the cap is hit (stop everything)."""
        nonlocal total
        bucket = results.setdefault(technique, set())
        for v in variants:
            if total >= max_candidates:
                return False
            v = v.strip("-").lower()
            if not v or v == domain.lower() or len(v) > 63:
                continue
            if any(c not in VALID_LABEL_CHARS and c != "." for c in v):
                continue
            if v in seen:
                continue
            seen.add(v)
            bucket.add(v)
            total += 1
        return True

    # 1. omission — 'example' -> 'exmple'
    if not add("omission", (f"{sld[:i]}{sld[i+1:]}.{tld}" for i in range(len(sld)))):
        return results
    # 2. transposition — 'example' -> 'eaxmple'
    if not add("transposition", (
        f"{sld[:i]}{sld[i+1]}{sld[i]}{sld[i+2:]}.{tld}" for i in range(len(sld) - 1)
    )):
        return results
    # 3. substitution (keyboard-adjacent) — 'example' -> 'exampke'
    def _subs():
        for i, ch in enumerate(sld):
            for n in KEYBOARD_NEIGHBORS.get(ch, ""):
                yield f"{sld[:i]}{n}{sld[i+1:]}.{tld}"
    if not add("substitution", _subs()):
        return results
    # 4. duplication — 'example' -> 'exammple'
    if not add("duplication", (f"{sld[:i]}{ch}{sld[i:]}.{tld}" for i, ch in enumerate(sld) for ch in [sld[i]])):
        return results
    # 5. insertion — 'example' -> 'exzample'
    def _inss():
        for i in range(len(sld) + 1):
            for ch in string.ascii_lowercase + string.digits:
                yield f"{sld[:i]}{ch}{sld[i:]}.{tld}"
    if not add("insertion", _inss()):
        return results
    # 6. hyphenation — 'example' -> 'exam-ple'
    if not add("hyphenation", (f"{sld[:i]}-{sld[i:]}.{tld}" for i in range(1, len(sld)))):
        return results
    # 7. homoglyphs — 'example' -> 'examp1e'
    def _homos():
        for i, ch in enumerate(sld):
            for h in HOMOGLYPHS.get(ch, []):
                yield f"{sld[:i]}{h}{sld[i+1:]}.{tld}"
        for digraph, repl in DIGRAPH_HOMOGLYPHS.items():
            if digraph in sld:
                yield f"{sld.replace(digraph, repl)}.{tld}"
    if not add("homoglyph", _homos()):
        return results
    # 8. bitsquatting — single-bit flips that stay DNS-legal
    def _bits():
        for i, ch in enumerate(sld):
            for bit in range(8):
                c2 = chr(ord(ch) ^ (1 << bit))
                if c2 != ch and c2 in VALID_LABEL_CHARS:
                    yield f"{sld[:i]}{c2}{sld[i+1:]}.{tld}"
    if not add("bitsquatting", _bits()):
        return results
    # 9. vowel-swap — 'example' -> 'eximple'
    def _vowels():
        for i, ch in enumerate(sld):
            if ch in VOWELS:
                for v in VOWELS:
                    if v != ch:
                        yield f"{sld[:i]}{v}{sld[i+1:]}.{tld}"
    if not add("vowel-swap", _vowels()):
        return results
    # 10. pluralization — 'example' -> 'examples'
    if not add("pluralization", [f"{sld}s.{tld}"]):
        return results
    # 11. combosquatting — 'example' -> 'example-login.com'
    def _combos():
        for kw in COMBO_KEYWORDS:
            yield f"{kw}{sld}.{tld}"
            yield f"{sld}{kw}.{tld}"
            yield f"{kw}-{sld}.{tld}"
            yield f"{sld}-{kw}.{tld}"
    if not add("combosquatting", _combos()):
        return results
    # 12. tld-swap — 'example.com' -> 'example.co'
    add("tld-swap", (f"{sld}.{t}" for t in TLD_SWAPS if t != tld))
    return results


# ---------------------------------------------------------------------------
# Liveness / intel checks
# ---------------------------------------------------------------------------

def dns_resolves(name: str, timeout: float = 4.0) -> bool:
    """True if the name has any A/AAAA record (i.e. registered and live)."""
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    for rdtype in ("A", "AAAA"):
        try:
            if resolver.resolve(name, rdtype):
                return True
        except Exception as exc:
            log.debug("dns probe %s/%s failed: %s", name, rdtype, exc)
            continue
    return False


def has_mx(name: str, timeout: float = 4.0) -> bool:
    """True if the name can receive email — the credential-phishing signal."""
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        return bool(resolver.resolve(name, "MX"))
    except Exception:
        return False


def check_ct_logs(domain: str, timeout: float = 15.0) -> set[str]:
    """Find lookalike names in Certificate Transparency logs via crt.sh.

    Attackers need TLS for convincing phishing pages, and every public cert
    lands in CT logs. We pull certs mentioning the domain string, then keep
    names that are *similar but not equal* to the watched domain (and not
    mere subdomains of it).
    """
    found: set[str] = set()
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%{domain}%", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "sentinel-typo-watch/1.0"},
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception as exc:  # CT is best-effort; DNS is the primary signal
        log.warning("crt.sh lookup failed for %s: %s", domain, exc)
        return found

    watched = domain.lower()
    for entry in entries:
        names = str(entry.get("name_value", "")).lower().split("\n")
        for name in names:
            name = name.strip().lstrip("*.")
            if not name or name == watched or name.endswith("." + watched):
                continue
            similarity = difflib.SequenceMatcher(None, watched, name).ratio()
            if similarity >= 0.75:
                found.add(name)
    return found


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_candidate(candidate: str, technique: str, evidence: dict) -> tuple[int, Severity]:
    """Score 0-100 and map to severity.

    Weighting rationale (documented so tuning is deliberate, not magic):
    - resolves in DNS (+30): registered and live — the core signal.
    - has MX (+25): can receive mail as you — direct BEC/phishing capability.
    - seen in CT logs (+20): someone bothered to get TLS for it — intent.
    - deceptive technique (+10): homoglyph/bitsquatting are never accidents.
    - combosquatting (+5): keyword lures are built for phishing.
    """
    score = 0
    if evidence.get("resolves"):
        score += 30
    if evidence.get("has_mx"):
        score += 25
    if evidence.get("in_ct_logs"):
        score += 20
    if technique in ("homoglyph", "bitsquatting"):
        score += 10
    if technique == "combosquatting":
        score += 5

    if score >= 60:
        severity = Severity.CRITICAL
    elif score >= 40:
        severity = Severity.HIGH
    elif score >= 20:
        severity = Severity.MEDIUM
    elif score > 0:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    return score, severity


# ---------------------------------------------------------------------------
# Automation entry point
# ---------------------------------------------------------------------------

def run(config: dict, state: dict) -> list[Finding]:
    """Run a typo_watch pass. ``state`` is accepted for the common contract
    (currently unused — every run is a full fresh sweep)."""
    domains: list[str] = config.get("domains", [])
    max_candidates: int = config.get("max_candidates", 1500)
    use_ct: bool = config.get("check_ct_logs", True)
    min_severity = Severity.from_name(config.get("min_severity", "LOW"))

    findings: list[Finding] = []
    for domain in domains:
        log.info("typo_watch: sweeping %s", domain)
        candidates = generate_typos(domain, max_candidates)
        log.info("typo_watch: %s -> %d candidates", domain,
                 sum(len(v) for v in candidates.values()))

        ct_hits = check_ct_logs(domain) if use_ct else set()

        for technique, names in candidates.items():
            for name in sorted(names):
                evidence = {
                    "watched_domain": domain,
                    "candidate": name,
                    "technique": technique,
                    "resolves": dns_resolves(name),
                    "has_mx": has_mx(name),
                    "in_ct_logs": name in ct_hits,
                }
                score, severity = score_candidate(name, technique, evidence)
                if severity < min_severity or severity == Severity.INFO:
                    continue
                evidence["score"] = score
                findings.append(Finding(
                    automation="typo_watch",
                    title=f"Lookalike domain active: {name} (vs {domain})",
                    severity=severity,
                    description=(
                        f"{name} resembles watched domain {domain} "
                        f"(technique: {technique}, score {score}/100). "
                        + ("It resolves in DNS. " if evidence["resolves"] else "")
                        + ("It has MX records and can receive email as your brand. " if evidence["has_mx"] else "")
                        + ("It appears in Certificate Transparency logs (TLS cert issued). " if evidence["in_ct_logs"] else "")
                    ).strip(),
                    evidence=evidence,
                    recommendation=(
                        "Investigate ownership via WHOIS/RDAP. If malicious: file an "
                        "abuse complaint with the registrar, submit the URL to "
                        "Google Safe Browsing / Microsoft Defender, warn staff about "
                        "phishing lures using this domain, and consider a defensive "
                        "registration or UDRP filing for high-value brands."
                    ),
                ))
    return sorted(findings)
