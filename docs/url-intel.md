# URL Intel — how it works

Malicious-URL analysis: unshorten, score, corroborate.

## Pipeline

1. **Unshorten** — follows redirects (HEAD, capped hops) to the true
   destination. Shorteners are the #1 phishing obfuscation layer; the
   *final* URL is what gets scored, and the hop chain ships in evidence.
2. **Heuristics** — deterministic, each weighted:
   - punycode/IDN host (`xn--`) → +30 (homoglyph domains)
   - IP-literal host → +25 (no domain reputation to burn)
   - `@` in authority → +25 (displayed host ≠ real host)
   - brand string inside an unrelated domain → +20
   - >4 DNS labels → +15 (brand-in-subdomain lures)
   - abused TLD (`.zip` `.mov` `.xyz` …) → +15
   - phish-kit path (`login.php`, `verify.html`) → +10
   - overlong URL/query → +5–10
3. **Corroborate** — urlscan.io public search API (no key needed) for
   historic verdicts on the domain; any malicious hit adds +30.
4. **Verdict** — 0–100 → ≥75 CRITICAL, ≥50 HIGH, ≥25 MEDIUM, >0 LOW.
   The full signal breakdown ships in evidence: analysts see *why*.

## Tuning

- `unshorten: false` / `urlscan_lookup: false` for air-gapped runs
  (heuristics alone still catch most phishing structure).
- `min_severity`: `LOW` default; raise to `MEDIUM` for noisy feeds.

## Limitations

- Heuristics are structural, not content-based: a clean-looking URL
  hosting a fresh phish kit scores low until urlscan.io has seen it.
- Shortener hop-chains can loop; hops are capped and loops are logged.

## Sec+ mapping

SY0-701 Domain 1.0 — Threats, Attacks & Vulnerabilities (phishing,
malware delivery).
