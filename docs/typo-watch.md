# Typo Watch — how it works

Lookalike-domain detection for brand impersonation, credential harvesting, and BEC.

## Pipeline

1. **Generate** — ~1,500 candidates per watched domain from 12 techniques:
   omission (`exmple`), transposition (`eaxmple`), keyboard-adjacent
   substitution (`exampke`), duplication (`exammple`), insertion, hyphenation
   (`exam-ple`), homoglyphs (`examp1e`), bitsquatting, vowel-swap,
   pluralization, combosquatting (`example-login`), TLD-swap (`example.co`).
   Generation is priority-ordered and capped so scheduled runs stay bounded.
2. **Liveness** — each candidate is resolved via DNS (A/AAAA). A candidate
   that resolves is registered and live: the core signal.
3. **Mail capability** — MX lookup. A lookalike that can *receive* mail can
   run BEC and credential-phishing as your brand. Weighted heavily (+25).
4. **Certificate Transparency** — crt.sh is queried for certs issued to
   names similar (difflib ≥ 0.75) to the watched domain. Attackers need TLS
   for convincing phishing pages, and CT logs are public — this catches
   lookalikes your DNS view hasn't seen yet.
5. **Score** — DNS +30, MX +25, CT +20, deceptive technique (homoglyph /
   bitsquatting) +10, combosquatting +5. ≥60 CRITICAL, ≥40 HIGH, ≥20 MEDIUM.

## Tuning

- `max_candidates`: raise for high-value brands (cost: DNS queries per run).
- `min_severity`: `LOW` is the default noise floor; `MEDIUM` if you only
  want actionable hits.
- `check_ct_logs: false` if crt.sh is unreachable from your network.

## Limitations / evasion

- IDN homoglyphs (Cyrillic `а` vs Latin `a`) are out of scope for the ASCII
  generator; the CT-log leg still catches them when certs are issued.
- Attackers who never get TLS and never point DNS at the name are
  invisible until used — pair with mail-log hunting for the domain strings.
- WHOIS privacy means attribution usually stops at the registrar; the
  finding's recommendation covers the abuse-report path.

## Sec+ mapping

SY0-701 Domain 1.0 — Threats, Attacks & Vulnerabilities (social engineering,
phishing, typosquatting).
