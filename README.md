# CPS-Fusion: four vulnerability chains you can run

> **Deliberately vulnerable code.** Everything under `chains/` contains
> intentional weaknesses so that scanners have something to find. Do not
> deploy it, expose it, or reuse it. The secrets in it are placeholders and
> unlock nothing.

Severity triage looks at one finding at a time. A Medium gets deferred, a Low
gets deferred, an Informational is often never shown at all. The **Chain
Potential Score (CPS)** asks a different question: *what can these findings do
together?*

This repository holds the four example chains from the CPS writeup as real
code, plus the scoring engine that scores them. No finding in any chain is
rated above Medium, and every chain still scores High.

| # | Example | Chain | Stack | Findings | Highest severity | Chain CPS |
|---|---|---|---|---|---|---|
| 1 | Account takeover | CH-101 | PHP | 3 Medium + 2 Low | Medium | **10.00** High |
| 2 | Token theft | CH-104 | Node.js | 2 Medium + 3 Low | Medium | **9.14** High |
| 3 | Silent data exfiltration | CH-106 | Java | 5 Informational | Informational | **9.15** High |
| 4 | API token forgery | CH-110 | Go | 2 Medium + 1 Low | Medium | **8.01** High |

## Quick start

Python 3.10 or later; nothing to install.

```bash
python demo.py                      # all four chains
python demo.py --chain CH-106       # just one
python -m unittest discover -s tests
```

`demo.py` reads `fixtures/expected_findings.json`, scores every finding with
`cps_engine`, matches them against `catalog/chains_index.json`, and prints each
chain like this:

```
CH-110  API token forgery
API Auth Weakening to Token Forgery
------------------------------------------------------------------------------
  Scanner sev     CPS  Finding  ::  location
  Medium         6.50  Use_of_Hardcoded_Password  ::  chains/CH-110-token-forgery/auth-service/main.go:30
  Medium         6.75  Client_Weak_Cryptographic_Hash  ::  chains/CH-110-token-forgery/auth-service/public/js/checkout.js:54
  Low            6.12  JWT_No_Claims_Directives_Validation  ::  chains/CH-110-token-forgery/auth-service/main.go:51
------------------------------------------------------------------------------
  Highest scanner severity: Medium
  Chain CPS:                8.01  (High)   [3/3 fully assembled]
```

It ends with a summary table that compares the highest scanner severity in
each chain with the chain's CPS.

## The four chains

**1. Account takeover (CH-101):** `chains/CH-101-account-takeover/storefront/public/login.php`.
The session ID comes from `mt_rand()` seeded with the clock, so it can be
guessed (Medium, plus a Low for non-cryptographic random). The ID is "signed"
with MD5 (Medium). The cookie is sent with `SameSite=None` (Medium) and
`Path=/` (Low). An attacker can guess the ID, forge its signature, send the
cookie cross-site, and use the session anywhere on the site.

**2. Token theft (CH-104):** `chains/CH-104-token-theft/web-gateway/src/server.js`.
After sign-in the app redirects to a `return_to` value it never checks, with
the new session handle appended (Medium). There is no HSTS header (Medium) and
no CSP header (Low). Links open with `target="_blank"` and no `noopener`
(Low). Unsanitised query values go into the audit log (Low). The token goes to
a page the attacker controls, and the forged log hides the trail.

**3. Silent data exfiltration (CH-106):** `chains/CH-106-silent-exfiltration/catalog-service/`.
All five findings are Informational, the level below Low: dynamic SQL,
database actions that are never logged, no global error handler, error
returns that are ignored, and internals written to `System.out`. Most
backlogs never show these findings, yet together they score 9.15.

**4. API token forgery (CH-110):** `chains/CH-110-token-forgery/auth-service/`.
The JWT signing key is a password hardcoded in the binary (Medium). The client
derives its digest with SHA-1 (Medium). The JWT parser checks no expiry,
issuer or audience (Low). As a result, a token with any claims the attacker
chooses is accepted.

## How the score is computed

Each finding is scored on five dimensions (prevalence, chain utility, AI
leverage, blast radius and impact proximity), each from 0 to 4. The weights
are 0.15, 0.30, 0.25, 0.15 and 0.15, and the weighted sum is scaled to 0–10.
`cps_engine/dimension_defaults.py` holds the default dimension values for each
scanner query.

A chain scores its strongest finding plus a tenth of the others, capped at 10:

```
CPS_chain = max(scores) + 0.1 × (sum(scores) − max(scores))
```

The bands are Negligible (≤ 2.5), Low (≤ 5.0), Moderate (≤ 7.5) and High
(above 7.5). The tests also show that a chain stops assembling, and its score
drops, when any one of its findings is removed. In other words, fixing one
link breaks the chain.

## Checking it with a real scan

The fixture records the findings the code is *expected* to produce. It lets
the demo and tests run offline, but it is not scan output. To check what a
scanner actually reports, scan this repository with SAST enabled, export the
results as JSON, and run:

```bash
python demo.py path/to/results.json
```

Supported formats are Checkmarx One results JSON, SARIF 2.1.0, CxSAST legacy
JSON and the Vulnerability Type report. Each required finding in the catalog
is limited to its own service folder (`match_file_contains`), so the four
chains can't match each other's findings in a whole-repository scan. The exit
code is 0 when every chain fully assembles.

## Layout

```
demo.py                      run the chains and print chain CPS vs. severities
cps_engine/                  CPS scoring and chain-matching engine
catalog/chains_index.json    the four chain definitions
fixtures/expected_findings.json  expected findings, used offline
chains/
  CH-101-account-takeover/storefront/        PHP
  CH-104-token-theft/web-gateway/            Node.js (no dependencies)
  CH-106-silent-exfiltration/catalog-service/ Java (servlet API only)
  CH-110-token-forgery/auth-service/         Go (golang-jwt)
tests/test_four_chains.py
```

The chains, the engine and the expected severities come from the Nexa
Commerce reference app in [CPS-DEMO](https://github.com/cxsmtp/CPS-DEMO),
which has all ten chains.
