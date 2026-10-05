# CPS-Fusion: ten vulnerability chains proven by a real scan

> **Deliberately vulnerable code.** Everything under `chains/` contains
> intentional weaknesses so that scanners have something to find. Do not
> deploy it, expose it, or reuse it.

Severity triage looks at one finding at a time. A Low gets deferred, and an
Informational is often never shown at all. The **Chain Potential Score (CPS)**
asks a different question: *what can these findings do together?*

This repository holds ten chains as real code, plus the scoring engine that
scores them. Every link in every chain was reported by a real Checkmarx One
scan of this repository (scan `a71e672d-dd27-4bfb-a26a-c7fa4d15e5bb`, commit
`beba8de`, all six engines: SAST, SCA, KICS, containers, secret detection and
API security). That scan reported no Critical or High findings anywhere in the
repository, and no link in any chain is rated above Low.

| # | Chain | ID | Stack | Links (scanner severity) | Chain CPS |
|---|---|---|---|---|---|
| 1 | Session prediction | CH-201 | Node.js | 6 Low | **10.00** High |
| 2 | Silent bulk export | CH-202 | Java / JSP | 5 Informational | **7.62** High |
| 3 | Report substitution | CH-203 | Java | 2 Low + 2 Informational | **7.25** Moderate |
| 4 | Support-desk impersonation | CH-204 | Python / Flask | 4 Low | **9.61** High |
| 5 | Error oracle | CH-205 | PHP | 2 Low + 3 Informational | **7.81** High |
| 6 | Remember-me hijack | CH-206 | PHP | 3 Low | **8.70** High |
| 7 | Token leak | CH-207 | Node.js | 6 Low | **9.94** High |
| 8 | Upload to script | CH-208 | Go | 3 Low | **6.71** Moderate |
| 9 | Operator console blind spot | CH-209 | Java / JSP | 2 Low + 3 Informational | **7.89** High |
| 10 | Silent order loss | CH-210 | PHP | 1 Low + 3 Informational | **6.09** Moderate |

Seven chains land in the High band and three in Moderate, built entirely from
Low and Informational findings.

## Quick start

Python 3.10 or later; nothing to install.

```bash
python demo.py                      # all ten chains
python demo.py --chain CH-204       # just one
python -m unittest discover -s tests
```

`demo.py` reads `fixtures/scan_findings.json` (the scan's own findings for
the chain folders, with their result ids), scores every finding with
`cps_engine`, matches them against `catalog/chains_index.json`, and prints
each chain with every link's severity, CPS and file:line, then a summary
table.

## The ten chains

Each chain lists its links as the scan reported them (first location shown;
the catalog keeps every result id and location).

**1. Session prediction (CH-201, Node.js).** Account takeover without stealing a credential. Session IDs come from Math.random() with a clock prefix, so they can be enumerated; the verification error path leaks the start of the signing key and the raw error text reaches the caller; caller text is written into the log unescaped, hiding the probing; and the page ships without a Content-Security-Policy.

  - Low: `Use_of_Insufficiently_Random_Values` at `chains/CH-201-session-prediction/web/src/session.js:18`
  - Low: `Client_Insecure_Randomness` at `chains/CH-201-session-prediction/web/src/session.js:17`
  - Low: `Secret_Leak_in_Error_Messages` at `chains/CH-201-session-prediction/web/src/session.js:33`
  - Low: `Information_Exposure_Through_an_Error_Message` at `chains/CH-201-session-prediction/web/src/server.js:66`
  - Low: `Log_Forging` at `chains/CH-201-session-prediction/web/src/server.js:54`
  - Low: `Missing_CSP_Header` at `chains/CH-201-session-prediction/web/src/server.js:68`

**2. Silent bulk export (CH-202, Java / JSP).** Undetected bulk export of the customer table. The read is never audited, failures are swallowed without a log entry, the only trace goes to stdout, the update result is discarded, and the export page has no error handler. Every link is Informational.

  - Informational: `Insufficient_Logging_of_Database_Actions` at `chains/CH-202-silent-export/catalog/src/main/java/com/cps/ch202/ExportDao.java:51`
  - Informational: `Insufficient_Logging_of_Exceptions` at `chains/CH-202-silent-export/catalog/src/main/java/com/cps/ch202/ExportDao.java:41`
  - Informational: `ESAPI_Banned_API` at `chains/CH-202-silent-export/catalog/src/main/java/com/cps/ch202/ExportDao.java:42`
  - Informational: `Unused_Variable` at `chains/CH-202-silent-export/catalog/src/main/java/com/cps/ch202/ExportDao.java:52`
  - Informational: `Pages_Without_Global_Error_Handler` at `chains/CH-202-silent-export/catalog/src/main/webapp/admin/export.jsp:1`

**3. Report substitution (CH-203, Java).** A local user reads or replaces the nightly finance report. It is staged in the shared temp directory with default permissions, the existence check is always true so it never guards anything, and the move happens with no logging of failure.

  - Low: `Creation_of_Temp_File_With_Insecure_Permissions` at `chains/CH-203-report-swap/reports/src/main/java/com/cps/ch203/ReportWriter.java:25`
  - Low: `Incorrect_Permission_Assignment_For_File_System_Resources` at `chains/CH-203-report-swap/reports/src/main/java/com/cps/ch203/ReportWriter.java:25`
  - Informational: `Expression_is_Always_True` at `chains/CH-203-report-swap/reports/src/main/java/com/cps/ch203/ReportWriter.java:31`
  - Informational: `Insufficient_Logging_of_Exceptions` at `chains/CH-203-report-swap/reports/src/main/java/com/cps/ch203/ReportWriter.java:37`

**4. Support-desk impersonation (CH-204, Python / Flask).** A caller plants values in their own session that the support desk later shows to staff as server-set identity. A cookie value is copied from the request, caller text is written into the audit log verbatim, and nothing restricts script on the response.

  - Low: `Trust_Boundary_Violation_in_Session_Variables` at `chains/CH-204-session-trust/admin_portal/portal.py:29`
  - Low: `Cookie_Poisoning` at `chains/CH-204-session-trust/admin_portal/portal.py:44`
  - Low: `Log_Forging` at `chains/CH-204-session-trust/admin_portal/portal.py:36`
  - Low: `Missing_Content_Security_Policy` at `chains/CH-204-session-trust/admin_portal/portal.py:45`

**5. Error oracle (CH-205, PHP).** Schema and data enumeration through error text. Connection failures return the raw driver message, query failures are caught and dropped so an empty catalogue looks like a broken one, and the unchecked update hides the probing from operators.

  - Low: `Information_Exposure_Through_an_Error_Message` at `chains/CH-205-error-oracle/storefront/public/catalogue.php:23`
  - Low: `Improper_Exception_Handling` at `chains/CH-205-error-oracle/storefront/public/catalogue.php:41`
  - Informational: `Declaration_Of_Catch_For_Generic_Exception` at `chains/CH-205-error-oracle/storefront/public/catalogue.php:37`
  - Informational: `Detection_of_Error_Condition_Without_Action` at `chains/CH-205-error-oracle/storefront/public/catalogue.php:37`
  - Informational: `Unchecked_Error_Condition` at `chains/CH-205-error-oracle/storefront/public/catalogue.php:20`

**6. Remember-me hijack (CH-206, PHP).** Long-lived account access. The remember-me value comes from a clock-seeded generator, the cookie is sent to every path on the host, and partner links opened with target=_blank let the opened page navigate the account tab to a look-alike login.

  - Low: `Use_of_Non_Cryptographic_Random` at `chains/CH-206-cookie-scope-phish/storefront/public/account.php:18`
  - Low: `Cookie_Overly_Broad_Path` at `chains/CH-206-cookie-scope-phish/storefront/public/account.php:20`
  - Low: `Unsafe_Use_Of_Target_Blank` at `chains/CH-206-cookie-scope-phish/storefront/public/account.php:39`

**7. Token leak (CH-207, Node.js).** Third-party capture of customer bearer tokens and the upstream password. Tokens ride the query string to the partner, the outbound URL and the upstream password are written to the log, caller text can forge log lines, raw errors return stack traces, and the page can be framed.

  - Low: `Use of GET Request Method with Sensitive Query Strings` at `chains/CH-207-token-leak/gateway/src/gateway.js:34`
  - Low: `Secret_Leak_in_Logs` at `chains/CH-207-token-leak/gateway/src/gateway.js:19`
  - Low: `Privacy_Violation_in_Logs` at `chains/CH-207-token-leak/gateway/src/gateway.js:34`
  - Low: `Log_Forging` at `chains/CH-207-token-leak/gateway/src/gateway.js:32`
  - Low: `Information_Exposure_Through_an_Error_Message` at `chains/CH-207-token-leak/gateway/src/gateway.js:44`
  - Low: `Missing_Framing_Policy` at `chains/CH-207-token-leak/gateway/src/gateway.js:32`

**8. Upload to script (CH-208, Go).** Stored script execution from an upload. The X-Content-Type-Options header is set to a value that does not stop sniffing, so a browser renders HTML out of an uploaded image; caller text is logged verbatim, hiding the upload; and the page can be framed to drive the victim to the file.

  - Low: `Misconfigured_X_Content_Type_Options` at `chains/CH-208-content-sniffing/files/main.go:25`
  - Low: `Log_Forging` at `chains/CH-208-content-sniffing/files/main.go:28`
  - Low: `Missing_Framing_Policy` at `chains/CH-208-content-sniffing/files/main.go:25`

**9. Operator console blind spot (CH-209, Java / JSP).** Refund batches run with no reliable trail. Caller text is logged verbatim so entries can be forged, failures print the stack trace to the caller, output goes to banned APIs, the operator credential sits in an unused field, and the console page has no error handler.

  - Low: `Log_Forging` at `chains/CH-209-operator-console/console/src/main/java/com/cps/ch209/OperatorServlet.java:31`
  - Low: `Information_Exposure_Through_an_Error_Message` at `chains/CH-209-operator-console/console/src/main/java/com/cps/ch209/OperatorServlet.java:40`
  - Informational: `ESAPI_Banned_API` at `chains/CH-209-operator-console/console/src/main/java/com/cps/ch209/OperatorServlet.java:35`
  - Informational: `Unused_Variable` at `chains/CH-209-operator-console/console/src/main/java/com/cps/ch209/OperatorServlet.java:25`
  - Informational: `Pages_Without_Global_Error_Handler` at `chains/CH-209-operator-console/console/src/main/webapp/admin/console.jsp:1`

**10. Silent order loss (CH-210, PHP).** A customer who can make the order write fail is still told it succeeded, and nothing records that it did not. Connection and write failures are caught generically and dropped. Every link is Low or Informational.

  - Low: `Improper_Exception_Handling` at `chains/CH-210-silent-order-loss/storefront/public/checkout.php:31`
  - Informational: `Declaration_Of_Catch_For_Generic_Exception` at `chains/CH-210-silent-order-loss/storefront/public/checkout.php:32`
  - Informational: `Detection_of_Error_Condition_Without_Action` at `chains/CH-210-silent-order-loss/storefront/public/checkout.php:25`
  - Informational: `Unchecked_Error_Condition` at `chains/CH-210-silent-order-loss/storefront/public/checkout.php:22`
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
(above 7.5). The tests also check that a chain stops assembling when every
result for any one of its links is removed. In other words, fixing one link
breaks the chain.

## Re-checking with a new scan

Scan this repository again, export the results as JSON, and run:

```bash
python demo.py path/to/results.json
```

Supported formats are Checkmarx One results JSON, SARIF 2.1.0, CxSAST legacy
JSON and the Vulnerability Type report. Each required finding in the catalog
is limited to its own chain folder (`match_file_contains`), so chains can't
match each other's findings in a whole-repository scan. The exit code is 0
when every chain fully assembles.

## Layout

```
demo.py                      run the chains and print chain CPS vs. severities
cps_engine/                  CPS scoring and chain-matching engine
catalog/chains_index.json    the ten chain definitions, with scan result ids
fixtures/scan_findings.json  findings from scan a71e672d, used offline
chains/CH-201 ... CH-210     one folder per chain (Node.js, Java, Python, PHP, Go)
tests/test_chains.py
```
