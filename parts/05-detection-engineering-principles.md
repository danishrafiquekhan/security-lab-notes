**Part 5: Detection Engineering Principles**<!--h1-->

This part explains the discipline behind the content in the `detection-engineering` repo — not just what a Sigma rule or a KQL query looks like, but why the format and workflow are built the way they are, and where this lab's own detection content ran into the real limits of "write once, run anywhere." The central teaching example of this whole part is the last one: the actual, current gap between what this lab's detection content is written for (Sentinel/KQL) and what its live SIEM actually is (Wazuh) — and why that gap was left open rather than papered over.

**5.1 Sigma rule anatomy**<!--h2-->

**Sigma** **[FREE]** (open, community-maintained YAML specification and tooling, `sigmahq/sigma` on GitHub, no license cost) is a generic, source-agnostic signature format for describing detection logic. Its entire reason to exist is stated plainly in this lab's own `detection-engineering` README: writing the same detection logic three times for three different query languages (KQL, SPL, Lucene, whatever) is a waste of effort, and worse, it means the logic itself — the actual security judgment about what pattern matters — is scattered across multiple platform-specific dialects instead of living in one place as the source of truth. A Sigma rule is written once, in a structured YAML document, and a converter (`sigma-cli` plus a target-specific backend/pipeline) compiles it into whatever query language a specific platform speaks. The Sigma file is the asset; the compiled KQL, SPL, or whatever else is one *output* of it — which is exactly why this lab keeps both the Sigma source and the generated KQL in the repo rather than just the compiled query, and treats the Sigma file as authoritative when the two could drift.

Here's a real rule from this lab, `sigma-rules/password-spray.yml`, with every field annotated:

```yaml
title: Potential Password Spray Against Azure AD      # human-readable name
id: 4c1a9e3d-5b7f-4a6e-8d2c-3f4a5b6c7d8e               # globally unique UUID —
                                                        # stable identity for this
                                                        # rule across renames/edits
status: experimental                                   # maturity: experimental,
                                                        # test, stable, deprecated
description: >
  Flags failed sign-in events that match common password-spray failure codes.
  This rule expresses the per-event condition only — the "many accounts, one
  source, short window" aggregation is added in the KQL layer...
references:
  - https://attack.mitre.org/techniques/T1110/003/
author: Danish Khan
date: 2026-08-29
tags:
  - attack.credential-access
  - attack.t1110.003                                   # MITRE ATT&CK mapping —
                                                        # see 5.3
logsource:                                              # WHERE this rule applies —
  category: authentication                              # what kind of log source
  product: azure                                        # (product/service pair)
  service: signinlogs                                    # this rule targets, before
                                                          # any specific query syntax
detection:
  selection:
    ResultType:
      - 50053  # account locked
      - 50126  # invalid username or password
  condition: selection                                  # boolean logic combining
                                                          # named selection blocks
falsepositives:                                          # honest, specific — see 5.4
  - Shared corporate NAT/VPN egress IP causing many users to appear to share a source IP
  - A single user genuinely mistyping their password multiple times
level: high                                             # severity: informational,
                                                          # low, medium, high, critical
```

The fields that do the real work are `logsource` and `detection`. `logsource` is deliberately abstract — it says "this rule needs an authentication-category log from Azure's sign-in service," not "query the `SigninLogs` table in Sentinel specifically." That abstraction is what makes conversion to different backends possible at all: a pipeline (covered in 5.2) is the piece of configuration that maps `logsource: {category: authentication, product: azure, service: signinlogs}` onto an actual table name in a specific platform. `detection` is where the actual matching logic lives — one or more named blocks (here just `selection`) combined by a `condition` field, which can reference multiple named blocks with `and`/`or`/`not` for more complex rules.

`falsepositives` and `level` look like boilerplate metadata but aren't — 5.4 covers why `falsepositives` in particular deserves real, specific content, not a placeholder.

**Where Sigma's single-rule model genuinely runs out**<!--h3-->

It's worth being honest about a real limitation this lab actually hit, because it's more instructive than a rule that converted cleanly: password spray is fundamentally an *aggregation* pattern — many distinct accounts failing from one source IP within a short window — and Sigma's single-rule specification has no clean way to express "count distinct X, grouped by Y, over a time window." The rule above only captures the per-event condition (which failure codes count as a spray-relevant failure); the aggregation logic is written by hand directly into the generated KQL file (shown in 5.2), with a comment explaining why it lives there instead of in the Sigma source. This is a real, acknowledged drift risk — if the failure-code logic in the Sigma rule changes, whoever updates it has to remember the hand-written KQL aggregation exists downstream and isn't automatically kept in sync by the converter. No cleaner solution was found within plain Sigma for this rule; it's flagged in this lab's own documentation as a known rough edge, not resolved.

**5.2 KQL fundamentals**<!--h2-->

**KQL (Kusto Query Language)** is the query language for Azure Log Analytics / Microsoft Sentinel (and Application Insights, and a few other Azure data stores built on the same Kusto engine). It's the compile target this lab's Sigma rules are converted to, via `sigma-cli` with the `kusto` plugin (`pipx install sigma-cli && sigma plugin install kusto`).

A handful of operators do almost all the real work in detection-relevant KQL:

- **`where`** — row-level filtering, the direct analog of a Sigma `selection` block. `SigninLogs | where ResultType in~ ("50053", "50126")` filters down to rows matching either failure code (`in~` is the case-insensitive membership operator).
- **`summarize`** — aggregation: collapsing many rows into grouped statistics. This is exactly the operator Sigma has no equivalent for, which is why it's the one hand-added to the generated password-spray KQL.
- **`bin()`** — time-windowing, almost always used inside a `summarize ... by` clause to bucket events into fixed intervals (`bin(TimeGenerated, 10m)` groups rows into 10-minute buckets) — this is what turns "count of failures" into "count of failures *per 10-minute window*," which is the difference between a meaningless running total and an actual burst-detection signal.
- **`join`** — combining rows from two tables on a matching key, used when the detection logic needs to correlate across log types (e.g., joining `SigninLogs` to `AuditLogs` to see whether a suspicious sign-in was followed by a specific administrative action).
- **`dcount()`** — distinct count, almost always the aggregation function actually being computed inside `summarize` for identity-abuse patterns, because "how many failures happened" is far less meaningful than "how many *distinct accounts* failed" — a single account retried ten times is a mistyped password; ten distinct accounts each failing once from the same source in the same window is a spray.

Here's the full generated KQL for the password-spray rule, showing how the Sigma `selection`/`condition` maps onto `where`, and how the hand-written aggregation extends it:

```kql
// Base condition below is what sigma-cli generates directly from the Sigma
// rule. The aggregation (many distinct accounts, one source, short window)
// is added by hand here — Sigma's single-rule spec has no clean way to
// express "count distinct X grouped by Y over a timeframe", so this part is
// maintained directly in KQL, with the Sigma rule as the source of truth for
// the underlying per-event condition it wraps.
SigninLogs
| where ResultType in~ ("50053", "50126")
| summarize
    FailedAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName, 20)
    by IPAddress, bin(TimeGenerated, 10m)
| where FailedAccounts >= 10   // tune this threshold against your own traffic before enabling
```

Reading this line by line against the operators above: `where ResultType in~ (...)` is the direct compile of the Sigma `selection`; `summarize FailedAccounts = dcount(UserPrincipalName) ... by IPAddress, bin(TimeGenerated, 10m)` is the hand-added aggregation, grouping by source IP and 10-minute time bucket and counting *distinct* accounts (not total failed events) per group; the final `where FailedAccounts >= 10` is a tunable threshold, explicitly commented as needing calibration against real traffic rather than trusted as a universal constant — ten failed accounts in ten minutes might be a loud, obvious spray on a small tenant and background noise on a large one with shared corporate NAT egress, which is exactly the false-positive scenario the rule's `falsepositives` field already names.

**The pipeline problem: why conversion isn't automatic for every log source**<!--h3-->

Converting Sigma to KQL isn't just "run the compiler" — it needs a **pipeline**, a small piece of configuration telling the converter which Sentinel table a given `logsource` maps to. The built-in `sentinel_asim` pipeline shipped with `sigma-cli` only knows a limited built-in list of log categories out of the box (things like `network_connection`); anything outside that list fails conversion with `unable to determine table name from rule` — not because the rule is wrong, but because Entra ID sign-in and audit logs simply aren't in that pipeline's default mapping. This lab's fix, `kql-conversions/pipelines/azuread-table-mappings.yml`, is a small (~15-line) custom pipeline that explicitly sets the table name for `SigninLogs`, `AuditLogs`, and `OfficeActivity` before `sentinel_asim`'s own resolution logic runs (it has to run at a lower priority number so it takes effect first). This is a concrete, real example of Sigma's platform-agnostic promise needing real, platform-specific glue work to actually deliver — "source-agnostic detection logic" doesn't mean zero platform-specific configuration exists anywhere in the pipeline; it means that configuration is isolated into one small, reusable mapping file instead of being baked into every individual rule.

**5.3 MITRE ATT&CK mapping as a discipline**<!--h2-->

**MITRE ATT&CK** **[FREE]** (public knowledge base, MITRE Corporation, no cost, no license) is a structured taxonomy of adversary tactics (the "why" — the attacker's goal, like Credential Access or Privilege Escalation) and techniques/sub-techniques (the "how" — a specific method, like T1110.003, Password Spraying, a sub-technique of the broader T1110 Brute Force technique).

Tagging a detection rule with an ATT&CK ID — as every rule in this lab does, e.g. `attack.t1110.003` on the password-spray rule, `attack.t1078.004` (Valid Accounts: Cloud Accounts) on the impossible-travel rule — does two real things beyond documentation. First, it gives the rule a stable, shared vocabulary that means the same thing across every detection engineering team on earth; "T1110.003" unambiguously means the same attacker behavior whether you're reading this lab's Sigma rule or a completely unrelated vendor's threat intel report. Second, and more operationally useful, it makes **coverage** a measurable, queryable thing instead of a vague impression.

This is exactly what `attack-mapping.csv` in this lab is for — a flat table tying every rule to its technique, its data source, and its actual status:

```csv
Rule,ATT&CK Technique,Data Source,Status
suspicious-signin-velocity,T1078.004,Azure AD Sign-in Logs (SigninLogs),converted (KQL) - not yet deployed/validated
password-spray,T1110.003,Azure AD Sign-in Logs (SigninLogs),converted (KQL) + hand-written aggregation - not yet deployed/validated
suspicious-oauth-consent,T1528,Entra ID Audit Logs (AuditLogs),converted (KQL) - not yet deployed/validated
privileged-role-assignment,T1098.003,Entra ID Audit Logs (AuditLogs),converted (KQL) - not yet deployed/validated
mass-file-download,T1567,M365 Unified Audit Log (OfficeActivity),converted (KQL) - not yet deployed/validated, high FP risk by design
conditional-access-policy-tampering,T1556.009,Entra ID Audit Logs (AuditLogs),converted (KQL) - not yet deployed/validated
suspicious-powershell-execution,T1059.001,Defender for Endpoint (imProcessCreate/DeviceProcessEvents),converted (KQL) - not yet deployed/validated
```

A table like this is what turns "we have detections" into an answerable question: which techniques does this rule set actually cover, against which data sources, and — critically, and honestly captured in the `Status` column here — which of those are just syntactically valid versus actually validated against real production data. Read across this table, the real coverage claim is narrower than "7 rules covering 7 techniques" sounds: every single row says "not yet deployed/validated," which is the honest state of this content (all 7 rules convert cleanly and are syntactically valid Sigma/KQL; none have run against a real Sentinel workspace with real sign-in traffic, so false-positive rates against real data are simply unknown). A coverage-tracking file that only recorded the technique mapping and left out the status column would overstate what this lab's detection content actually proves — the Status column is what keeps `attack-mapping.csv` honest rather than decorative.

At a larger scale, this same discipline is how a real detection engineering team decides where to invest next: cross-reference the techniques a rule set covers against the techniques most relevant to the organization's actual threat model (informed by industry reporting, red team findings, or a framework like the ATT&CK-based Center for Threat-Informed Defense's coverage heat maps), and the gap between the two *is* the backlog. Without ATT&CK mapping, "what are we missing" has no rigorous answer at all — just impressions.

**5.4 False positive tuning philosophy**<!--h2-->

Alert fatigue is not an abstract UX complaint — it's the mechanism by which a detection stops working even while it keeps firing correctly. An analyst who has seen the same rule fire 40 times for a benign reason stops reading alert #41 carefully, and alert #41 being the one real positive doesn't change that they've been trained, by every prior instance, to expect noise. This is a real cost with a real failure mode attached, and it's the reason the `falsepositives` field in a Sigma rule deserves to be treated as **a living, honestly-maintained piece of the rule's actual logic**, not a boilerplate field filled in once and forgotten.

Look again at the two rules quoted in 5.1 and 5.2. `impossible-travel.yml` names specific, plausible causes: "New device or browser used for the first time by a legitimate user" and "Corporate VPN or anonymizing proxy used intentionally by the organisation." `password-spray.yml` names "Shared corporate NAT/VPN egress IP causing many users to appear to share a source IP" and "A single user genuinely mistyping their password multiple times." Every one of these is specific enough to actually inform a tuning decision — a real analyst reading "shared corporate NAT/VPN egress IP" knows exactly what to check (is this source IP a known corporate egress point? if so, either exclude it or raise the distinct-account threshold for it specifically) rather than being handed a generic "some false positives may occur" that provides zero actionable direction.

The philosophy this implies: a `falsepositives` field should be written by actually thinking through "what legitimate, non-malicious activity would trigger this exact condition" for *this specific rule's exact logic*, not copy-pasted from a template. And it should change over time — as a rule actually runs against real traffic (which, honestly, none of this lab's 7 rules have done yet, per 5.3's status table), the *real* false-positive sources that show up in production should get added to this field, and thresholds (like `password-spray.yml`'s KQL layer `FailedAccounts >= 10`) should get tuned against what real traffic actually looks like, not left at a plausible-sounding placeholder forever. A `falsepositives` field that never changes after a rule goes live is a signal that nobody's actually reviewing what the rule fires on — which is the exact condition that produces alert fatigue in the first place, quietly, over months, until the rule gets muted or ignored rather than fixed.

The `mass-file-download` rule's status entry is worth calling out specifically here too: it's explicitly flagged in `attack-mapping.csv` as "high FP risk by design." That's an honest acknowledgment that some detections are inherently noisy because the underlying behavior (downloading many files) is extremely common and legitimate, and the rule exists anyway because the alternative — not detecting mass exfiltration via M365 at all — is worse than tuning a noisy rule down over time. Naming that risk explicitly, in the coverage table itself, is exactly the same honesty principle as a well-written `falsepositives` field: say what the rule will actually do in production, don't let the deployment discover it the hard way.

**5.5 The platform translation problem**<!--h2-->

This is the central teaching example of this whole part, and it's worth stating plainly rather than softening: **this lab's detection content is written for Microsoft Sentinel's KQL schema — `SigninLogs`, `AuditLogs`, `OfficeActivity` — but the SIEM actually running in this lab, live, is Wazuh** **[FREE]** (Apache 2.0-licensed, self-hosted, no tier or feature paywall — the full product is free). That's not an oversight to be fixed by "just converting the KQL to Wazuh's rule format." It's a real architectural mismatch, and understanding *why* it's real, not just asserted, is the actual lesson.

**Why "just convert it" isn't trivial**<!--h3-->

Wazuh is built around host- and network-level telemetry: log files tailed off a monitored endpoint (via its agent or `<localfile>` configuration), Windows Event Log channels, file integrity monitoring, rootkit/vulnerability detection, and its rule engine (decoders + rules, largely XML-based, matching against parsed log fields) is designed around that shape of data. This lab's own working example of Wazuh doing exactly what it's good at is the MySQL container monitoring: Wazuh ships built-in decoders and rules for MySQL's log format out of the box (`ruleset/decoders/0150-mysql_decoders.xml`, `ruleset/rules/0295-mysql_rules.xml`), so four deliberate wrong-password login attempts against the `soc-lab-mysql` container correctly fired Wazuh's built-in rule 50106 ("MySQL: authentication failure," level 9) with no custom Wazuh rule needed at all — because MySQL error-log-format authentication failures are precisely the kind of host-adjacent log Wazuh's ruleset was built to parse. The Cloudflare Pages traffic case is the same pattern one level harder: Wazuh has no built-in decoder for arbitrary JSON web logs, but it *does* auto-decode top-level JSON keys into `data.<field>` once told the log format is JSON, so only a custom *rule* (id 100011, matching `data.url` against `/login.html`) was needed, not a custom decoder — still fundamentally the same kind of task Wazuh is built for: matching structured fields inside a log line that arrives, one event at a time, from something that resembles a host or a web request.

Entra ID sign-in and audit logs are a completely different shape of problem. `SigninLogs` and `AuditLogs` are cloud identity provider telemetry — structured JSON records describing authentication and directory-management events at the *tenant* level, with no host, no agent, and no local log file to tail in the first place; the data lives in Microsoft's cloud and is queried through Log Analytics/KQL, not read off a filesystem. More importantly, the *detection logic itself* — the password-spray rule's `summarize dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 10m)` aggregation covered in 5.2 — is a cross-event, cross-account, time-windowed aggregation query, which is exactly the kind of query Kusto/KQL is built to express fluently and Wazuh's per-event decoder-and-rule matching engine is not built to express at all in the same way. Wazuh does have some correlation capability (rule-to-rule triggering within a time window via `<if_matched_sid>`/frequency rules), but reproducing "count distinct accounts failing from one IP in a 10-minute window, across a stream of cloud identity events that were never designed to land on a Wazuh-monitored host in the first place" would mean building an entirely separate ingestion pipeline (something to pull Entra ID logs out of Azure and reformat them into a form Wazuh could parse, conceptually similar to the MySQL relay script but for a fundamentally different, higher-volume, schema-rich data source) and then re-deriving the aggregation logic inside Wazuh's much more limited correlation primitives.

**Why forcing the fit would be worse than admitting the gap**<!--h3-->

It would be possible to *technically* write something that superficially resembles this detection logic as a Wazuh rule — matching on some subset of fields, approximating the aggregation with a frequency rule, producing an alert that looks like it's "the Wazuh version" of the password-spray detection. That would be worse than the honest gap, for a specific reason: it would produce a rule that *looks* deployed and functioning while actually evaluating a materially different, weaker condition than the one the Sigma rule and its `falsepositives` field were actually reasoned about — and nobody reading "password-spray: covered" in a status table would know that without reading the Wazuh rule's actual logic line by line. That's a worse state than an honest gap, because an honest gap is visible and can be prioritized; a fake-fit rule creates false confidence that quietly erodes the moment it's actually tested against real traffic (or, worse, never gets tested and just sits there being wrong).

This is why the actual decision in this lab was to pick **one honest target platform per piece of content** rather than force universal coverage: the Sigma/KQL detection content stays written and reasoned about against Sentinel's real schema, because that's the schema Entra ID identity telemetry actually has, and it's ready to point at a real Sentinel workspace the moment one exists — while Wazuh, running live in this lab today, is used for exactly what it's actually good at and actually has real data for right now (MySQL auth failures, HTTP request patterns from the Cloudflare Pages site), and is explicitly *not* asked to pretend it's evaluating cloud identity provider telemetry it was never built to receive.

**The generalizable lesson**<!--h3-->

The teaching point here generalizes well past this one lab: **"our detection content covers X" is a claim about logic, and that claim is only true for the platform the logic was actually reasoned about against.** A Sigma rule's portability is real — the same rule genuinely can target Splunk, Elastic, or Sentinel by swapping backends, because those are all query engines built to answer the same kind of question (structured search and aggregation over structured events) even if the syntax differs. But portability to a platform built for a *different kind of question entirely* — host telemetry versus cloud IdP telemetry — isn't a backend-swap problem, it's a "this platform cannot ask this question the way it needs to be asked" problem, and no amount of syntax conversion fixes that. Recognizing which kind of gap you're looking at — and saying so plainly in a status table or a README, the way `attack-mapping.csv`'s status column and this lab's own documentation do — is the actual discipline. Pretending broad coverage exists because two rules technically both have the word "rule" in them is the failure mode this whole section exists to name and avoid.
