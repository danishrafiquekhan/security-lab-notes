**Part 13: Lab Metrics — What Actually Got Measured**<!--h1-->

Every number in this section is computed from timestamps inside evidence files already committed elsewhere in the portfolio (`atomic-red-team-validation`'s `evidence/*.json`, `detection-engineering`'s `sample-alert.json` files) — nothing here is estimated or aspirational. Where a real number can't be produced yet, that's stated as a gap, not filled in with a guess. This section exists because a lab that only ever shows "it fired" without ever asking "how fast, and against what" is missing half of what a real detection engineering role actually measures.

**Detection pipeline latency, by source**<!--h2-->

"Latency" here means the gap between the event happening at the source and Wazuh's alert timestamp — a real measure of each pipeline's own overhead, not of a human analyst's reaction time.

| Source | Event → Alert gap | Delivery mechanism |
|---|---|---|
| Sysmon (T1059.001, WMI-spawned PowerShell) | ~30 ms | Wazuh agent, real-time eventchannel push |
| Suricata (ET SCAN RDP/Nmap) | ~130 ms | Wazuh manager reading `eve.json` in near-real-time |
| Cloudflare (`/login.html` hit) | ~1.27 s | Relay script appending to a bind-mounted file, Wazuh's own file-watch cycle |
| Auth0 (failed client-credentials exchange) | ~12.5 s | Checkpoint-polling relay, 10-second poll interval — this number is bounded by that interval, not a pipeline defect |

The honest takeaway: push-based, agent-resident telemetry (Sysmon) is two orders of magnitude faster than a polling-based relay (Auth0), and that gap is architectural, not a bug to fix — it's the real tradeoff between "install an agent on the source" and "poll an API you don't control the push semantics of." Anyone building a detection pipeline against a SaaS API without native log streaming will hit this same ceiling.

MySQL's raw log timestamp isn't used for a latency figure here — `full_log`'s embedded time is in the container's local timezone while the Wazuh alert timestamp is UTC-normalized, a full-hour offset that would produce a nonsense negative-or-inflated number if subtracted naively. Rather than publish a wrong figure, this is flagged as a real instrumentation gap: the MySQL relay should timestamp events in UTC at the point of capture if this number is ever wanted for real.

**Multi-step attack chain timing**<!--h2-->

The T1078.004 LocalStack case study is the only evidence file capturing a full multi-step chain rather than a single event, so it's the only place a real "attack chain duration" figure exists:

- `CreateUser` alert: `07:45:21.592`
- `AttachUserPolicy` alert: `07:45:23.599`
- `CreateAccessKey` alert: `07:45:23.599`

Total real elapsed time from the first persistence-relevant action to the last, all three independently alerting, was **2.007 seconds** — driven by how fast the AWS CLI issued the three calls in sequence, not by any detection delay (all three rules fired essentially immediately on each event). This is a useful number for a specific reason: it shows the detection layer keeping up with an attack chain that a human running commands by hand would take much longer than 2 seconds to execute — the real-world constraint here would always be the attacker's own pace, not Wazuh's.

**MITRE ATT&CK coverage — fired vs. designed-only**<!--h2-->

| Technique | Status |
|---|---|
| T1059.001 (PowerShell) | **Fired for real** — rule 92071, Wazuh built-in Sysmon ruleset |
| T1047 (Windows Management Instrumentation) | **Fired for real** — same alert as above, dual-tagged |
| T1078.004 (Valid Accounts: Cloud Accounts) | **Fired for real** — rules 100031/100032/100033, LocalStack-adapted |
| T1110.003 / brute-force-adjacent (MySQL repeated failed auth) | **Fired for real** — Wazuh built-in `mysql_log` rule 50106 |
| Network scan detection (ET SCAN RDP/Nmap) | **Fired for real** — Suricata sid 2036252 via Wazuh rule 86601 |
| MFA fatigue / push-bombing | **Designed only** — Sigma + KQL written for Sentinel, never fired against real telemetry (see `identity-incident-response/mfa-fatigue/`) |
| Impossible travel | **Designed only** — same status, Sentinel-schema content, no live Entra/Sentinel tenant |

Five of seven tracked techniques have real fired evidence behind them. The two that don't are both blocked the same way — they need either a real Sentinel/Entra tenant or a real MFA-enrolled device and geographically distinct network egress, neither of which this lab has for free. That's tracked as an open gap, not glossed over — see Part 9 and the root `README.md` of `detection-engineering` for the same honesty applied at the repo level.

**What isn't measured yet**<!--h2-->

- **Alert-to-case time (Wazuh → TheHive).** Real cases have been created from real alerts (Cloudflare, MySQL, Suricata), but no run captured both the alert timestamp and the case-creation timestamp together, so no real MTTR-style number exists yet. The `custom-thehive` integration script would need one added line writing its own dispatch timestamp to produce this honestly.
- **Alert-to-case conversion / noise ratio.** How many real alerts across all five sources did *not* escalate to a case, versus how many did — a real signal-to-noise measurement TheHive's own case list could answer once the stack is brought back up and queried directly, rather than estimated.
- **False positive rate.** Every fired alert documented across this portfolio was fired by a test deliberately designed to trigger it — there is no real baseline of "how much of this lab's own benign daily activity gets flagged," because there isn't enough ambient real usage for that number to mean anything yet.

These three are the natural next real measurements, in the order they'd actually be built: alert-to-case timing only needs one code change to an integration script already running; noise ratio only needs TheHive brought up and its case/alert counts compared; a real false-positive baseline needs sustained ambient traffic this lab doesn't generate on its own.
