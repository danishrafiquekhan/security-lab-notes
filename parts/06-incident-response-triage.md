**Part 6: Incident Response & Triage Workflows**<!--h1-->

**6.1 The alert → investigation → case → resolution lifecycle**<!--h2-->

Every incident response process, no matter how mature the organization, moves
through the same four stages. Understanding what each stage is actually *for*
— and where the boundaries between them sit — matters more than memorizing
tool names, because the tools change (this lab uses Wazuh **[FREE]** and
TheHive/Cortex **[FREE]**; a production shop might use Splunk **[PAID]** and
ServiceNow SecOps **[PAID]**) but the stages don't.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/06-incident-response-triage-12.png)

**Alert** is a machine-generated signal: a correlation rule matched a pattern
in log data and produced a record with a severity level, a source, and some
context. An alert is a *hypothesis*, not a finding. Wazuh's rule 100011
firing on a request to `/login.html` on the lab's Cloudflare Pages site is an
alert: it says "this pattern is worth a human look," nothing more. It does
not mean an attack happened.

**Triage** is the stage most often confused with "investigation," and the
distinction matters enough to state plainly: triage is a rapid initial
assessment, not a full investigation. Its job is to answer a small, fixed set
of questions fast — who or what is involved, how many events, is this
expected activity, does this warrant escalation — using only the evidence
already sitting in the alert plus one or two quick supporting queries. Triage
that takes twenty minutes and touches six different log sources has stopped
being triage; it has quietly become an investigation with a light disguise.
A SOC that cannot triage in under a few minutes per alert cannot keep up with
alert volume, which is precisely why triage exists as a distinct, disciplined
step rather than everyone just "starting to investigate."

**Investigation** is what happens after triage concludes an alert is worth
real time: full evidence gathering across every relevant log source, scoping
("what else did this actor touch"), timeline reconstruction, and — critically
— it happens inside a **case**, not inside the SIEM's alert queue. This is
where a case management system earns its keep. A SIEM like Wazuh is built to
ingest, correlate, and surface events at scale; it is not built to hold a
running narrative of "here is everything we know about incident #47,
assigned to analyst X, evidence attached, decisions logged with timestamps
and reasoning." That is a fundamentally different data model — structured
casework, not log correlation — and it is exactly the gap TheHive **[FREE]**
(case management) and Cortex **[FREE]** (automated observable enrichment,
running analyzers against IOCs attached to a case) are designed to fill.
TheHive gives a case a lifecycle (open → in progress → closed), tasks,
observables, and an audit trail; Cortex takes an observable dropped into a
case — an IP, a hash, a domain — and runs it through configured analyzers
automatically.

**Resolution** closes the loop: root cause determination, containment
verification, and — the step most SOCs skip under time pressure but
shouldn't — feeding what was learned back into detection engineering. If an
alert turned out to be a true positive that took too long to catch, that's a
detection gap to close. If it turned out to be a noisy false positive, that's
a tuning task. Resolution without that feedback loop just means the same
class of incident gets triaged from scratch again next time.

**The honest gap in this lab**<!--h3-->

Wazuh and TheHive/Cortex both run in this lab (`~/securitylab/wazuh-docker`
for Wazuh; TheHive 5.4 + Cortex 3.1.7 backed by Cassandra 4.1 and
Elasticsearch 7.17.24 for the case management side), but **they are not wired
together**. TheHive and Cortex's containers exist and have been built, but
were stopped/idle during this lab session, and there is no active integration
— no webhook, no Wazuh-to-TheHive connector, nothing — that turns a Wazuh
alert into a TheHive case automatically. This is a real, documented gap, not a
detail being glossed over: today, when Wazuh's rule 100011 or rule 50106
fires, that alert lives and dies in the Wazuh dashboard's alert list. Nobody
and nothing opens a case for it. In a production SOC this integration is
usually one of the first pieces of plumbing built (Wazuh can forward alerts
via its integration framework — a shell/Python script hook, or a Filebeat
output — to a webhook that creates a TheHive case, and Cortex-Wazuh-Connector
is a real open-source project built for exactly this), but in this lab it
remains a next step, not a finished capability. Anyone reading this
document and reproducing the lab should treat "wire Wazuh alerts into
TheHive automatically" as an explicit, valuable extension exercise, not
something to assume already exists.

**When to use a dedicated case management system / when not to**<!--h3-->

**Use one** the moment more than one person needs to work an incident, or the
moment "what did we do and why" needs to survive longer than someone's memory
of a Slack thread. Use one when observables need repeatable automated
enrichment (Cortex analyzers) rather than an analyst manually pasting a hash
into five different lookup sites every time. Use one when compliance or
after-action review requires a defensible audit trail of who decided what,
when.

**Don't bother** for a one-person lab where every alert gets looked at within
minutes and closed the same session — the overhead of opening and maintaining
a case for every single alert exceeds the value, which is part of why this
lab's current single-analyst workflow (a human looking directly at the Wazuh
dashboard) hasn't urgently needed the TheHive integration finished yet. The
gap is real and worth closing for the sake of completeness and practice, but
it isn't blocking anything today, precisely because alert volume here is low
and there's only one person triaging.

**6.2 Real case walkthroughs**<!--h2-->

The following walkthroughs are graded by how real they are. Some are fully
worked runbooks from this lab's actual repos. Some are real alerts that
actually fired during this lab session, with real evidence. One category is
explicitly hypothetical — planned but not yet run — and is labeled as such
throughout; it is included because it teaches what triage *would* look like
once the missing piece (a Windows VM with telemetry) exists.

**Walkthrough 1: The GUID triage runbook (`detection-engineering/guid-triage/`)**<!--h3-->

This is the fullest worked example in the portfolio, built specifically to
teach triage discipline for a hard identity-security problem: a GUID (a
service principal ID, an object ID, an application ID) shows up in a sign-in
log or audit log, and the analyst has to figure out what it actually is
before deciding whether the activity is a threat.

**What the analyst sees.** A Sentinel-schema `SigninLogs` or `AuditLogs`
entry where the actor or target is a raw GUID rather than a friendly
username — e.g. a service principal authenticating, or an application ID
appearing as the actor in an audit event. Unlike a human sign-in, there's no
immediately readable "who," and that opacity is exactly what makes GUIDs a
favorite blind spot: analysts under time pressure sometimes wave a GUID
through as "probably some system thing" without checking, which is the
failure mode this runbook exists to prevent.

**What the analyst checks, in order:**

1. **Resolve the GUID's identity first.** Query Entra ID (via `az ad sp show
   --id <guid>` or the Graph API `/servicePrincipals/{id}` endpoint) to
   determine what the GUID actually is: a first-party Microsoft service
   principal, a third-party enterprise application, a custom-registered app
   your org owns, or — if the lookup returns nothing — a GUID that no longer
   resolves to any object, which is itself a signal worth flagging (deleted
   app, or a fabricated/spoofed ID that never existed).
2. **Check the application's owner and creation date.** A service principal
   created yesterday behaving unusually is a very different story than one
   that's been running unchanged for two years.
3. **Check what permissions/scopes it holds.** A GUID with `Directory.Read.All`
   or high-privilege Graph scopes acting oddly is a materially higher-severity
   finding than one scoped to read a single mailbox.
4. **Check the pattern of activity, not just the single event.** Is this
   service principal authenticating from its usual pattern (same conditional
   access policy results, same IP ranges/ASNs, same frequency), or is this a
   deviation — a new location, a burst of activity, a permission grant it's
   never made before?
5. **Cross-reference against known-good inventories.** Does this GUID appear
   in an approved application registry / CMDB? An unlisted GUID performing
   directory changes is far more suspicious than a listed one.

**Conclusion the runbook teaches the analyst to reach:** a GUID is not
inherently suspicious — most sign-in and audit noise involving GUIDs is
completely legitimate automation (backup jobs, sync connectors, monitoring
tools) — but a GUID is also not inherently *trustable by virtue of being a
machine identity*, which is the actual bias this runbook is correcting for.
The triage verdict is a function of identity resolution + privilege level +
behavioral deviation, evaluated in that order, and an analyst who skips step
1 (resolving what the GUID even is) cannot honestly reach any verdict at all.

**Walkthrough 2: The two BEC/phishing cases (`detection-engineering/bec-phishing/`)**<!--h3-->

These two cases model the alert-to-verdict path for business email
compromise, using Sigma rules built against email/identity telemetry.

**Case A — Invoice fraud via bulk-mail infrastructure.** The pattern: an
attacker sends a fraudulent invoice or payment-redirect email that is not
sent from a compromised internal mailbox, but from bulk commercial email
infrastructure (mass-mailer services, marketing platforms) — mail servers
with real deliverability reputation, making the mail more likely to bypass
spam filtering than a fly-by-night sender domain would. The detection logic
centers on the mismatch between the claimed sender identity (a name/display
matching a known vendor or internal finance contact) and the actual sending
infrastructure (a bulk-mail provider's IP/domain that has no legitimate
business relationship with that claimed identity), combined with
payment-redirect language patterns in the body/subject. Alert-to-verdict:
the alert fires on the infrastructure mismatch; the analyst confirms by
checking whether the claimed sender has ever legitimately used that bulk-mail
provider before (usually no) and whether the message contains bank-detail-
change or urgent-payment language (usually yes) — verdict reached without
needing a full mailbox compromise investigation, because the sending
infrastructure alone tells the story.

**Case B — Executive impersonation via personal email.** The pattern: an
attacker registers or uses a personal free-webmail address (Gmail, Outlook.com
style) and sets the display name to match a real executive's name, then
emails staff — typically finance or HR — with an urgent, authority-pressured
request (wire transfer, gift cards, sensitive data). The detection logic
here centers on display-name spoofing detection: a message where the display
name matches an internal executive but the underlying envelope/from address
domain is an external free-webmail domain, especially when combined with
urgency/authority-pressure language and a request type (financial,
credential, data) that the real executive would not normally make by email
to that recipient. Alert-to-verdict: the alert fires on the display-name/
domain mismatch; the analyst confirms by checking the actual sending domain
against the executive's real corporate domain (trivial mismatch check) and
by noting the classic BEC social-engineering markers (urgency, secrecy
requests, off-channel payment instructions) — verdict reached quickly because
the domain mismatch is a near-deterministic signal once you know to look at
envelope-from rather than display-name.

Both cases teach the same underlying lesson from a different angle than the
GUID runbook: in BEC, the *infrastructure/domain* is almost always the
highest-signal thing to check first, because attackers can spoof a display
name trivially but cannot spoof legitimate sending infrastructure without
actually compromising it.

**Walkthrough 3: T1078.004, run for real, adapted via LocalStack**<!--h3-->

The `atomic-red-team-validation` repo contains two case study folders —
**T1078.004 (Valid Accounts: Cloud Accounts)** and **T1059.001 (Command and
Scripting Interpreter: PowerShell)**. Both have now actually been run;
T1059.001's real result is Walkthrough 4 below. T1078.004's official Atomic
Red Team tests all require real Azure/GCP cloud resource creation — checked
with a `-ShowDetails` dry-run before deciding this — so rather than force a
real-cloud-touching test, the same underlying "valid account establishes
persistence" concept was adapted using AWS IAM against LocalStack instead.

- **Who:** the `test` credential (LocalStack's documented placeholder, not a
  real identity) creating a new IAM user, `backup-svc-account` — an
  intentionally innocuous name mirroring real attacker backdoor-account
  naming conventions.
- **What:** three sequential IAM API calls — `CreateUser`, then
  `AttachUserPolicy` (AdministratorAccess), then `CreateAccessKey` — the
  actual persistence mechanism, since a fresh access key survives revocation
  of whatever credential the attacker originally used to get in.
- **How many:** one deliberate test sequence, all three steps captured as
  separate alerts.
- **Is this expected:** yes, deliberate validation traffic — but the point
  was confirming detection, which it did: three custom Wazuh rules (no
  built-in AWS/CloudTrail decoder exists) fired cleanly, correctly tagged
  MITRE T1078.004, with `CreateAccessKey` weighted highest (level 9) since
  it's the actual persistence step, not just a precursor. One-line verdict:
  *"Expected — deliberate technique validation; all three persistence steps
  caught with correct MITRE tagging, no custom-rule gaps found."* A real
  attacker's identical sequence in a real cloud account would warrant
  immediate credential revocation and a review of what that new access key
  was subsequently used for.

Worth being explicit, the same honesty this document applies everywhere
else: this validates the detection *concept*, not the literal official
Atomic Red Team test for T1078.004 — see that case study's own README for
the full accounting of what this does and doesn't prove relative to the
real (cloud-login-requiring) test.

**Walkthrough 4: T1059.001, run for real, caught by Wazuh's built-in Sysmon ruleset**<!--h3-->

Unlike T1078.004 above, this one actually happened. Sysmon and the Wazuh
agent are installed on the Windows VM (Part 9, Lab 5), and a real encoded
PowerShell execution was run against it and caught clean.

- **Who:** the built-in Administrator account on the isolated lab VM
  (`WIN-ATOMICLAB`) — a real deviation from `atomic-red-team-validation`'s
  own stated rule of using a separate throwaway local account, documented
  honestly in that repo's `LAB-SETUP.md` rather than glossed over.
- **What:** `powershell.exe -NoProfile -E <base64>`, decoding to a harmless
  `Write-Host <test GUID>` — Atomic Test #15 for T1059.001 (not Test #1,
  which turned out to be Mimikatz, caught via a `-ShowDetails` dry-run
  *before* anything executed). The process was launched via WMI
  (`WmiPrvSE.exe` as parent), not a direct shell spawn — a real execution
  detail, not something planned for.
- **How many:** one deliberate test execution, plus 36+ incidental Sysmon
  file-create events from .NET's own script-block compilation caching —
  noise from a completely benign side effect, not part of the technique
  itself, and a real, live example of the alert-fatigue problem this
  document discusses elsewhere.
- **Is this expected:** yes, in the sense that it was deliberate, controlled
  test traffic — but the point of running it wasn't to confirm something
  benign, it was to confirm Wazuh's detection actually fires on this
  execution pattern, which it did: rule `92071` (level 12), correctly
  tagged with both **T1047** (WMI) and **T1059.001** (PowerShell), full
  command line and file hashes captured. One-line verdict: *"Expected —
  deliberate technique validation; Wazuh's built-in Sysmon ruleset caught
  it cleanly with correct dual MITRE mapping, no custom rule needed."* The
  real gap this surfaced wasn't the detection rule — it was that Wazuh's
  Windows agent doesn't monitor the Sysmon channel by default at all,
  documented in Part 10.13, which would have made this alert impossible
  regardless of rule quality.

**Walkthrough 5: The real live-fired alerts from this lab session**<!--h3-->

These are also genuinely real: they fired
during this lab session, against real (synthetic-but-live) traffic, and
produced real alert JSON in the Wazuh dashboard. These are deliberately
kept as **micro-triage** examples — real alert, real one-line assessment —
because that is what most day-to-day triage actually looks like: fast,
terse, and conclusive without needing an open case.

**Alert: Cloudflare `/login.html` rule (custom rule ID 100011, level 7).**
Fired when a request hit `/login.html` on the lab's public Cloudflare Pages
site (`soc-lab-target.pages.dev`), captured via the Pages Function →
`wrangler tail` → Python relay → Wazuh pipeline (see Part 9, Lab 2 for the
full data path).

- **Who:** the client IP surfaced via Cloudflare's `cf-connecting-ip` header
  in the alert JSON, plus country and user-agent.
- **What:** an HTTP request to `/login.html`, a page that does nothing but
  log to console — there is no real authentication behind it.
- **How many:** the request count for that source in the observed window
  (a single curl-driven test in this case, since the traffic generating
  this alert was the analyst's own verification curl requests).
- **Is this expected:** yes — this was deliberate verification traffic
  generated by the analyst to confirm the detection pipeline worked
  end-to-end, not an actual external actor. One-line verdict: *"Expected —
  self-generated test traffic confirming rule 100011 fires correctly on
  /login.html requests; no real actor involved, pipeline verified
  functional."* In a live scenario with unrecognized source IPs hitting this
  same page, the verdict would instead flag it as possible scanner/
  credential-testing reconnaissance, per the rule's framing, and warrant a
  quick IP reputation check as the next triage step.

**Alert: MySQL failed-auth rule (built-in Wazuh rule ID 50106, level 9,
"MySQL: authentication failure").** Fired against the `soc-lab-mysql`
container via the general/error log → Python relay → Wazuh localfile →
Wazuh's *built-in* `mysql_log` decoder/rule pipeline (no custom rule needed
— see Part 9, Lab 3).

- **Who:** the MySQL client connection recorded in the error log for the
  failed authentication attempt.
- **What:** four deliberate wrong-password login attempts against the
  container, generated by the analyst as a verification test.
- **How many:** 4 failed attempts in the observed window.
- **Is this expected:** yes — deliberately generated to confirm the
  built-in MySQL detection pipeline worked, and it did: rule 50106 fired
  correctly and auto-mapped to PCI DSS/GDPR/HIPAA/NIST 800-53 compliance
  controls out of the box, which is one of the real advantages of using a
  SIEM's built-in ruleset over a custom one — that compliance mapping came
  for free. One-line verdict: *"Expected — 4 self-generated failed logins
  confirming rule 50106 and MySQL log ingestion pipeline work correctly; no
  real brute-force actor involved."* In a live scenario, the same rule
  firing against a source that isn't the analyst's own testing would prompt
  an immediate check of attempt volume and source — a handful of failures
  from one internal IP is very different from hundreds from an external one.

**Walkthrough 6: The two identity incident-response case studies (`detection-engineering/identity-incident-response/`)**<!--h3-->

These two are a stronger example of a full case-study lifecycle than anything else in this document, Walkthroughs 3 and 4 included: `detection-engineering/identity-incident-response/` contains **full, complete lifecycle case studies** — detection through lessons learned, each with a Sigma rule, an incident report, a playbook, and a hunting query — grounded in a fictional Contoso scenario (`j.reyes@contoso.com`).

**MFA fatigue / push-bombing.** The detection is a brand new Sigma rule, `mfa-fatigue-detection.yml` (tagged `T1621` and `T1110`), with the same known Sigma limitation as this lab's `password-spray.yml` rule: Sigma can't natively express the aggregation logic the detection needs, so it's hand-written into the generated KQL with a comment explaining why. The incident report, playbook, and hunting query built around it walk a full push-bombing scenario end to end — an attacker with valid credentials spamming MFA push approvals, exactly the attack pattern named in Part 4.4's MFA discussion.

**Impossible travel.** This case study builds the missing lifecycle artifacts — incident report, playbook, hunting query — on top of the Sigma rule that already existed in this repo (`sigma-rules/impossible-travel.yml`), rather than duplicating it. The hunting query is a genuinely complementary detection angle, not a restatement: it does independent geo-velocity math (distance between sign-in locations over time, checked against a plausible travel speed) instead of relying on Entra ID's own `RiskEventTypes` field, which is a real, worked example of the "don't rely on a single signal" triage discipline this document teaches elsewhere.

Both playbooks are explicit, the same honest framing used throughout this document and `sentinel-soar-playbooks`, that they are designs — not deployed, executing automations. What makes these two walkthroughs worth citing here specifically is that they are the strongest available example in this portfolio of a *complete* case-study lifecycle (not just a single real alert, and not just a rule) — genuinely stronger evidence of end-to-end incident-response thinking than a rule on its own would be.

**6.3 A generic triage runbook template**<!--h2-->

The structure below is deliberately modeled on the shape of the GUID triage
runbook — identity resolution first, context and privilege second, behavioral
deviation third, verdict last — generalized so it applies to *any* new alert
type, not just identity/GUID alerts. Use this as a starting skeleton when a
detection fires on something with no existing runbook yet.

**1. Context and scope**<!--h3-->

- What exactly fired the alert — which rule ID, which detection logic, what
  raw event triggered it?
- What is the blast radius if this is real — one account, one host, one
  application, or something broader?
- What time window does this alert cover, and is there a natural window to
  extend the query into (a few minutes before/after) to catch related
  activity the single event doesn't show?

**2. Initial hypothesis**<!--h3-->

- State, in one sentence, what this alert is claiming might be happening.
  Being explicit here (rather than jumping straight to evidence-gathering)
  forces clarity about what you're actually trying to confirm or deny —
  exactly the discipline the GUID runbook enforces by making "resolve the
  GUID's identity" the mandatory first step rather than an optional one.

**3. Evidence gathering (the "who/what/how many" of triage)**<!--h3-->

- **Who/what** is involved — resolve raw identifiers (GUIDs, IPs, hashes,
  usernames) to something meaningful before doing anything else. An
  unresolved identifier is not evidence, it's a placeholder.
- **How many** — is this a single event or a pattern? Volume changes the
  verdict more than almost anything else.
- **Context checks** — does this match a known-good inventory, an approved
  application list, a normal behavioral baseline for this identity/host?
  Pull only what's needed to answer the hypothesis — triage stops here,
  investigation is what happens if more is needed.

**4. Confirm or deny**<!--h3-->

- Based on steps 1–3 only, reach one of three verdicts: **benign/expected**
  (close with documented reasoning), **needs investigation** (escalate to a
  case), or **inconclusive** (a legitimate third outcome — document what's
  missing and either escalate anyway on caution, or set a follow-up).
- Do not let "I'm not sure" default silently to "close it" — an inconclusive
  triage that gets closed without escalation is how real incidents get
  missed.

**5. Containment decision**<!--h3-->

- If escalating: does this warrant an immediate containment action (disable
  an account, isolate a host) before the full investigation completes, or
  can containment wait until the case has more evidence? This decision
  mirrors the human-approval-gate logic covered in Part 7 for automated
  response — the same reasoning about irreversibility and blast radius
  applies whether the containment action is manual or automated.

**6. Documentation**<!--h3-->

- Record the verdict and the one or two pieces of evidence that drove it,
  even for a benign close — especially for a benign close, because that's
  the record that lets someone later ask "why was this alert dismissed" and
  get a real answer instead of "the analyst probably checked and it was
  fine." This is the exact discipline a case management system like TheHive
  is built to enforce structurally; until Wazuh and TheHive are wired
  together in this lab, that documentation has to happen manually, which is
  itself a good argument for finishing that integration.
