**Part 11: Glossary**<!--h1-->

Alphabetical reference for terms and acronyms used throughout this
document. Definitions are written to be precise and specific to how the
term is actually used in this lab, not generic dictionary text.

**A**<!--h2-->

**Answer file (`autounattend.xml`)** — an XML file that supplies Windows
Setup with pre-determined install-time answers (disk partitioning,
locale, admin password, first-boot commands) so an installation can run
fully unattended, with no human clicking through the installer GUI.
Windows Setup automatically scans attached removable media (including a
CD-ROM) for a file with this exact name during its early (windowsPE)
install pass.

**ATT&CK (MITRE ATT&CK)** — a publicly maintained knowledge base of
real-world adversary behavior, organized as a matrix of **tactics**
(the adversary's goal at a given stage, e.g. Initial Access, Persistence,
Privilege Escalation), **techniques** (a specific method used to achieve
a tactic, e.g. T1078 Valid Accounts), and **sub-techniques** (a more
specific variant of a technique, e.g. T1078.004 Cloud Accounts). Used in
this lab both to map detection rules to the behavior they catch
(`attack-mapping.csv`) and to structure adversary-emulation test plans
(Atomic Red Team).

**B**<!--h2-->

**BEC (Business Email Compromise)** — a fraud technique where an
attacker compromises or spoofs a business email account/identity (often
an executive or finance-team member) to trick a target into taking a
harmful action, most commonly an unauthorized wire transfer or a
credential/gift-card request. Distinct from generic phishing in that it
usually skips malware entirely and relies purely on social engineering
and a convincing sender identity.

**C**<!--h2-->

**Cortex** — the analyzer/responder automation engine paired with
TheHive, used to run enrichment and response actions (e.g. reputation
lookups, IOC checks) against observables attached to a case.

**CSP (Content-Security-Policy)** — an HTTP response header that tells a
browser which sources (scripts, styles, images, frames, etc.) a page is
allowed to load content from, used as a defense-in-depth control against
cross-site scripting and data-injection attacks by restricting what a
compromised or injected script is actually allowed to do.

**D**<!--h2-->

**Decoder (Wazuh)** — see "Decoder vs. rule."

**Decoder vs. rule (Wazuh-specific distinction)** — in Wazuh, a
**decoder** is responsible for parsing a raw log line into structured
fields (extracting a source IP, a status code, a username, etc. from
unstructured text) — it decides whether a line is even recognized at
all, often gated by a **prematch** pattern that the start of the line
must match before decoding proceeds further. A **rule** then evaluates
the *already-decoded* fields against conditions (this field equals X,
this decoder's output combined with another recent event, etc.) to
decide whether to generate an alert, at what severity level. A log line
that never matches any decoder's prematch pattern never reaches rule
evaluation at all, regardless of how well-written the applicable rule is
— this is exactly the failure mode documented in Part 10's MySQL
log-format case study.

**Detection engineering** — the discipline of building, testing, tuning,
and maintaining the actual detection logic (rules, queries, correlation
searches) that turns raw telemetry into meaningful security alerts —
distinct from simply "having a SIEM," since a SIEM ingesting logs with no
tuned detection content on top of it produces either silence or noise,
not signal.

**Detection mode (WAF)** — a WAF operating mode where a request matching
a rule is logged as if it would have been blocked, but is still allowed
through to the backend unmodified — used to observe and tune a ruleset's
false-positive rate against real traffic before switching to prevention
mode. See Part 8.3.

**F**<!--h2-->

**False positive / false negative** — a **false positive** is an alert
that fires on activity that was not actually malicious or was not the
condition the detection was meant to catch (wastes analyst time, and
enough of them causes real alerts to get ignored — "alert fatigue"). A
**false negative** is malicious activity that a detection *should* have
caught but didn't (a silent, undetected gap — generally the more
dangerous of the two failure modes, since nothing draws attention to it).

**G**<!--h2-->

**GUID (Globally Unique Identifier)** — a 128-bit identifier
(`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` format) used, among many other
places, by Microsoft Entra ID/Azure AD to identify users, groups,
applications, and roles uniquely and immutably — unlike a display name
or UPN, a GUID doesn't change if an object is renamed, which is why
identity investigations often need to resolve a GUID back to a
human-readable identity as an explicit triage step (see the
`guid-triage` runbook referenced in the Identity Security section).

**H**<!--h2-->

**HSTS (HTTP Strict-Transport-Security)** — an HTTP response header that
tells a browser to only ever connect to this host over HTTPS for a
specified duration, protecting against protocol-downgrade and
SSL-stripping attacks on subsequent visits by refusing to even attempt a
plain-HTTP connection.

**hvf (Hypervisor.framework)** — Apple's built-in hardware virtualization
acceleration framework on macOS, analogous to KVM on Linux and WHPX on
Windows — lets a hypervisor (like QEMU) use the CPU's own virtualization
extensions instead of software emulation, which is dramatically faster
but only works when guest and host CPU architectures match.

**I**<!--h2-->

**IaC (Infrastructure as Code)** — managing infrastructure (cloud
resources, networking, compute) by describing it in version-controlled
configuration files (e.g. Terraform HCL) and applying that description
through a tool, rather than configuring resources by hand through a
console/UI — enables review, repeatability, and a diffable history of
infrastructure changes.

**IdP (Identity Provider)** — a system that authenticates users and
issues identity assertions/tokens that other applications (relying
parties) trust, rather than each application handling its own username/
password authentication independently. Microsoft Entra ID, Auth0, and
Okta are all IdPs.

**IOC (Indicator of Compromise)** — an observable artifact (an IP
address, file hash, domain name, email address) associated with known or
suspected malicious activity, used to search for or match against
telemetry to find evidence of that activity elsewhere.

**J**<!--h2-->

**JML (Joiner-Mover-Leaver)** — the identity lifecycle framework covering
the three key transition points of an identity's relationship with an
organization: joining (provisioning access for a new hire), moving
(adjusting access when someone changes role/department), and leaving
(deprovisioning access when someone departs) — a common source of
identity security gaps is a broken or incomplete Mover or Leaver process
leaving stale, unnecessary access in place.

**K**<!--h2-->

**KQL (Kusto Query Language)** — the query language used by Microsoft
Sentinel (and Azure Data Explorer/Log Analytics more broadly) to search
and analyze log data — the language this lab's `detection-engineering`
repo's Sentinel-facing detection content is written in, targeting tables
like `SigninLogs` and `AuditLogs`.

**L**<!--h2-->

**Localfile (Wazuh config term)** — a `<localfile>` block in Wazuh's
agent/manager configuration (`ossec.conf`) that tells Wazuh to monitor a
specific file or log source (a file path, a Windows Event Channel, a
command's output) and feed its content into the decoder/rule pipeline —
the mechanism this lab uses, with `<log_format>syslog</log_format>` and
`<log_format>json</log_format>` respectively, to ingest the relayed MySQL
logs and the relayed Cloudflare Pages traffic logs.

**Logpush** — Cloudflare's feature for continuously streaming logs
(HTTP requests, firewall events, etc.) to an external destination
(storage, a SIEM) — a paid-tier feature, which is why this lab's
Cloudflare Pages traffic is instead captured via `wrangler ... tail`
rather than Logpush.

**M**<!--h2-->

**MFA (Multi-Factor Authentication)** — requiring more than one
independent proof of identity to authenticate (typically something you
know, like a password, plus something you have, like an authenticator
app or hardware key) — a baseline control against credential-only
compromise, and required on this lab's Azure account specifically as a
condition of doing any IaC work against it.

**O**<!--h2-->

**OIDC (OpenID Connect)** — an identity/authentication layer built on top
of OAuth 2.0, adding a standardized way for a client to verify a user's
identity and obtain basic profile information via an ID token — commonly
used alongside or instead of SAML for modern application sign-in flows.

**P**<!--h2-->

**PIM (Privileged Identity Management)** — a Microsoft Entra ID feature
for just-in-time, time-bound activation of privileged roles, rather than
standing/permanent privileged role assignment — reduces the window an
elevated-privilege identity is actually usable, and creates an
approval/audit trail each time a role is activated.

**Playbook** — in this document's usage, a documented, structured
response procedure for handling a specific type of security event or
alert (e.g. this lab's MFA fatigue and impossible-travel playbooks) —
distinct from a SOAR *automation* playbook (see `sentinel-soar-playbooks`),
though the two terms overlap: an analyst-facing playbook can be the basis
a SOAR automation is later built from.

**Prematch (Wazuh decoder term)** — see "Decoder vs. rule."

**Prevention mode (WAF)** — a WAF operating mode where a request matching
a blocking rule is actually blocked in real time, as opposed to detection
mode's log-only behavior. See Part 8.3.

**R**<!--h2-->

**RBAC (Role-Based Access Control)** — an access control model where
permissions are granted to roles, and identities are granted membership
in roles, rather than permissions being assigned to individual identities
directly — makes access easier to reason about and audit at scale than
per-identity permission assignment.

**S**<!--h2-->

**SAML (Security Assertion Markup Language)** — an XML-based standard for
exchanging authentication and authorization assertions between an IdP
and a service provider, commonly used for enterprise single sign-on —
older than OIDC but still widely deployed, especially in enterprise SaaS
integrations.

**SIEM (Security Information and Event Management)** — a platform that
centrally collects, normalizes, and correlates log/event data from many
sources and applies detection logic to it to generate alerts — Wazuh and
Microsoft Sentinel are both SIEMs (Wazuh also markets itself as XDR; see
below).

**Sigma** — a generic, platform-agnostic format for writing detection
rules, designed to be convertible into the native query language of many
different SIEM/log platforms (Splunk SPL, Elastic Query DSL, Sentinel's
KQL, and others) from a single source rule — this lab's
`detection-engineering` repo authors detection logic in Sigma first, then
maintains KQL conversions for Sentinel's schema.

**SOAR (Security Orchestration, Automation and Response)** — a platform
or capability for automating and orchestrating incident response
actions — enrichment, containment, notification — often chained together
into playbooks triggered by a SIEM alert. TheHive/Cortex here, and the
Sentinel Logic Apps playbook *designs*, are both SOAR-category tooling.

**T**<!--h2-->

**TCG (Tiny Code Generator, QEMU context)** — QEMU's built-in software
CPU emulation backend, used when hardware-accelerated virtualization
(hvf/KVM/WHPX) isn't available or applicable — notably, running an x86_64
guest (Windows Server) on an Apple Silicon (ARM64) host requires TCG,
since there is no hardware acceleration path for emulating a different
CPU architecture than the host's own — which is exactly why this lab's
Windows Server VM install took over an hour: it is genuinely,
substantially slower than hardware-accelerated virtualization.

**Triage** — the initial assessment step of incident response: given a
raw alert or report, quickly determining its likely severity, whether it
is a true or false positive, and what (if anything) needs to happen next
— distinct from full investigation, which goes deeper once triage has
established the alert is worth investigating further.

**TTP (Tactics, Techniques, and Procedures)** — the general term for how
an adversary operates, spanning MITRE ATT&CK's tactic/technique
hierarchy down to the specific, granular implementation details
("procedures") a particular threat actor or campaign actually used.

**W**<!--h2-->

**WAF (Web Application Firewall)** — a filtering layer, typically sitting
in front of a web application or API, that inspects HTTP(S) requests
against a ruleset (commonly OWASP Core Rule Set-based) looking for
patterns associated with common web attacks (SQLi, XSS, path traversal),
and blocks or logs matches depending on its configured mode. See Part
8.3 for detection vs. prevention mode.

**WHPX (Windows Hypervisor Platform)** — Windows' built-in hardware
virtualization acceleration API, the Windows analog to hvf (macOS) and
KVM (Linux) — not directly relevant to this Mac-hosted lab, but included
here because it is the third member of the same acceleration-backend
family referenced when discussing why TCG was necessary on this
particular host.

**X**<!--h2-->

**XDR (Extended Detection and Response)** — a SIEM-adjacent product
category that extends detection and response beyond log correlation
alone into more active endpoint-level visibility and response
capability (process monitoring, file integrity monitoring, active
response actions) — Wazuh markets itself as SIEM/XDR, reflecting that it
includes both a log-correlation detection engine and an agent-based
endpoint monitoring/active-response capability, not just log ingestion.
