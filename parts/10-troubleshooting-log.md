**Part 10: Real Troubleshooting Log**<!--h1-->

This part is a set of genuine troubleshooting case studies from actually
building this lab — not illustrative examples. Each one follows the same
shape: symptom, investigation, root cause, fix, and a one-line lesson
that generalizes past this specific bug. The point of including these at
all is that this is what real lab-building (and real production
operations) actually looks like — not a clean sequence of commands that
worked on the first try, but a series of specific things that broke,
were diagnosed, and were fixed one at a time.

**10.1 The Wazuh certificate generator permissions bug**<!--h2-->

**Symptom**: Wazuh 4.9.2 **[FREE]** (Apache 2.0, self-hosted) ships an
official certificate generation step as part of the `wazuh-docker`
single-node setup — a container run that generates the internal TLS
certificates (root CA plus per-node certs) used between the manager,
indexer, and dashboard containers. Partway through this run, the output
folder holding the generated certificates got locked read-only, before
the generator had finished writing the last two certificate files.
Subsequent writes into that folder failed.

**Investigation**: the certificate generator writes its output into a
bind-mounted host directory, and at some point during the run it (or a
step in the container's entrypoint chain) applies restrictive
permissions to that directory as a hardening step — intended to run
*after* all files are written, but in this run it took effect while two
certificate files were still outstanding. This left the output directory
in a half-finished, now-locked state: most of the expected certs
present, two missing, and the directory no longer writable — which
prevented the generator from finishing naturally on a re-run without
first fixing permissions.

**Root cause**: a permissions-hardening step in the cert generator's run
sequence executed before, rather than strictly after, all output files
were written — a timing/ordering issue in the generator's own process,
not a misconfiguration on the host side.

**Fix**: rather than fight the generator's permission state to coax it
into finishing the run, the two missing certificate files were created
by hand — copying the already-generated root CA cert/key pair to serve
in place of the two missing files, since in this single-node setup
topology the missing files were, functionally, just further copies of
the same root CA material the generator had already successfully
produced for the other nodes. This is a pragmatic, single-node-specific
fix — it works because a single-node Wazuh deployment's internal certs
all chain to the same root CA and don't need distinct per-node key
material to function correctly in this topology; it would not
necessarily be the right fix in a multi-node cluster where each node
legitimately needs its own distinct certificate identity.

**Lesson**: when a generator tool fails partway through a multi-file
output with a permissions error, check whether the already-completed
output is actually sufficient to hand-complete the remaining files before
assuming the whole run needs to be reset and re-attempted from scratch.

**10.2 The Windows `autounattend.xml` specialize-pass component error**<!--h2-->

**Symptom**: during the fully unattended install of the Windows Server
2022 Evaluation VM (built via raw `qemu-system-x86_64`, BIOS/i440fx
machine type, `autounattend.xml` supplied via a second CD-ROM built with
macOS's `hdiutil makehybrid`), Windows Setup surfaced this error during
the specialize pass:

```
Windows could not parse or process the unattend answer file for pass
[specialize]. The settings specified in the answer file cannot be
applied. The error was detected while processing settings for component
[Microsoft-Windows-Networking-MPSSVC-Svc].
```

**Investigation**: the `autounattend.xml` included a
`Networking-MPSSVC-Svc` component (the component that governs the
Windows Firewall/MPSSVC service) in the specialize pass, intended to
pre-enable the firewall and the specific rules needed for RDP access
without any manual step after first boot. The error message names the
exact component and pass where parsing failed, which narrowed the search
immediately to that one component block rather than the file as a whole
— the property names used for that component in the answer file did not
match the schema Windows Setup actually expects for that component
(wrong/unsupported property names for that specific unattend component),
so Setup could not apply the specialize-pass settings and halted there.

**Root cause**: incorrect property names in the `Networking-MPSSVC-Svc`
component block of `autounattend.xml` — the exact unattend.xml component
schema for this particular firewall-service component was reconstructed
from memory/general knowledge rather than validated against the actual
schema, and it didn't match what Windows Setup expects.

**Fix**: rather than continue trying to get the exact property-name
schema for that component right, the component was removed from
`autounattend.xml` entirely, and the equivalent outcome (firewall
enabled, RDP allowed) was achieved in a simpler, more reliable way: plain
`netsh advfirewall` commands run inside `FirstLogonCommands`, which
execute as ordinary shell commands after the OS has already booted for
the first time, rather than needing to be expressed in the
unattend.xml schema during the specialize pass at all.

```xml
<!-- Illustrative shape of the FirstLogonCommands replacement — generic
     example of the approach, not a verified full unattend.xml excerpt -->
<FirstLogonCommands>
  <SynchronousCommand wcm:action="add">
    <Order>1</Order>
    <CommandLine>netsh advfirewall set allprofiles state on</CommandLine>
  </SynchronousCommand>
  <SynchronousCommand wcm:action="add">
    <Order>2</Order>
    <CommandLine>netsh advfirewall firewall set rule group="remote desktop" new enable=yes</CommandLine>
  </SynchronousCommand>
</FirstLogonCommands>
```

**Lesson**: when an exact declarative-config schema (unattend.xml
components, in this case) is hard to get right from memory and a
simpler imperative equivalent (a shell command run after boot) achieves
the same outcome, prefer the imperative path — it fails with an
ordinary, readable command error instead of an opaque XML-schema parse
error that only surfaces deep into a lengthy install process.

**10.3 The Cloudflare API token permission-scoping saga**<!--h2-->

**Symptom**: getting `wrangler` (Cloudflare's CLI) authenticated with
enough permission to actually deploy to Cloudflare Pages **[FREEMIUM]**
(static hosting is free; Logpush/continuous log retention needs a paid
plan) took several failed attempts with hand-scoped API tokens before
succeeding.

**Investigation**: Cloudflare's custom API token system is built around
granular **permission groups** — a token is scoped to specific
combinations of a permission group (e.g. "Cloudflare Pages", "Workers
R2 Storage", "Zone DNS") crossed with a resource scope (account-level or
specific zone). The first token created for this session's work was
scoped to R2 storage permissions — the wrong permission group for what
was actually needed (deploying to Pages), a leftover from earlier,
unrelated R2-focused work. A second and third token were created,
attempting to correct this, but still landed without the specific "Pages
— Edit" permission actually included in the permission group selection.
Compounding this, the Cloudflare account itself had zero zones and no
site actually configured at the point these tokens were first being
tested, which made it harder to tell, from a failing `wrangler` command
alone, whether the problem was token scope, account state, or both at
once.

**Root cause**: Cloudflare's permission-group system for custom API
tokens is granular enough that it is genuinely easy to under-scope a
token — there is no single "Pages: full access" checkbox that obviously
covers everything Pages deployment needs; the correct combination of
permission group and access level has to be selected deliberately, and
it is easy to select a plausible-looking but incomplete combination
(as happened across the first three tokens here) without an obvious
error telling you which specific permission is missing.

**Fix**: rather than continue iterating on hand-scoped custom tokens,
`wrangler login` was used instead — Cloudflare's browser-based OAuth
flow, which authenticates wrangler with the actual logged-in user's
account access rather than a manually-assembled permission set. This
flow grants broader scope by default (matching whatever the logged-in
account can actually do in the dashboard) and succeeded immediately
where the hand-scoped custom tokens had not.

**Lesson**: Cloudflare's granular custom-token permission system is easy
to under-scope, and for a one-off or individual admin task, the
browser-based OAuth login flow is often faster and more reliable than
iterating on a hand-built token's exact permission groups — save
precisely-scoped custom tokens for cases that actually need least
privilege (a CI pipeline, a shared automation credential), not for
one-person interactive use.

**10.4 The `wrangler tail` deployment-ID binding limitation**<!--h2-->

**Symptom**: `wrangler pages deployment tail` (used to stream live
request logs from the Cloudflare Pages Function middleware logging every
real request to `soc-lab-target.pages.dev`, since Cloudflare's free tier
has no Logpush/log retention) needs to be run in a way that keeps working
across redeploys of the site, and it doesn't.

**Investigation**: `wrangler pages deployment tail` in non-interactive
mode (the mode needed to run it unattended, piped into the Python relay
script that reformats and forwards log lines to Wazuh) requires an
**explicit deployment ID** argument — it does not implicitly tail
"whatever the current/latest deployment is." In interactive mode,
`wrangler` can prompt for or infer a target deployment, but that
interactivity is exactly what has to be avoided for something meant to
run unattended in the background.

**Root cause**: the tail command's non-interactive contract is bound to
one specific, immutable deployment ID at invocation time, not to the
site or project as a moving target. There is no "tail whatever is
currently live" mode available non-interactively.

**Downstream consequence**: because every deploy to Cloudflare Pages
creates a new deployment with a new ID, any `wrangler tail` process
already running against the previous deployment's ID silently stops
being relevant the moment a new deploy goes out — the old deployment
may still exist and even still serve some traffic during a transition,
but new traffic to the newly-live deployment is invisible to a tail
process still bound to the old ID. This directly breaks the goal of
"persistent" monitoring: any redeploy of the Pages site — even a trivial
content change — silently breaks the log pipeline until someone notices
and manually restarts the tail process with the new deployment's ID.

**Fix**: documented as a known, real, currently-unresolved operational
limitation in this lab, not something that was engineered around with,
for example, an auto-restart wrapper script that queries the latest
deployment ID and re-launches tail on each redeploy — that would be the
natural next fix, but it had not been built as of this document being
written.

**Lesson**: a monitoring/log-tailing tool bound to a specific resource
identifier (a deployment ID, here) rather than to a stable, persistent
resource (the project/site itself) is not actually persistent monitoring
— it is monitoring that silently expires on the next change to the thing
it's watching, and that expiry needs to be handled explicitly (automatic
re-binding, alerting on staleness, or both) or it will be discovered the
hard way, as a silent gap.

**10.5 The MySQL log-format mismatch with Wazuh's decoder**<!--h2-->

**Symptom**: MySQL 8.0 **[FREE]** (community edition; Oracle also sells a
paid Enterprise edition with additional features not used here) was
stood up as a monitored, deliberately-attacked target (`soc-lab-mysql`)
with general query logging and error logging both enabled. Wazuh already
ships built-in decoders and rules for MySQL log formats
(`ruleset/decoders/0150-mysql_decoders.xml`,
`ruleset/rules/0295-mysql_rules.xml`) — no custom Wazuh rule should have
been needed. But MySQL's raw `general_log`/`error_log` output, fed
directly into Wazuh, did not get decoded or matched by those built-in
rules.

**Investigation**: Wazuh's built-in `mysql_log` decoder is written
against a specific expected line prefix — it uses a **prematch** pattern
looking for lines that begin with `MySQL log: ` before it will even
attempt the rest of the decode. MySQL's actual raw log output — both
`general_log` and `error_log` in their native on-disk format — does not
begin with that literal string; it uses MySQL's own native timestamp and
field layout, which never matches the decoder's prematch condition at
all. Every line was arriving at Wazuh, but every line was being silently
ignored at the very first decoder-matching step, before any rule logic
ever had a chance to run — meaning no amount of tuning the *rule* would
have fixed this, since the *decoder* was never even matching to hand
anything to the rule stage.

**Root cause**: a format mismatch between the source log's native output
shape and the specific prematch string Wazuh's shipped decoder expects.
The decoder and rule content were fine as-is (built-in, no custom rule
needed, exactly as expected) — the problem was entirely that raw MySQL
log lines never matched the shape the decoder was written to recognize.

**Fix**: a small Python relay script was written to tail
`error.log`/`general.log`, reformat each matching line so it starts with
the literal `MySQL log: ` prefix (and otherwise preserves/reshapes the
rest of the line into the field order the decoder expects), and append
the reformatted lines to a separate file bind-mounted into the Wazuh
manager container. That file is picked up via a Wazuh `<localfile>`
stanza configured with `<log_format>syslog</log_format>`. Verified live:
four deliberate wrong-password MySQL login attempts correctly fired
Wazuh's built-in rule 50106 ("MySQL: authentication failure", level 9),
which auto-mapped to PCI DSS/GDPR/HIPAA/NIST 800-53 compliance controls
out of the box, once the relay was in place.

**Lesson**: this is a specific instance of a very general, very common
real-world detection engineering problem — **the source log format
almost never matches your detection platform's expected format out of
the box**, even when the platform ships purpose-built content for that
exact log source. "Just add a log source" sounds like a config change;
in practice, log normalization and reformatting — getting the bytes on
disk to actually match what the parsing layer expects — is very often
the majority of the real work involved, and it is worth budgeting time
for that step explicitly rather than assuming a built-in decoder/rule
pair means the log source will "just work" once the file is being read.

**10.7 The recurring Docker Desktop virtiofs bind-mount staleness bug**<!--h2-->

**Symptom**: Docker Desktop's macOS bind-mount layer (virtiofs) repeatedly
went stale after a config or log file was edited from the host side — a
container kept operating on an old, cached view of a file that had
genuinely already changed on disk. This surfaced at least three separate
times, in three genuinely different specific forms: once on a config file
edit, once on a rules file edit, and once on a brand-new volume mount that
had never actually been attached to a running container at all.

**Investigation**: `docker restart` alone was often not enough to fix
this, which is the non-obvious part — the intuitive fix for "a container
seems to be looking at stale data" is to restart it, and that intuition is
wrong here often enough to be worth documenting explicitly. Sometimes only
a full `docker compose up -d` — which triggers container **recreation**,
not just a restart of the existing container — actually picked up the
current, correct file state. The third occurrence was the most instructive
variant: a brand-new volume mount added to `docker-compose.yml` was never
picked up by `docker restart` at all, for a reason that isn't really about
virtiofs staleness in the narrow sense — `docker restart` restarts the
existing container with its existing set of mounts; it has no mechanism to
attach a mount that wasn't part of the container when it was created. Only
`docker compose up -d`, by recreating the container from the current
compose file, actually attaches a newly-added volume.

**Root cause**: two related but distinct failure modes sharing one
underlying cause. First, virtiofs's own caching genuinely can serve a
container a stale view of a bind-mounted file's contents after a host-side
edit, and a plain restart doesn't always force a fresh read. Second, and
more fundamentally, a `docker restart` never re-evaluates a container's
mount configuration at all — it restarts the same container with the same
mounts it already had, so a mount added to `docker-compose.yml` *after*
that container was created is invisible to it until the container is
actually recreated. Config staleness and an entirely un-attached new mount
look like the same symptom ("the container isn't seeing what I just
changed") but are different failure modes with the same practical fix.

**Fix**: when a file edited from the host side doesn't appear to be
picked up by a running container, don't stop at `docker restart` — escalate
to `docker compose up -d`, which forces container recreation and both
re-reads current bind-mounted file state and re-applies the current set of
volume mounts from `docker-compose.yml`. This was the actual fix in all
three occurrences of this bug across this lab session.

**Lesson**: on Docker Desktop for macOS specifically, `docker restart`
and `docker compose up -d` are not interchangeable ways to "make a
container see a change" — `restart` reuses the existing container
unchanged, `up -d` recreates it against the current compose file and
current host-side file state. Any time a change made outside a running
container (a config edit, a rules file edit, a new volume added to
`docker-compose.yml`) doesn't seem to take effect, recreation via
`docker compose up -d` should be the next thing tried, not repeated
plain restarts.

**10.8 TheHive's default account lacked case-creation permissions**<!--h2-->

**Symptom**: with the `custom-thehive` Wazuh integration built and
configured, alerts forwarded from Wazuh to TheHive's API were not
producing cases, even though the API calls themselves were reaching
TheHive without a connection or authentication-format error.

**Investigation**: the integration was authenticating against TheHive's
own default account, `admin@thehive.local` / `secret`, created
automatically the way TheHive seeds a first-run superadmin. That account
turned out to hold platform-management rights — the kind of access needed
to administer TheHive itself, manage organisations, and manage users — but
not the specific `manageCase`/`create` permission that actually creating a
case requires. Platform administration and case-management are governed
by different permission scopes inside TheHive, and the default account
was never provisioned with the latter.

**Root cause**: assuming a superadmin-labeled default account has every
permission a normal working integration would need, when TheHive's
permission model actually separates "can administer the platform" from
"can create and work cases" as distinct scopes.

**Fix**: a real organisation (`soc-lab`) was created inside TheHive, and a
dedicated user with an `analyst` profile was created inside that
organisation via TheHive's own API — the profile that actually carries
`manageCase`/`create` rights. The integration was reconfigured to
authenticate as that user instead of the default admin account, and case
creation started working immediately once that permission gap was closed.

**Lesson**: a platform's default/superadmin account is not a safe stand-in
for "has every permission this integration needs" — administrative
permissions and functional/workflow permissions (here, case creation) are
often genuinely separate scopes, and the correct fix is provisioning a
purpose-specific account with the exact permission the integration
actually needs, not assuming the most privileged-looking account already
has it.

**10.9 Auth0's Management API grant defaulted to far broader scope than requested**<!--h2-->

**Symptom**: after creating a Machine-to-Machine application in Auth0 and
authorizing it against the Management API for log-polling purposes only
(`read:logs`, `read:logs_users`), the resulting client-grant carried
**nearly the entire Management API scope** — user management, client
management, encryption keys, and more — rather than just those two
read-only scopes.

**Investigation**: Auth0's dashboard "Authorize" step, when authorizing an
application against an API, defaults to showing **every available scope
checked** unless a person actively goes through and unchecks the ones not
needed. Nothing was misconfigured or attacked here — the platform's own
default behavior handed out far more access than was requested, because
the selection UI's default state is "everything," not "nothing" or "the
minimum implied by what you're trying to do."

**Root cause**: an over-broad default in a third-party platform's own
authorization UI, not a mistake specific to this lab's configuration
steps — the kind of over-permissioning failure mode that recurs constantly
in real cloud/SaaS IAM work whenever a tool's default is "grant broadly,
let the user narrow it" rather than "grant nothing, let the user opt in."

**Fix**: corrected via the Management API itself rather than the
dashboard: `GET /api/v2/client-grants?client_id=...` to locate the
specific grant record, then a `PATCH` to that grant's `scope` field,
narrowing it down to just `read:logs` and `read:logs_users`. The fix was
then verified, not just assumed: a deliberate write-style Management API
call was made against the newly-narrowed credentials, and it correctly
returned `403 insufficient_scope`, confirming the scope reduction had
actually taken effect rather than merely appearing correct in the
dashboard.

**Lesson**: never trust an authorization flow's default scope selection at
face value, especially in a dashboard UI that defaults to "everything
checked" — verify the actual granted scope after the fact via the
platform's own API, and confirm a narrowed scope really took effect with a
real call that is expected to fail, not just one that's expected to
succeed. A successful call proves the remaining permissions still work; it
proves nothing about whether the removed ones were actually removed.

**10.10 The repo-wide markdown-header convention drift**<!--h2-->

**Symptom**: across this portfolio's public repos, there is a
consistently applied rule of never using literal `#` markdown headers —
using **bold text** instead — everywhere except this specific knowledge
document (which needs real `#`/`##`/`###` headers because it gets
converted to Word/PDF via pandoc, and pandoc needs real heading levels to
build a table of contents). Despite that rule already being consistently
present in the existing files of every repo, multiple background AI
agents, each individually tasked with writing new content "matching this
repo's existing style," still reintroduced literal `#` headers in the
new files they wrote.

**Investigation**: each agent was working from an instruction along the
lines of "match the existing style/tone of this repo" — which relies on
the agent correctly inferring the no-`#`-headers convention purely by
reading the surrounding files and generalizing from them, rather than
being told the rule directly. Because the instruction never stated the
formatting rule explicitly, whether any individual agent actually
picked it up depended on how much of the existing file content it
happened to read carefully enough to notice the pattern, and how strongly
it weighted "match style" against its own default habit of using
standard markdown headers (which is the normal, unremarkable default for
markdown generally — there was nothing about a `#` header that would
read as obviously wrong to an agent that hadn't specifically registered
this repo's specific deviation from that default). The result was
inconsistent: some new files matched the convention, others didn't,
requiring a manual audit pass afterward to find and fix every file that
had drifted.

**Root cause**: an implicit convention ("match the existing style") was
relied on to carry a specific, non-default formatting rule (no `#`
headers) that needed to be stated as an explicit instruction to be
reliably followed, especially across multiple independent
writers working in parallel with no shared checklist between them.

**Fix**: a manual audit-and-fix pass across the affected files,
correcting any reintroduced `#` headers back to the bold-text convention
— and, going forward, stating the header-style rule explicitly in any
instruction given to a writer (human or agent) working on these repos,
rather than relying on it being inferred from context.

**Lesson**: when delegating content-writing work — to another person or
to an automated agent, and especially when multiple writers are working
in parallel without visibility into each other's output — state
non-default conventions (formatting rules, naming rules, structural
rules) as explicit, repeated instructions every time, rather than
trusting them to be correctly inferred from "match the existing style."
Explicit contracts survive parallel, fast-moving work in a way that
inferred conventions don't; this exact document's own formatting rule
(use real `#` headers, the opposite of the portfolio's usual convention)
is itself only followable because it was stated explicitly in the brief
each writer received, which is the direct, deliberate fix for the
failure mode described in this case study.

**10.11 LocalStack S3 needs path-style addressing, or `apply` hangs forever**<!--h2-->

**Symptom**: `terraform apply` against LocalStack, for a config using the
`aws` provider to create an S3 bucket, hung indefinitely — no error, no
progress, just sat there. LocalStack's own container logs showed the
actual cause repeating over and over: `exception during call chain:
Unable to find operation for request to service s3: HEAD /`, followed
by `HEAD / => 500`, every few seconds.

**Root cause**: the AWS provider defaults to virtual-hosted-style S3
addressing — `bucket-name.s3.amazonaws.com` — when checking whether a
bucket already exists before creating it. LocalStack serves every AWS
service off a single endpoint (`localhost:4566`), so it needs path-style
addressing instead (`localhost:4566/bucket-name`) to know which bucket a
request is actually for. A virtual-hosted-style request arrives as a
bare `HEAD /` with no bucket name anywhere LocalStack can find it,
which it can't route to any operation — so it 500s, and the provider,
seeing a failure rather than a clean 404 (bucket doesn't exist yet),
just retries the same malformed request rather than treating it as
permission to proceed with creation.

**Fix**: one line in the provider block — `s3_use_path_style = true`.
Immediate; the very next `apply` attempt succeeded cleanly.

**Lesson**: a hang with zero error output is a different failure mode
from a hang with a visible retry loop, and the difference matters for
where to look. Terraform's own CLI output gave no indication anything
was wrong — the actual diagnostic signal was sitting in the *target's*
logs, not the tool's. When a `plan`/`apply` against any non-AWS-default
endpoint just sits there, check the target's own request logs before
assuming the Terraform config itself is broken; the request may be
arriving and failing silently on the other end, not failing to send at
all.

**10.12 Non-interactive PowerShell Gallery installs hang on the NuGet provider prompt**<!--h2-->

**Symptom**: `Install-Module -Name powershell-yaml -Force` over PowerShell
remoting (WinRM) to the Windows Server VM just hung — no output, no
error, no completion, indefinitely. Killing and retrying the exact same
command produced the same silent hang every time.

**Root cause**: a fresh Windows install has no NuGet package provider
registered, and PowerShell's `Install-Module` needs one to talk to the
PowerShell Gallery. On a first run, it normally prompts interactively —
"NuGet provider is required to continue... Do you want PowerShell to
install and import the NuGet provider now?" — and waits for a
keypress. Over an interactive console that prompt is easy to miss for a
second and then answer; over WinRM there is no console for it to prompt
on, so the command just blocks forever waiting for input that can never
arrive. `-Force` on `Install-Module` does not suppress this — it
answers a different, later prompt (about installing from an untrusted
repository), not this earlier one about the provider itself.

**Fix**: install the NuGet provider and trust the PSGallery repository
explicitly, before ever calling `Install-Module`:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```
Once both of those succeed, every subsequent `Install-Module` call
completes normally with no further prompts.

**Lesson**: any Windows automation driven non-interactively (WinRM,
CI, a provisioning script) needs every one-time interactive prompt a
fresh install might trigger — package providers, repository trust,
execution policy — handled explicitly and in advance, not assumed away
by a flag that looks like it should cover it. `-Force` covering "this
specific confirmation" is not the same claim as "-Force covering every
confirmation this command could possibly show," and the two are easy to
conflate until a silent hang forces the distinction.

**10.13 Wazuh's Windows agent doesn't monitor the Sysmon event channel by default**<!--h2-->

**Symptom**: Sysmon was installed and confirmed running on the Windows
VM (SwiftOnSecurity config, service started cleanly), and the Wazuh
agent was confirmed **Active** on the manager, forwarding real Windows
Security event log telemetry (logon/logoff events showed up as genuine
Wazuh alerts). But nothing from Sysmon specifically ever appeared —
no process-creation events, nothing on Sysmon's own event channel at
all, despite Sysmon itself clearly working.

**Root cause**: the Wazuh Windows agent's default `ossec.conf` only
configures three `eventchannel` localfile sources — Application,
Security, and System, the three built-in Windows Event Log channels.
Sysmon writes to its own separate channel,
`Microsoft-Windows-Sysmon/Operational`, which isn't one of those three
and isn't added automatically just because Sysmon is installed and
running. An agent can be genuinely healthy and actively forwarding
real telemetry while still being completely blind to Sysmon, because
Sysmon telemetry was never one of the things it was told to watch.

**Fix**: add an explicit `<localfile>` block to the agent's
`ossec.conf` for the Sysmon channel:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
then restart the `WazuhSvc` service. Telemetry started flowing
immediately afterward.

**Lesson**: "the agent is Active" and "the agent is Active and
correctly wired to your specific value-added telemetry source" are two
separate claims, and only checking the first one is a common, easy way
to think detection coverage exists when it doesn't. Any time a specific
Windows Event Log channel (Sysmon, PowerShell Operational, Windows
Defender, etc.) matters for a given detection story, verify it's
explicitly in the agent's `ossec.conf`, not just that the agent process
itself is running and reachable.

**10.14 `Invoke-AtomicTest`'s process-management wrapper hangs indefinitely over WinRM**<!--h2-->

**Symptom**: `Invoke-AtomicTest T1059.001 -TestNumbers 15` (a confirmed
safe, benign encoded-PowerShell test, verified with a `-ShowDetails`
dry-run first) hung indefinitely when run over PowerShell remoting
(WinRM), reporting `Process Timed out after 120 seconds` — and the same
result at every different `-TimeoutSeconds` value tried, from 20 up to
120. The command wasn't running slowly; it was reliably hitting
whatever timeout was set, every time, which is the signature of
something structurally blocked rather than something merely slow.

**Root cause**: `Invoke-AtomicTest`'s own process-launching and
process-waiting logic doesn't behave the same way under a WinRM remote
session as it does interactively — the specific mechanism it uses to
track whether the spawned attack-command process has finished doesn't
resolve correctly without an interactive desktop session backing it.
The underlying attack command it wraps is fine; only the wrapper's own
completion-detection logic is affected.

**Fix**: bypass `Invoke-AtomicTest`'s wrapper and call the actual
attack-command logic directly. For this specific test, that meant
calling `Out-ATHPowerShellCommandLineParameter` (the `AtomicTestHarnesses`
module cmdlet the atomic test's YAML definition wraps) directly instead
of going through `Invoke-AtomicTest` at all:
```powershell
Import-Module AtomicTestHarnesses -Force
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop
```
This ran immediately and returned a clean `TestSuccess: True` result
with a real process ID — the actual technique executed correctly the
entire time, only the outer wrapper's own timeout logic was broken for
this execution context.

**Lesson**: when a security-testing framework's high-level convenience
wrapper misbehaves in an unusual execution context (here: driven
non-interactively over remoting, rather than from an interactive
session), check whether the actual underlying mechanism it wraps still
works when called directly before concluding the technique itself
can't be tested. The wrapper and the technique are different things,
and a wrapper bug is not evidence the technique wasn't validated —
it's evidence to go one layer deeper before giving up.

**10.15 `wazuh-logcollector` silently crashed and stayed dead for ~17 minutes, no alerts, no obvious error**<!--h2-->

**Symptom**: during a full end-to-end re-verification pass across every live source, MySQL's rule `50106` didn't fire on a deliberate failed login even though the relay script was confirmed appending the right line to the right file at the right path inside the container. Every other local-file source (Cloudflare, Suricata, Auth0, LocalStack, Cowrie) would have been silently affected the same way, not just MySQL — this was caught because MySQL happened to be the first one re-tested.

**Root cause**: `/var/ossec/bin/wazuh-control status` showed `wazuh-logcollector not running...` while every other Wazuh daemon (`analysisd`, `remoted`, `syscheckd`, etc.) reported running normally. `ossec.log` showed why: a string of `wazuh-logcollector: ERROR: (1114): Error during select()-call due to [(4)-(Interrupted system call)]` messages, ending in `wazuh-logcollector: CRITICAL: (1600): Internal error. Exiting..` roughly 17 minutes before this was noticed. The daemon crashed and, unlike a full container restart, nothing inside the running container brought it back — there's no supervisor process restarting individual Wazuh daemons once they exit. Critically, this crash only kills *local file* ingestion (everything routed through `<localfile>` — all six live-traffic-tests sources); it does **not** affect agent-based telemetry, which is why the Windows VM's own heartbeat/logon events kept flowing the entire time and gave no visual indication anything was wrong.

**Fix**: `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logcollector` restarts just that one daemon without needing a full container restart (which would have been the heavier, also-valid fix). Confirmed via `wazuh-control status` showing it running again, then re-ran the MySQL test — rule `50106` fired within seconds.

**Lesson**: "the containers are all `Up`" is not the same claim as "every Wazuh daemon inside the container is alive" — `docker ps` only reports the container's own PID 1, not the dozen-plus daemons Wazuh runs inside it. A stopped-but-not-crashed *container* is obvious; a crashed *daemon* inside a healthy-looking container is invisible unless something specifically checks `wazuh-control status` or greps `ossec.log` for `CRITICAL`. This is also a real, if narrow, argument for eventually adding a "local-file sources have gone quiet" check to the dashboard built in Part 1/9 — right now it only shows *when* a source last alerted, not *whether the pipeline that would let it alert is actually still alive*, which are different facts and this incident is exactly the gap between them.
