**Part 9: End-to-End Practical Labs**<!--h1-->

The labs below are reproducible steps for what was actually built and
verified in this lab session, on a MacBook (Apple Silicon, 16GB RAM), macOS,
using Homebrew, Docker Desktop, and QEMU. Each lab states its goal,
prerequisites, exact steps, expected result, and what it teaches — and each
is explicit about what was actually verified with real evidence versus what
was merely assumed to work. Labs 1 through 3 were fully verified live. Lab 4
was verified up to a specific, stated point and no further. Lab 5 is
explicitly not done yet and is included as a documented next step, not a
completed lab.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/09-practical-labs-18.png)

**Lab 1: Stand up Wazuh **[FREE]** locally via Docker**<!--h2-->

**Goal**<!--h3-->

Get a working single-node Wazuh 4.9.2 SIEM/XDR stack (manager, indexer,
dashboard) running locally via Docker, as the foundation every other lab in
this document depends on.

**Prerequisites**<!--h3-->

- Docker Desktop installed and running (macOS, Apple Silicon).
- Git.
- At least a few GB of free disk for the indexer's data volume.

**Steps**<!--h3-->

1. Clone the official Wazuh Docker repository to a location outside any git
   repo you intend to push publicly — this stack generates real certs and
   local data that should not end up in version control:

   ```bash
   mkdir -p ~/securitylab
   cd ~/securitylab
   git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
   cd wazuh-docker/single-node
   ```

2. Generate the certificates the stack needs for the indexer/manager/
   dashboard to talk to each other over TLS:

   ```bash
   docker compose -f generate-indexer-certs.yml run --rm generator
   ```

   **The real bug hit and its fix:** this cert-generator step failed on
   first run with a permissions error — the container attempts to write
   certificate files into a bind-mounted local directory, and depending on
   how Docker Desktop on macOS has mapped file ownership between the
   container's user and the host filesystem, the container's write can be
   rejected. The fix was ensuring the target certs directory was
   writable by the container's user before running the generator — on
   macOS with Docker Desktop this typically means checking the bind-mount
   path's permissions and, if needed, adjusting them (`chmod` on the local
   `config/wazuh_indexer_ssl_certs/` directory) before re-running the
   generator step, rather than fighting Docker's user-namespace mapping
   directly. Once the target directory was writable, re-running the exact
   same `generate-indexer-certs.yml` command succeeded and populated the
   certs directory.

3. Bring the stack up:

   ```bash
   docker compose up -d
   ```

4. Confirm all three containers are healthy:

   ```bash
   docker compose ps
   ```

   Expected: `wazuh.manager`, `wazuh.indexer`, and `wazuh.dashboard`
   containers all in a running/healthy state.

**Expected result**<!--h3-->

- Wazuh dashboard reachable at `https://localhost` in a browser (self-signed
  cert — browser will warn, accept to proceed).
- Default login `admin` / `SecretPassword` has actually been changed in
  this lab — not a trivial fix, since `admin` is a reserved OpenSearch
  security-plugin account that rejects direct password-change API calls,
  and a plain restart doesn't apply an `internal_users.yml` edit to an
  already-initialized cluster. The real fix needed the indexer's own
  `hash.sh` (generate a new bcrypt hash) plus `securityadmin.sh` (push it
  into the running cluster's security index) — see Part 10.
- Indexer API reachable on port `9200`.

**What it teaches**<!--h3-->

- The shape of a real, self-hosted SIEM deployment: three cooperating
  services (ingestion/correlation, search/storage, visualization), not a
  single monolith — the same architectural split you'll see in Elastic's
  stack and most SIEM products, just open-source and free (Apache 2.0, no
  paid tier) instead of a managed/paid equivalent like Sentinel.
- That "the docs say run this compose file" and "it works on the first try"
  are not the same thing — a permissions mismatch between a bind-mounted
  host directory and a container's expected write access is one of the most
  common real-world Docker friction points, and diagnosing it (check what
  the container is trying to write, check whether the host path allows
  that) is a transferable skill well beyond Wazuh specifically.

**Lab 2: Wire a real Cloudflare Pages site's traffic into Wazuh with a custom detection rule**<!--h2-->

**Goal**<!--h3-->

Get live, real HTTP traffic from a real public website into Wazuh, and have
a custom rule fire a real alert on a specific suspicious path — end to end,
verified with real curl-generated evidence.

**Prerequisites**<!--h3-->

- Lab 1 completed (Wazuh running locally).
- A Cloudflare **[FREEMIUM]** account (static Pages hosting is free; note
  Logpush/continuous log streaming is a paid-plan feature, which is exactly
  why this lab needed a different capture path — see step 3).
- `wrangler` (Cloudflare's CLI) installed via npm.
- Python 3 for the relay script.

**Steps**<!--h3-->

1. Create and deploy a minimal static Cloudflare Pages site with a
   `functions/_middleware.js` Pages Function that logs every request:

   ```js
   // functions/_middleware.js
   export async function onRequest(context) {
     const { request } = context;
     console.log(JSON.stringify({
       method: request.method,
       path: new URL(request.url).pathname,
       ip: request.headers.get("cf-connecting-ip"),
       country: request.headers.get("cf-ipcountry"),
       user_agent: request.headers.get("user-agent"),
     }));
     return context.next();
   }
   ```

   Deploy with:

   ```bash
   wrangler pages deploy ./public --project-name soc-lab-target
   ```

   Include a clearly labeled dummy `/login.html` (does nothing but log —
   no real authentication logic behind it) and `/contact.html`, tag pages
   `noindex,nofollow`, and put a visible on-page banner disclosing this is
   a synthetic lab fixture collecting nothing — required before pointing
   any real public traffic at it.

2. Authenticate `wrangler` — real lesson from this session: a hand-scoped
   Cloudflare API token is easy to under-scope (multiple tokens created and
   discarded in this session: one scoped only to R2 storage, others missing
   Pages Edit permission specifically). `wrangler login`'s browser-based
   OAuth flow grants broader scope by default and was faster than fighting
   the custom-token permission-group UI for this one-off admin task:

   ```bash
   wrangler login
   ```

3. Capture live traffic. Cloudflare's Free tier has no Logpush/continuous
   log retention, so live traffic is captured by tailing the deployment
   directly:

   ```bash
   wrangler pages deployment tail --format=json <deployment-id>
   ```

   **Documented limitation:** this command binds to a specific deployment
   ID, which means it breaks on every redeploy — a new deployment ID means
   the tail command must be re-run with the new ID. This is a real,
   ongoing limitation of this capture approach, not a one-time setup cost.

4. Run a small Python relay that consumes the `wrangler tail` JSON output
   and appends each parsed event as a line to a file bind-mounted into the
   Wazuh manager container, e.g. `/var/ossec/logs/cloudflare-relay.log`.

5. Configure Wazuh to watch that file as JSON (in
   `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf` or
   the manager's `ossec.conf`):

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/ossec/logs/cloudflare-relay.log</location>
   </localfile>
   ```

   Wazuh auto-decodes top-level JSON keys into `data.<field>` for rule
   matching — no custom decoder was needed, since the relay already emits
   flat JSON with sensible field names.

6. Add a custom local rule in
   `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager/etc/rules/local_rules.xml`
   (a custom rule was needed here, unlike Lab 3, because Wazuh has no
   built-in decoder or ruleset for arbitrary JSON web logs the way it does
   for known log formats like MySQL's):

   ```xml
   <rule id="100011" level="7">
     <if_sid>...</if_sid>
     <field name="data.path">^/login\.html$</field>
     <description>Possible scanner/credential-testing activity: request to /login.html</description>
   </rule>
   ```

7. Restart the manager to load the new rule, then generate real traffic and
   confirm:

   ```bash
   curl https://soc-lab-target.pages.dev/login.html
   ```

**Expected result**<!--h3-->

Real request appears via the `wrangler tail` → relay → Wazuh pipeline, and
rule 100011 fires a level-7 alert visible in the Wazuh dashboard, with the
real client IP, country, and user-agent from the actual curl request
attached in `data.*` fields. **This was verified live in this session** —
real curl traffic produced real alerts, not a simulated/assumed result.

**What it teaches**<!--h3-->

- The general pattern for feeding any source that doesn't have a native
  Wazuh integration: capture → relay/reformat → localfile → custom rule.
  This four-stage pattern generalizes far beyond Cloudflare.
- The distinction between a decoder and a rule: Wazuh's JSON auto-decode
  handled field extraction for free; the *detection logic* (what pattern in
  those fields matters) still had to be hand-written, because detection
  logic is inherently source- and use-case-specific in a way generic field
  parsing isn't.
- A real operational limitation (the deployment-ID binding breaking on
  redeploy) that a from-scratch reader would hit and should expect, not be
  surprised by.

**Lab 3: Wire a real MySQL container's logs into Wazuh using its built-in `mysql_log` decoder/rules**<!--h2-->

**Goal**<!--h3-->

Feed a real MySQL 8.0 container's authentication logs into Wazuh and
confirm Wazuh's *built-in* MySQL ruleset detects failed authentication —
deliberately contrasted with Lab 2, which needed a custom rule because no
built-in ruleset existed for that source.

**Prerequisites**<!--h3-->

- Lab 1 completed.
- Docker, for running the MySQL container.

**Steps**<!--h3-->

1. Stand up a MySQL 8.0 container with general query logging and error
   logging both enabled:

   ```bash
   docker run -d --name soc-lab-mysql \
     -e MYSQL_ROOT_PASSWORD=<lab-only-password> \
     -v soc-lab-mysql-logs:/var/log/mysql \
     mysql:8.0 \
     --general-log=1 \
     --general-log-file=/var/log/mysql/general.log \
     --log-error=/var/log/mysql/error.log
   ```

2. Run a small Python relay script that tails `error.log` and
   `general.log`, and reformats matching authentication-related lines to
   fit Wazuh's expected `MySQL log: ...` prematch format (the format
   Wazuh's built-in `0150-mysql_decoders.xml` decoder expects to match
   against), appending them to a file bind-mounted into the Wazuh manager
   container.

3. Configure Wazuh to pick the relayed file up as `syslog` format (not
   `json` this time — the relay's job is specifically to produce lines that
   match the built-in decoder's expected prematch, so plain syslog-style
   ingestion is correct here):

   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/ossec/logs/mysql-relay.log</location>
   </localfile>
   ```

4. Confirm the built-in decoder and rules are present in the manager's
   ruleset (no custom rule file needed for this lab — this is the whole
   point of the contrast with Lab 2):

   ```bash
   docker exec wazuh.manager grep -l "MySQL" /var/ossec/ruleset/decoders/0150-mysql_decoders.xml
   docker exec wazuh.manager grep -l "50106" /var/ossec/ruleset/rules/0295-mysql_rules.xml
   ```

5. Generate real failed-login traffic against the container:

   ```bash
   for i in 1 2 3 4; do
     mysql -h 127.0.0.1 -u root -pWrongPassword$i 2>&1
   done
   ```

**Expected result**<!--h3-->

Four deliberate wrong-password login attempts correctly fired Wazuh's
built-in rule 50106 ("MySQL: authentication failure", level 9). **Verified
live in this session.** As a side benefit of using the built-in ruleset
rather than a custom one, the alert auto-mapped to PCI DSS, GDPR, HIPAA, and
NIST 800-53 compliance controls out of the box — mappings that come baked
into Wazuh's official ruleset and that a hand-written custom rule would not
have had unless the compliance tags were manually added.

**What it teaches**<!--h3-->

- The direct contrast with Lab 2: when a log source has a well-known,
  standard format (MySQL's error/general log format is stable and
  documented), a mature SIEM ships decoders and rules for it already —
  the work is entirely in getting the log lines into the expected shape
  and location, not in writing detection logic from scratch. When the
  source is arbitrary/custom (a JSON web log with lab-specific field
  names), no such ruleset can exist ahead of time, and custom rule-writing
  is unavoidable.
- The real value of using built-in rulesets where they exist: compliance
  mapping, MITRE ATT&CK tagging, and tuning that the Wazuh project
  maintains centrally — reasons to prefer "adapt the log to the existing
  rule" over "write a new rule to match the log" whenever a built-in option
  exists.

**Lab 4: Build a Windows Server 2022 evaluation VM via QEMU with a fully unattended install**<!--h2-->

**Goal**<!--h3-->

Get a working Windows Server 2022 desktop running under QEMU on Apple
Silicon, installed with zero interactive input, as the target host for
future Atomic Red Team testing (Lab 5).

**Prerequisites**<!--h3-->

- QEMU installed via Homebrew (`brew install qemu`).
- `hdiutil` (built into macOS) for building the answer-file ISO.
- The Windows Server 2022 Evaluation ISO, downloaded from Microsoft's own
  stable fwlink direct-download URL for the Server evaluation channel —
  chosen specifically because it requires no interactive business-info web
  form, unlike the Windows 11 Enterprise evaluation channel.
- Roughly 1+ hour of wall-clock time — TCG software emulation of an x86_64
  guest on an Apple Silicon host is genuinely slow; this is not a KVM/HVF
  accelerated install.

**Steps**<!--h3-->

1. Create the virtual disk:

   ```bash
   qemu-img create -f qcow2 ~/securitylab/vms/winserver2022.qcow2 60G
   ```

2. Build an `autounattend.xml` answer file covering the windowsPE,
   specialize, and oobeSystem passes: disk partitioning, product key
   (evaluation edition), administrator password, computer name, and a
   `FirstLogonCommands` block.

   **The real bug hit and its fix:** an initial attempt at the specialize
   pass included a `Networking-MPSSVC-Svc` component intended to enable the
   firewall and RDP declaratively via unattend XML properties. This failed
   during setup with:

   ```
   Windows could not parse or process the unattend answer file for pass
   [specialize]. The settings specified in the answer file cannot be
   applied. The error was detected while processing settings for component
   [Networking-MPSSVC-Svc].
   ```

   The property names used for that component were wrong/unsupported for
   this build. Rather than continuing to fight exact unattend.xml component
   schemas from memory against undocumented edge cases, the fix was to
   remove that component from the specialize pass entirely and instead
   enable the firewall rule and RDP via plain `netsh advfirewall` and
   registry commands inside `FirstLogonCommands` in the oobeSystem pass —
   simpler, more reliable, and far easier to verify correct:

   ```xml
   <FirstLogonCommands>
     <SynchronousCommand wcm:action="add">
       <Order>1</Order>
       <CommandLine>netsh advfirewall firewall set rule group="remote desktop" new enable=yes</CommandLine>
     </SynchronousCommand>
     <SynchronousCommand wcm:action="add">
       <Order>2</Order>
       <CommandLine>reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f</CommandLine>
     </SynchronousCommand>
   </FirstLogonCommands>
   ```

3. Build a small hybrid ISO containing just `autounattend.xml` at its root,
   using macOS's built-in `hdiutil`:

   ```bash
   hdiutil makehybrid -o ~/securitylab/vms/autounattend.iso \
     ~/securitylab/vms/unattend-src/ -iso -joliet
   ```

   Windows Setup automatically scans attached removable media for a file
   named `autounattend.xml` during the windowsPE pass — this is why the
   answer file doesn't need to be baked into the install ISO itself, just
   present on any attached CD-ROM.

4. Boot the install with two CD-ROMs attached — the Windows install ISO and
   the answer-file ISO — using BIOS/IDE emulation rather than UEFI/q35:

   ```bash
   qemu-system-x86_64 \
     -machine pc \
     -accel tcg \
     -m 4096 \
     -smp 2 \
     -drive file=~/securitylab/vms/winserver2022.qcow2,if=ide,format=qcow2 \
     -drive file=~/path/to/WinServer2022-eval.iso,media=cdrom,if=ide \
     -drive file=~/securitylab/vms/autounattend.iso,media=cdrom,if=ide \
     -boot d \
     -vnc :1
   ```

   **Why BIOS/IDE (`pc` machine type) instead of q35/UEFI:** IDE disk and
   CD-ROM emulation is understood natively by Windows Server 2022's inbox
   drivers with no virtio driver injection needed at install time — trading
   some disk/network performance for install-time simplicity and
   compatibility, which was the right tradeoff for getting a working
   install without fighting driver injection on top of everything else.
   **Why TCG (software emulation):** an x86_64 guest cannot use Apple
   Silicon's hardware virtualization (HVF accelerates only same-architecture
   guests), so this install runs fully emulated — genuinely slow (~1hr+),
   a real, expected cost of this specific host/guest architecture
   combination, not a misconfiguration to fix.

5. Connect via VNC (`:1` → `localhost:5901`) to watch/confirm the
   unattended install proceeds without any prompts, through to the working
   desktop the 10-boot autologon oobeSystem setting takes it to.

**Expected result**<!--h3-->

A booted Windows Server 2022 desktop, reached with zero interactive input
during setup, confirmed by connecting over VNC and seeing a logged-in
desktop. **This was confirmed** — the install completed and a working
desktop was reached.

**What was NOT verified — an honest, stated gap**<!--h3-->

Reaching a working desktop over VNC is not the same claim as "this VM is
reachable and manageable the way a real lab target needs to be." **RDP and
WinRM reachability from the host were never independently verified
end-to-end** in this session. The `FirstLogonCommands` block enables the
firewall rule and flips the `fDenyTSConnections` registry key, and there is
every reason to expect RDP works given those settings applied cleanly with
no error — but no actual RDP client connection from the host to the guest
was tested and confirmed working, and WinRM (needed for a lot of remote
Windows administration and would matter for future automation against this
VM) was not configured or tested at all. This is a real, stated gap, not an
assumption dressed up as a result — a reader reproducing this lab should
treat "confirm RDP/WinRM actually connect from the host" as an unverified
next step, separate from and in addition to Lab 5's Sysmon/agent work.

**The open, unresolved tension worth naming**<!--h3-->

QuartzVM, the GUI VM manager the user separately built (a real open-source,
MIT-licensed Rust/Tauri app, `quartzvm-releases`), is explicitly designed
around a "create → snapshot → destroy" disposable-lab philosophy. The
Windows Server VM built in this lab — hardcoded administrator password baked
into the answer file, 10-boot autologon configured for convenience — is, as
built, closer to a persistent asset than a disposable lab VM. This is a
genuinely open, undecided question in this lab, not something resolved by
this document: should this VM be rebuilt to fit the disposable philosophy
before it's used for anything sensitive, or does its role (a fixed Atomic
Red Team target) argue for persistence being fine here? Both positions have
merit; no decision has been made.

**What it teaches**<!--h3-->

- The real mechanics of a fully unattended Windows install via raw QEMU —
  not through a GUI wizard, but through the actual answer-file/ISO
  mechanism Windows Setup itself uses.
- A concrete lesson in debugging unattend.xml failures: when a declarative
  component's exact property schema is uncertain, falling back to an
  imperative equivalent (`netsh`/`reg` commands in `FirstLogonCommands`) is
  often more reliable than guessing at exact schema syntax from memory —
  a generally transferable lesson about knowing when to stop fighting a
  declarative config format and use an imperative escape hatch instead.
- The specific architecture tradeoffs (BIOS/IDE vs. UEFI/q35, TCG vs.
  hardware acceleration) that matter when running an x86_64 guest on an
  Apple Silicon host, and why those tradeoffs point toward BIOS/IDE for an
  install-time-simplicity-first VM.
- The discipline of stating what "the VM booted" does and doesn't prove —
  a working desktop over VNC is real evidence of one thing (the install
  succeeded) and zero evidence of another (host-to-guest network management
  reachability), and conflating the two is exactly the kind of overclaiming
  this document is built to avoid.

**Lab 5 (DONE — both case studies): install Sysmon + a Wazuh agent, run real Atomic Red Team tests**<!--h2-->

**Status**<!--h3-->

Performed for real. Sysmon and the Wazuh agent are installed on the
Windows Server 2022 VM from Lab 4, the agent is confirmed **Active** on
the manager, and both of `atomic-red-team-validation`'s Atomic Red Team
case studies have now been executed: T1059.001 (encoded PowerShell),
caught clean by Wazuh's **built-in** Sysmon ruleset — no custom rule
needed — and T1078.004 (Cloud Accounts), adapted via a real IAM
persistence simulation against LocalStack since the official test
needs real Azure/GCP cloud login. Neither case study is "planned, not
run yet" anymore.

**How it actually went, versus the plan**<!--h3-->

- Reachability was solved differently than either option Lab 4 left
  open (RDP or WinRM, both unconfirmed at the time). WinRM won: a
  `hostfwd` port-forward for 5985 on the QEMU NAT network, verified
  reachable, then driven from the host via `pywinrm` — real
  authenticated command execution confirmed before installing anything.
- The originally-planned Atomic Test #1 for T1059.001 turned out to be
  "Mimikatz" (downloads and runs a real credential dumper) — caught via
  a `-ShowDetails` dry-run *before* executing anything, not after. Test
  #15 ("ATHPowerShellCommandLineParameter -EncodedCommand parameter
  variations") was the actual benign encoded-PowerShell test intended,
  found by listing every test in the technique's YAML definition rather
  than trusting the first test number to be the simplest one.
- `Invoke-AtomicTest`'s own wrapper hung indefinitely over WinRM,
  regardless of `-TimeoutSeconds` value — a real, documented bug (Part
  10.14), not a technique failure. The underlying attack-command logic
  it wraps (`Out-ATHPowerShellCommandLineParameter`, from the
  `AtomicTestHarnesses` module) ran fine called directly, bypassing the
  wrapper entirely.
- A real, separate gap surfaced along the way (Part 10.13): Wazuh's
  Windows agent doesn't monitor the Sysmon event channel by default —
  only Application/Security/System are configured out of the box. Real
  Windows telemetry was already flowing (logon/logoff events proved the
  agent itself worked) while Sysmon-specific telemetry was still
  completely invisible, until the Sysmon channel was added to the
  agent's `ossec.conf` explicitly.

**What it actually produced**<!--h3-->

A real Sysmon Event ID 1 (process creation) for
`powershell.exe -NoProfile -E <base64>`, forwarded to Wazuh, correctly
fired as rule `92071` — *"A powershell process created by WMI executed
a base64 encoded command"* — level 12, tagged with **both** T1047
(Windows Management Instrumentation) and T1059.001 (PowerShell). The
dual tagging wasn't something planned for: `AtomicTestHarnesses`
launches its target process via WMI (`WmiPrvSE.exe` as the parent
process) rather than a direct child-process spawn, a real execution
detail that changed which techniques the alert correctly matched — see
the full case study in `atomic-red-team-validation` for the complete
forensic detail captured (command line, file hashes, parent process
chain).

A side effect worth noting honestly: the same PowerShell invocation
also produced 36+ separate Sysmon file-create alerts from `.NET`'s own
script-block compilation caching temp files — a live, real example of
the alert-fatigue problem discussed in Part 5 and Part 6, from a
completely benign, everyday execution path.

**What this lab teaches**<!--h3-->

- Wazuh's default Windows/Sysmon ruleset caught this technique with
  zero custom rule work — a materially different result from the
  Cloudflare case in Lab 2, which needed a custom rule because Wazuh
  has no built-in decoder for arbitrary JSON web logs. Real, measured
  evidence that Wazuh's out-of-box Windows/Sysmon coverage is stronger
  than its coverage for a source it wasn't originally built to speak.
- The full, real version of the T1059.001 triage walkthrough now exists
  in Part 6 (Walkthrough 4) as an actual alert with actual evidence,
  not a hypothetical narrative — the same transition Labs 2 and 3 made
  for their respective detections.
- Verifying a security-testing tool's own convenience wrapper still
  works in an unusual execution context (non-interactive remoting) is
  its own real skill, separate from validating the technique itself —
  see Part 10.14 for the general lesson.

**T1078.004, adapted: LocalStack instead of real Azure/GCP**<!--h3-->

The official Atomic Red Team tests for T1078.004 all need real cloud
resource creation — two use GCP (service account, custom IAM role),
one uses Azure (`New-AzAutomationRunbook`, needing `Connect-AzAccount`
and a real `terraform apply` against a real subscription). Checked
with `-ShowDetails` before deciding this rather than assuming it, all
three confirmed. None has a benign local-only variant the way
T1059.001's did.

Rather than force a real-cloud-touching test, the same underlying
technique concept — a valid cloud account minting a new credential to
persist past revocation of the original one — was adapted using AWS
IAM against LocalStack:
```bash
aws --endpoint-url=http://localhost:4566 iam create-user --user-name backup-svc-account
aws --endpoint-url=http://localhost:4566 iam attach-user-policy --user-name backup-svc-account --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name backup-svc-account
```
LocalStack Community doesn't generate CloudTrail-format logs at all (a
real, already-documented limitation in `aws-identity-detection`), so
the detection surface here is LocalStack's own plain-text request log
(`AWS iam.CreateUser => 200`, etc.), relayed on-demand into Wazuh —
this lab's fifth live source, distinct from the other four. A new
custom rule set (Wazuh has no built-in AWS/CloudTrail decoder) matched
all three steps cleanly, tagged with MITRE T1078.004, with
`CreateAccessKey` — the actual persistence mechanism — correctly
weighted higher (level 9) than the precursor `CreateUser`/
`AttachUserPolicy` steps (level 7 each).

Worth being explicit about what this does and doesn't prove: this
validates the detection *concept*, not the official Atomic Red Team
test for T1078.004 specifically — a reader checking against the
upstream Atomic Red Team library won't find a matching test, because
the real ones need cloud infrastructure this lab deliberately avoided
touching. See `atomic-red-team-validation`'s T1078.004 case study for
the full accounting of that distinction.

Both of `atomic-red-team-validation`'s case studies are now real,
executed, evidenced work rather than "planned, not run yet" — the
state described in Part 6's Walkthrough 3 for T1078.004 has been
updated accordingly.
