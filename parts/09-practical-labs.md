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
- Default login `admin` / `SecretPassword` — documented here explicitly as
  needing to be changed before this stack is ever exposed beyond localhost;
  it was left as default for this local-only lab session, which is fine for
  a lab bound to localhost and unacceptable for anything reachable
  externally.
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

**Lab 5 (NOT YET DONE — a documented next step, not a completed lab): install Sysmon + a Wazuh agent, run one real Atomic Red Team test**<!--h2-->

**Status**<!--h3-->

This lab has not been performed. It is included here specifically so the
gap is documented rather than silently missing, and so a reader knows
exactly what remains between "a Windows VM exists" (Lab 4) and "the
`atomic-red-team-validation` repo's T1078.004 and T1059.001 case studies are
real, run, evidenced case studies" rather than the "planned, not yet run"
state they're honestly labeled with today (see Part 6, Walkthrough 3).

**Goal (planned)**<!--h3-->

Install Sysmon and a Wazuh agent on the Windows Server 2022 VM from Lab 4,
confirm the agent registers with the Wazuh manager from Lab 1 and Sysmon
telemetry (process creation, PowerShell script block logging) flows into
Wazuh, then run exactly one Atomic Red Team test — most naturally
T1059.001 (PowerShell), since it requires no cloud identity setup, unlike
T1078.004 which involves cloud account context — and confirm Wazuh produces
a real alert from real Sysmon telemetry of that real technique execution.

**Prerequisites this depends on**<!--h3-->

- Lab 4's VM, plus resolving the stated RDP/WinRM reachability gap from Lab
  4 first — Sysmon and agent installation will need either a working RDP
  session or working WinRM/PowerShell remoting from the host, and neither
  has been confirmed working yet.
- Sysmon (Microsoft Sysinternals, **[FREE]**) with a configuration file
  (commonly a public baseline like SwiftOnSecurity's or Olaf Hartong's
  Sysmon-modular config) tuned to log process creation (Event ID 1) and,
  for PowerShell-specific visibility, PowerShell script block logging
  (Event ID 4104) enabled via Group Policy or registry.
- The Wazuh Windows agent package, installed and pointed at this lab's
  Wazuh manager (`wazuh.manager` container from Lab 1) with the manager's
  address and an enrollment key.
- The Atomic Red Team PowerShell module (`Invoke-AtomicRedTeam`) installed
  on the guest to actually execute the T1059.001 atomic test.

**What it would teach, once done**<!--h3-->

- Whether Wazuh's default Windows/Sysmon ruleset detects the atomic test's
  execution pattern out of the box, or whether — as with the Cloudflare
  case in Lab 2 rather than the MySQL case in Lab 3 — a custom rule is
  needed to catch it, which itself would be a useful, real data point about
  Wazuh's out-of-box Windows detection coverage versus its Linux/network
  coverage demonstrated in Labs 2 and 3.
- The full, real version of the hypothetical T1059.001 triage walkthrough
  in Part 6 — turning that "here is what triage would look like" narrative
  into an actual alert with actual evidence, the same transition Labs 2 and
  3 already made for their respective detections.

Until this lab is performed, any description of what its results would look
like remains explicitly hypothetical, exactly as framed in Part 6.
