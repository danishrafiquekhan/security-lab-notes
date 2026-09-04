**Part 3.7-3.9: QEMU/QuartzVM/Windows VM, Terraform + Azure, Sigma + KQL (Detection-as-Code)**<!--h1-->

This part covers three pieces of the lab that are, on the surface, about
completely different technical domains — hardware virtualization, cloud
infrastructure-as-code, and portable detection rule authoring — but share
one theme worth naming up front: each of them is built to a real, honest,
*partial* state, and each is a useful lesson in what "done" actually means
at different layers. The Windows VM installs and boots but sits in tension
with its own tooling's design philosophy. The Terraform code is syntax-
clean but has never touched real cloud infrastructure. The Sigma rules are
real and portable in theory but were only ever actually converted for one
of the two backends this lab could target. None of that is failure —
it's exactly the kind of honest state a real, evolving lab is normally in,
and it's worth teaching as such rather than smoothing over.

**Part 3.7: QEMU, QuartzVM, and the Windows Server VM**<!--h2-->

**Hypervisor acceleration vs software emulation**<!--h3-->

**QEMU** **[FREE]** (open source, installed via Homebrew on the lab host)
is a machine emulator and virtualizer. The distinction that actually
determines whether a VM is usable or painfully slow is whether QEMU can
use **hardware-assisted virtualization** or has to fall back to **pure
software emulation**:

- **Hardware acceleration** — on Linux, KVM; on Windows, WHPX (Windows
  Hypervisor Platform); on macOS, Apple's **HVF** (Hypervisor.framework).
  These let the guest's CPU instructions execute close to natively on the
  host CPU, with the hypervisor only intervening for privileged operations
  (I/O, interrupts, memory management). This is what makes a VM feel
  close to bare-metal speed.
- **TCG (Tiny Code Generator)** — QEMU's built-in software emulation
  path, used when hardware acceleration for the guest's instruction set
  isn't available on the host. TCG translates guest instructions into host
  instructions in software, instruction by instruction, with none of the
  hardware-level shortcuts a real hypervisor gets. This is dramatically
  slower — often an order of magnitude or more — than hardware-accelerated
  execution.

The lab host is Apple Silicon (ARM64). HVF acceleration on Apple Silicon
works for **ARM64 guests** — but the Windows Server 2022 Evaluation image
is **x86_64**. There is no hardware acceleration path for running x86_64
guest instructions on an ARM64 host; Apple Silicon's CPU cannot natively
execute x86_64 machine code, hardware-assisted or otherwise. So this VM
necessarily runs under **TCG software emulation** — genuinely slow, which
is exactly why the install took roughly an hour or more rather than the
few minutes a hardware-accelerated install would take. This is worth
stating plainly rather than glossing over: an Apple Silicon Mac running an
x86_64 Windows guest via QEMU is doing full software translation of every
instruction, not "a slower VM" in the way a resource-constrained
hardware-accelerated VM is slower — it's an entirely different, much
heavier execution model.

**The disposable-lab philosophy vs what actually got built**<!--h3-->

**QuartzVM** — a real, open-source (MIT-licensed) Tauri/Rust desktop app
the user built (github.com/danishrafiquekhan/quartzvm, installable via
`quartzvm-releases`) — exists as a GUI layer over QEMU, explicitly designed
around a **"create → snapshot → destroy"** disposable-lab philosophy: spin
a VM up for a specific purpose, snapshot known-good states you want to
return to, and destroy the VM entirely when you're done, rather than
maintaining long-lived VMs that accumulate drift and risk.

Worth stating plainly, because it's a real and currently unresolved
tension in this lab rather than a settled design decision: **the actual
Windows Server VM built in this session was not driven through QuartzVM's
GUI at all** — it was built directly via raw `qemu-system-x86_64` and
`qemu-img` commands. And the VM itself, as configured, looks much more
like a persistent asset than a disposable one: it has a **hardcoded
administrator password** baked into the unattended install answer file,
and **10-boot autologon** configured (the guest will automatically log in
as the administrator for the first 10 boots without a password prompt).
Neither of those is consistent with "disposable" — a hardcoded password
and extended autologon are conveniences for a VM you expect to keep
using and coming back to, not conveniences for something you intend to
snapshot-and-destroy routinely. This is flagged here as an open,
undecided question in the lab, not a mistake quietly fixed: does this VM
get folded into QuartzVM's disposable model going forward (rotate the
password, drop autologon, start snapshotting it), or does it stay a
longer-lived asset because Atomic Red Team validation work benefits from
a stable, already-configured target? Both are legitimate answers; neither
has been chosen yet.

**Unattended installation via autounattend.xml**<!--h3-->

Rather than clicking through Windows Setup interactively, the VM was
installed **fully unattended** using an `autounattend.xml` answer file.
Understanding why this works requires understanding Windows Setup's
**configuration passes** — conceptually, a small number of distinct
phases Windows Setup runs through, each of which can read different
sections of the answer file:

- **windowsPE** — the earliest pass, running inside the WinPE
  (preinstallation environment) that boots from the installation media
  itself, before any OS is actually installed onto disk. This pass
  handles things like disk partitioning, language/locale selection for
  setup itself, and product key entry. Critically for this lab, this is
  also the pass during which **Windows Setup scans all attached media —
  including removable media like a second CD-ROM/ISO — looking for a file
  literally named `autounattend.xml` at the root.** If found, Setup
  automatically uses it to drive the rest of the install with zero
  interactive prompts. This is exactly why the answer file was built into
  its own small ISO (via macOS's `hdiutil makehybrid`) and attached as a
  **second CD-ROM device** alongside the Windows installation media itself
  — Setup finds it automatically during this earliest pass without any
  manual pointing required.
- **specialize** — runs later, after the OS image has been laid down onto
  disk and the machine has rebooted into itself for the first time in a
  semi-configured state. This pass is where machine-specific and
  component-specific configuration happens — things like computer name,
  network configuration, and enabling/configuring individual Windows
  components (firewall behavior, specific services) via their component
  identifiers in the answer file.
- **oobeSystem** — the final pass, corresponding to the interactive
  "Out-Of-Box Experience" a normal user would see (account creation,
  region/keyboard confirmation, etc.) — except here, driven by the answer
  file instead of a human, including things like the local administrator
  account password and `FirstLogonCommands` (arbitrary commands to run
  automatically the first time a user logs on).

**The real bug: a specialize-pass component name mismatch**<!--h3-->

A real, concrete failure was hit and fixed during this build. The original
`autounattend.xml` included a component in the **specialize** pass
intended to enable the Windows Firewall and configure it (with the eventual
goal of allowing RDP access) via a `Networking-MPSSVC-Svc` component
definition, using specific property names for that component's settings.
Windows Setup rejected the answer file at the specialize pass with an
error to the effect of:

```
Windows could not parse or process the unattend answer file for pass
[specialize]. The settings specified in the answer file cannot be applied.
```

This is a notoriously unhelpful class of Windows Setup error — it
identifies *which pass* failed but not *which property or line* is
actually wrong, because the underlying cause is usually a component
property name or namespace that doesn't match what that specific Windows
build's unattend schema actually expects (these schemas are versioned per
Windows build and are easy to get subtly wrong from memory or from an
example written for a different Windows version). Diagnosing this by
trying to get the exact property names right for `Networking-MPSSVC-Svc`
purely from memory/documentation turned out to be more fragile than it was
worth. The actual fix was to **remove that component from the specialize
pass entirely** and instead achieve the same end goal (firewall enabled,
RDP allowed) with plain, well-documented `netsh advfirewall` commands
placed in `FirstLogonCommands` during the **oobeSystem** pass instead —
running ordinary command-line firewall configuration after the OS is
already up, rather than fighting an XML schema for a component whose exact
expected shape wasn't reliably known. This is a good general lesson: when
a declarative configuration mechanism's exact schema is uncertain and the
failure mode is opaque, falling back to an imperative command run
after-the-fact can be the more reliable engineering choice, even though
it's less "pure" than doing everything through the declarative answer
file.

**Why BIOS/IDE instead of UEFI/virtio**<!--h3-->

The VM was configured with QEMU's `pc` machine type (i440fx chipset, BIOS
boot — not `q35`, which is the more modern UEFI-capable chipset), and its
disk and CD-ROM devices are attached as **IDE**, not the higher-performance
**virtio** paravirtualized device family QEMU also supports. This was a
deliberate compatibility choice, not an oversight: virtio devices require
guest-side drivers that Windows does not ship in-box — using virtio disk
or network devices would have meant injecting third-party virtio driver
packages (commonly the Fedora/Red Hat `virtio-win` driver ISO) into the
Windows Setup process, either by slipstreaming drivers into the
unattended install or manually loading them during setup's disk-selection
screen. BIOS/IDE, by contrast, uses device types Windows has supported
natively and driver-lessly for decades — the tradeoff is pure performance
(IDE emulation is slower than virtio, particularly for disk I/O) traded
directly for **zero additional driver dependency**, which matters more in
a first-build context where the goal is "get a working, unattended,
reproducible install" rather than "get the fastest possible VM."

**When to use this / when NOT to use this**<!--h3-->

Use QEMU with TCG-only emulation when you specifically need a
cross-architecture guest (x86_64 on ARM64 or vice versa) and can tolerate
slow installs/boots in exchange for that flexibility — it is the only way
to run this Windows Server image at all on this Apple Silicon host. Do NOT
use TCG for anything where guest performance matters at runtime (this
matters here mainly during install; once installed and idle, or running
light agent workloads like Sysmon/a Wazuh agent, the VM is usable, just
not fast). Use BIOS/IDE over UEFI/virtio specifically when driver
compatibility and setup reliability matter more than raw performance —
revisit that choice (move to virtio with injected drivers) if this VM's
workload later becomes I/O-heavy enough that IDE emulation becomes the
bottleneck. And treat the disposable-vs-persistent tension honestly rather
than pretending it's resolved: this VM, as currently configured, needs a
deliberate decision one way or the other before it's reused heavily,
particularly given the hardcoded password.

**Part 3.8: Terraform + Azure**<!--h2-->

**State: the core concept, and why remote state matters**<!--h3-->

**Terraform** **[FREE]** (open source, HashiCorp) is declarative
infrastructure-as-code: you describe the infrastructure you want in `.tf`
files, and Terraform computes and applies the changes needed to make real
infrastructure match that description. The mechanism that makes this
possible is **state** — a JSON file (`terraform.tfstate`) that records
what Terraform believes currently exists (resource IDs, attributes,
dependency relationships) so it can diff "what's declared" against "what's
real" on every run rather than blindly re-creating everything every time.

State can live **locally** (a `.tfstate` file on the machine running
Terraform) or **remotely** (a shared backend — in the Azure ecosystem,
typically an Azure Storage Account with a blob container configured as the
backend). Remote state matters for two concrete reasons, not just
"best practice" as an abstract label:

- **Locking** — a remote backend (when it supports locking, as Azure
  Storage does via blob leases) prevents two people or two automated runs
  from applying changes to the same infrastructure concurrently, which
  would otherwise corrupt state or produce conflicting real-world changes.
  Local state has no locking at all — nothing stops two terminal sessions
  on the same machine from racing each other.
- **Shared source of truth** — if state lives only on one person's laptop,
  nobody else (and no CI/CD pipeline) can safely run Terraform against
  that infrastructure without first obtaining that exact state file,
  which doesn't scale past a single operator and is fragile even then
  (lost laptop, disk failure — state gone, and with it Terraform's entire
  understanding of what it manages).

**The bootstrap chicken-and-egg problem**<!--h3-->

A specific, well-known wrinkle that `terraform-labs`' own structure
acknowledges (its numbered exercises include one specifically for "remote
state Azure backend," folder 02): to use a remote Azure Storage Account as
your Terraform backend, **that storage account itself has to already
exist** — and Terraform normally wants to be the tool that creates Azure
resources. This is a genuine chicken-and-egg problem: you can't declare
the remote-state storage account as a Terraform-managed resource *using
that same backend*, because the backend has to exist before Terraform can
even initialize. The standard resolution is to create that one bootstrap
resource (the storage account + container) manually or via a one-off local-
state Terraform run, and only *then* configure subsequent Terraform
configurations to point at it as their backend. This bootstrap step is
inherently a bit manual/imperative even in an otherwise fully declarative
workflow, and that's normal, not a flaw in the approach.

**Module composition**<!--h3-->

Terraform **modules** let a configuration be composed from reusable,
parameterized units (a "networking module," a "compute module") rather
than one flat sprawling file — `terraform-labs`' folder 03 is specifically
a networking+compute modules exercise. The principle is the same as
function/library composition in software: define an interface (input
variables, output values), implement the resource logic once, and reuse it
across environments or exercises with different inputs, rather than
copy-pasting resource blocks.

**Terraform Cloud vs local backend**<!--h3-->

**Terraform Cloud** **[FREEMIUM]** (HashiCorp's hosted service; a free
tier exists for small teams, with paid tiers for governance/policy
features at scale) provides remote state storage *and* remote plan/apply
execution, plus features like a run history UI, policy-as-code gates, and
team access controls — folder 04 in `terraform-labs` specifically explores
Terraform Cloud integration. The tradeoff versus a plain Azure Storage
Account backend: Terraform Cloud gives you a managed, richer experience
(no need to build your own CI runner for `terraform plan`/`apply`, built-
in state locking and history, a web UI) at the cost of depending on an
external hosted service and, past the free tier, real cost. A plain remote
backend (Azure Storage) gives you just state storage and locking — the
minimum needed for team-safe state — with `plan`/`apply` still run from
wherever you invoke the Terraform CLI (a laptop, a self-managed CI runner),
which is more work to wire up but keeps everything inside infrastructure
you already control.

**"Syntax valid" is not "actually deploys correctly" — and none of this has been applied**<!--h3-->

This needs to be stated with complete honesty because it's real and
important: **all seven `terraform-labs` exercise folders pass `terraform
fmt` and `terraform validate` cleanly. None of them have ever been
`terraform apply`'d against a real Azure subscription**, despite a real
free-tier Azure subscription existing (with MFA required, a spending cap
set, and `az login`-only auth per the repo's own README) for the entire
duration of this project.

This is worth unpacking as two genuinely different levels of confidence,
because conflating them is a common and consequential mistake:

- **`terraform validate` / `fmt`** confirms the configuration is
  syntactically well-formed HCL, that resource argument names and types
  match what the provider schema expects, and that references between
  resources resolve. This is a **static, local, offline** check. It
  catches typos, wrong argument names, and type mismatches. It does
  **not** contact Azure at all, and therefore cannot catch: insufficient
  IAM permissions on the executing identity, resource naming collisions
  in the target subscription, quota limits, region availability gaps for
  a specific SKU, misconfigured dependencies that are only wrong at
  *apply time* (a resource that references another resource's actual
  runtime-computed ID rather than a static value), or plain logical
  errors that are valid HCL but produce infrastructure that doesn't
  actually do what was intended.
- **A successful `terraform apply`** is the only thing that actually
  proves the configuration works against the real target platform — real
  permissions, real quotas, real naming rules, real inter-resource
  dependency ordering, all exercised for real.

`terraform-labs` sits entirely at the first level of confidence. That is
explicitly, honestly documented in the repo itself as "untested-in-anger,"
and it should be understood as exactly that here too — this is real,
carefully-written infrastructure-as-code that has demonstrated it is
*well-formed*, not that it *works*. A hiring manager or reviewer reading
this portfolio should take that distinction at face value rather than
assuming "clean Terraform repo" implies "deployed and proven"; the two are
different claims, and this lab only makes the first one.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/03c-tools-qemu-terraform-detection-as-code-8.png)

**When to use this / when NOT to use this**<!--h3-->

Use Terraform (over clicking through the Azure Portal) whenever
infrastructure needs to be reproducible, reviewable (via pull requests
against `.tf` diffs), or destroyed and recreated repeatedly — exactly the
lab-exercise pattern `terraform-labs` is built around, where
`terraform destroy` after every exercise is a stated intention. Use remote
state (Azure Storage, or Terraform Cloud) the moment more than one person
or more than one machine might ever run Terraform against the same
infrastructure — local state does not scale past a single operator on a
single machine. Do NOT present `terraform validate`-clean code as
equivalent to proven, working infrastructure — say explicitly, as this
lab does, that it has not been applied, and treat that as a concrete next
step (with the bootstrap backend problem solved first) rather than a
detail to omit.

**Part 3.9: Sigma + KQL — Detection-as-Code**<!--h2-->

**What Sigma is and why it exists**<!--h3-->

**Sigma** **[FREE]** (open source, community-maintained rule format and
converter toolchain) is a generic, YAML-based signature format for SIEM
detection rules — the stated goal of the project is "write a detection
rule once, in a platform-agnostic way, then convert it to whatever your
actual SIEM's native query language is" (via `sigma-cli`/`pySigma`
backends targeting specific platforms — Splunk SPL, Elastic Query DSL,
Microsoft Sentinel KQL, and others). The value proposition, in theory, is
that detection logic becomes portable and shareable across organizations
and platforms the way source code is portable across machines with the
same language runtime: a well-written Sigma rule expressing "flag sign-ins
from impossible travel distances within an implausible time window" should
be convertible to whichever backend a given SOC actually runs, without
each SOC having to invent that logic from scratch in their own platform's
syntax.

**The real platform-translation problem this lab actually hit**<!--h3-->

This lab is a genuinely instructive, honest case of where that "convert
once, run anywhere" promise runs into a real limit. The `detection-
engineering` repo's Sigma rules and their KQL conversions were written
**against Microsoft Sentinel's specific table schema** — `SigninLogs`,
`AuditLogs`, the actual column names and semantics Entra ID sign-in and
audit data land in inside a Sentinel workspace. That's a deliberate,
sensible choice: Sentinel is *built* for exactly this kind of cloud
identity telemetry, with purpose-built tables, built-in identity
connectors, and a KQL query surface designed around that data shape.

But the SIEM actually running live in this lab is **Wazuh**, not Sentinel
— chosen for the live lab specifically because it's free and self-hosted,
while Sentinel is consumption-priced and no real Sentinel tenant exists
for this project. Wazuh's native rule format is not KQL at all — it's an
XML-based decoder/rule system (exactly what Parts 3.5 and 3.6 above walk
through in concrete detail: `<decoder>` and `<rule>` blocks matching
regex/field patterns against normalized log fields) built around log-based
telemetry from hosts, applications, and network sources, not around
cloud identity provider API schemas like Entra ID's sign-in and audit
logs.

The honest engineering conclusion reached in this lab — stated plainly
rather than smoothed over — is that **the identity-focused Sigma/KQL
detection content in the `detection-engineering` repo was deliberately
NOT converted into Wazuh's native rule format.** Forcing that conversion
would mean writing Wazuh rules pretending to match against Entra ID
sign-in/audit-log fields that Wazuh has no actual ingestion pipeline for
in this lab — there is no Entra ID log source feeding Wazuh at all here.
A Wazuh rule with no real matching data behind it is not a working
detection; it's a rule that looks plausible in a rules file and would
fire on nothing, ever, in this environment. That would be *fake* coverage
— content that exists to look complete rather than to actually detect
anything — and this lab's standard, demonstrated consistently elsewhere
(the honest "stopped by default"/"idle" labels on TheHive and LocalStack,
the "never applied" label on Terraform), is to say plainly what's real and
what isn't rather than paper over the gap. So: the Sigma/KQL content stays
written for Sentinel's schema, because that's the platform it's actually
correct for, and it is documented as Sentinel-target content, not
Wazuh-deployed content — a real, live SOC would either stand up a genuine
Sentinel workspace with Entra ID log ingestion to run this content for
real, or accept that running it meaningfully on Wazuh would require first
building an entirely separate ingestion pipeline (an Entra ID audit log
export mechanism feeding Wazuh, analogous in spirit to the MySQL/Cloudflare
relays already built) before a native Wazuh rule would even have data to
match against — and that pipeline does not exist in this lab.

**attack-mapping.csv and MITRE ATT&CK tagging as a discipline**<!--h3-->

Independent of which backend a given rule targets, `detection-engineering`
maintains an `attack-mapping.csv` tying each Sigma rule to specific
**MITRE ATT&CK** technique IDs (e.g. T1078.004 for cloud account abuse,
T1110 for brute force, and similar). This is a discipline worth calling
out on its own: ATT&CK mapping isn't decoration on top of a detection
rule, it's what lets a rule's *coverage* be reasoned about systematically
— which techniques does this ruleset actually cover, where are the gaps,
which techniques does the organization have zero detection for at all.
Maintaining that mapping as a structured, separate artifact (a CSV,
queryable and diffable, rather than prose scattered across rule comments)
is what makes coverage analysis and gap-finding tractable at any scale
beyond a handful of rules — the same reason ATT&CK Navigator-style
heatmaps are a standard SOC reporting artifact in real security
programs.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/03c-tools-qemu-terraform-detection-as-code-9.png)

**When to use this / when NOT to use this**<!--h3-->

Use Sigma when detection logic genuinely needs to be portable across
multiple SIEM backends, or when publishing/sharing detection content for
others whose SIEM you don't control — the platform-agnostic authoring step
is real value even when only one backend ends up actually deployed, since
it forces the underlying detection logic to be expressed clearly enough to
convert at all. Do NOT treat "Sigma rule exists" as equivalent to "this
detection is live and firing somewhere" — as this lab demonstrates
directly, a Sigma rule converted to one backend's query language is only
as real as that backend actually running with the right data feeding it,
and content correctly scoped for one platform's schema (Sentinel's
identity tables here) should not be force-converted to a structurally
different platform (Wazuh's log-based rule engine) just to claim broader
coverage — that produces rules that look like detections but detect
nothing. Maintain an explicit ATT&CK mapping artifact (like
`attack-mapping.csv`) as a first-class part of any detection content
repository, not an afterthought, since it's what turns a pile of
individually-reasonable rules into an analyzable coverage picture.
