**Part 2: Environment Setup End-to-End**<!--h1-->

This section walks through setting up the host machine for this lab from a
completely clean macOS install, on Apple Silicon. Every command below is
real and was actually used to build this environment — none of it is
hypothetical. Where a step has a known failure mode, that failure mode is
documented alongside the fix, because "it just works" is rarely true the
first time and pretending otherwise doesn't help anyone reproducing this.

The host for this lab is a MacBook, Apple Silicon (M-series), 16GB RAM,
running macOS. That RAM ceiling matters throughout this section and the
rest of the document — Wazuh's three containers, TheHive's four containers,
LocalStack, Suricata, MySQL, and an x86_64 Windows VM under software
emulation are all candidates to run concurrently, and 16GB does not
comfortably hold all of them at once. Part of "setting up the environment"
is accepting that you will be starting and stopping stacks deliberately,
not leaving everything running.

**2.1 Toolchain overview**<!--h2-->

Before the command-by-command walkthrough, here is the shape of what you're
installing and why it's layered this way. Each layer depends on the one
below it being healthy — a Docker Desktop that hasn't been launched yet
will make every container command below it fail in a way that looks like a
Docker problem but is actually a "the daemon isn't running" problem.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/02-environment-setup-2.png)

The important read of this diagram: Homebrew is the single install path
for almost everything else. Docker Desktop and QEMU are peers — both sit
directly on Homebrew, both are "run untrusted/isolated things" layers, but
they solve different problems (containers for Linux-native services like
Wazuh; full x86_64 VM emulation for a Windows guest that needs its own
kernel, not a container). The cloud CLIs (Terraform, `az`, `gh`, `wrangler`
via npm) don't depend on Docker or QEMU at all — they're a separate,
parallel install track that happens to also come through Homebrew (except
`wrangler`, which comes through npm).

**2.2 Homebrew**<!--h2-->

Homebrew **[FREE]** (open source, no paid tier) is macOS's de facto package
manager and the entry point for nearly everything else in this section.

Install it fresh (if not already present):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

What this does: downloads and runs Homebrew's official install script,
which places the Homebrew prefix at `/opt/homebrew` on Apple Silicon (not
`/usr/local` — that's the Intel-Mac path, and mixing the two up is a common
source of "brew installed but command not found" confusion when following
instructions written for Intel Macs).

After install, the script itself prints the exact lines needed to add
Homebrew to your shell PATH — run them, then verify:

```bash
eval "$(/opt/homebrew/bin/brew shellenv)"
brew --version
brew doctor
```

`brew shellenv` prints the environment variables (PATH, MANPATH, etc.)
Homebrew needs and `eval`-ing it applies them to the current shell. Add the
`eval "$(/opt/homebrew/bin/brew shellenv)"` line to your `~/.zshrc` (zsh is
the default macOS shell) so every new terminal session picks it up
automatically — without this, `brew`-installed tools work in the shell you
ran the installer in but vanish in every new terminal, which looks like a
broken install but is actually just a missing PATH entry.

`brew doctor` audits your Homebrew install for common misconfigurations
(conflicting PATH entries, permission issues on Homebrew's directories) and
is worth running any time something installed via brew "isn't found" —
its output is usually specific enough to fix directly.

**2.3 Docker Desktop**<!--h2-->

Docker Desktop **[FREEMIUM]** (free for personal use and small business
under Docker's current terms; paid subscription required for larger
companies) is how every containerized piece of this lab runs: Wazuh's
three containers, TheHive's four, LocalStack, Suricata, and the MySQL
target.

Install via Homebrew cask:

```bash
brew install --cask docker
```

This downloads and installs the Docker Desktop `.app` — it does **not**
start it, and it does **not** put a working `docker` daemon on your
machine yet. This is the single most common trip-up in this whole setup
process, worth stating plainly:

**Docker Desktop must be manually launched at least once before anything
Docker-related works.** Installing the cask puts `Docker.app` in
`/Applications` and symlinks the `docker`/`docker-compose` CLI binaries
onto your PATH, but the actual container engine (a lightweight Linux VM
Docker Desktop manages internally) only starts when you open the app — via
Spotlight, `open -a Docker`, or clicking the icon — and it takes a real
number of seconds to finish starting (the whale icon in the menu bar
animates until it's ready).

Until that VM is up, every `docker` command that needs the daemon fails
with a socket-connection error that has nothing to do with your actual
command — for example:

```
$ docker info
Cannot connect to the Docker daemon at unix:///Users/you/.docker/run/docker.sock. Is the docker daemon running?
```

This looks like a broken install. It usually just means Docker Desktop's
app hasn't been launched yet, or hasn't finished starting. The fix:

```bash
open -a Docker
```

then wait (10-30 seconds is typical, longer on first launch or after a
macOS update) and confirm readiness with:

```bash
docker info
```

Once `docker info` returns a full daemon info block instead of the
socket-connection error, the daemon is live. Verify the CLI and Compose
plugin versions:

```bash
docker --version
docker compose version
```

Note the lab's compose stacks (Wazuh's `wazuh-docker`, TheHive's compose
file) use `docker compose` — the integrated `docker` CLI subcommand shipped
with Docker Desktop — not the older standalone `docker-compose` Python
tool. If you find yourself following an older Wazuh tutorial that
references `docker-compose` (hyphenated), substitute `docker compose`
(space) throughout; the hyphenated tool is deprecated and may not even be
present on a fresh Docker Desktop install.

A second real constraint to note now, because it shapes how you'll
operate this lab day to day: with 16GB of host RAM, running Wazuh (3
containers) + TheHive's stack (4 containers, including two JVM-heavy
services — Cassandra and Elasticsearch) + LocalStack + Suricata + MySQL
simultaneously will contend hard for memory. Docker Desktop's own
Resources settings (Settings → Resources) let you cap how much RAM/CPU the
Docker VM itself is allowed to use — check this setting if containers start
getting OOM-killed or the whole Mac becomes sluggish; it's not unusual to
need to explicitly `docker compose down` one stack before bringing another
one up on a 16GB machine.

**2.4 QEMU**<!--h2-->

QEMU **[FREE]** (GPL, no paid tier) is the machine emulator/virtualizer
used in this lab to build the Windows Server 2022 evaluation VM from raw
ISO, without going through a heavier commercial virtualization product.

Install via Homebrew:

```bash
brew install qemu
```

Verify both binaries this lab actually uses are on PATH — `qemu-img` for
disk image creation/management, and the x86_64 system emulator specifically
(Homebrew's `qemu` formula installs emulators for many target
architectures; the Windows guest needs the x86_64 one):

```bash
qemu-img --version
qemu-system-x86_64 --version
which qemu-img qemu-system-x86_64
```

Both should resolve to paths under `/opt/homebrew/bin/`. If
`qemu-system-x86_64` is missing while `qemu-img` is present, it usually
means an incomplete or corrupted brew install — `brew reinstall qemu`
resolves it.

A note on why this lab uses raw `qemu-system-x86_64` commands directly
rather than a GUI: QuartzVM (github.com/danishrafiquekhan/quartzvm), a
Tauri/Rust desktop app the lab's author also built as a separate open-source
project, exists specifically to wrap QEMU behind a "create → snapshot →
destroy" disposable-lab UI. It's mentioned here because it's part of the
same author's toolkit and worth knowing about, but the actual Windows VM
build documented in this lab was driven directly via raw QEMU commands, not
through QuartzVM's GUI — useful to know if you're trying to reproduce this
lab exactly rather than through the GUI tool.

The core command shape used to boot the Windows Server 2022 VM (covered in
full, with the unattended-install answer file and the firewall/RDP bug fix,
in the identity/VM-focused section of this document) looks like:

```bash
qemu-system-x86_64 \
  -machine pc \
  -m 4096 \
  -smp 2 \
  -drive file=win2022.qcow2,if=ide \
  -cdrom WindowsServer2022.iso \
  -drive file=autounattend.iso,if=ide,media=cdrom \
  -boot d
```

Two deliberate choices are worth calling out at the setup-planning stage, before
you even get to the install: `-machine pc` (the older i440fx BIOS-boot
chipset, not `q35`/UEFI) and `-drive ...,if=ide` (IDE disk/CD-ROM
controllers, not virtio) were both chosen for maximum guest driver
compatibility — Windows Server's installer recognizes IDE/BIOS hardware out
of the box, whereas virtio disk/network controllers need drivers injected
during setup that Windows doesn't ship natively. This trades performance
for "it boots without extra steps," which is the right tradeoff for a lab
VM you're building once, not a production hypervisor guest. And because
this is an x86_64 guest running on an Apple Silicon (arm64) host, QEMU
falls back to TCG (software) emulation rather than hardware-accelerated
virtualization — genuinely slow, expect over an hour for a full Windows
Server install, not a misconfiguration to debug.

**2.5 Terraform and Azure CLI**<!--h2-->

Terraform **[FREE]** (open source CLI; Terraform Cloud has a free tier used
in one of the `terraform-labs` exercises, with paid tiers above it) and the
Azure CLI **[FREE]** (the CLI tool itself is free; what it manages —
Azure resources — is billed separately, and the lab's Azure subscription is
a free-tier account with a spending cap) are installed for the
`terraform-labs` repo's exercises.

```bash
brew install terraform azure-cli
```

Verify:

```bash
terraform -version
az version
```

Authenticate the Azure CLI interactively — this lab's own documented
convention (per the `terraform-labs` README) is to authenticate only via
interactive `az login`, never long-lived service principal secrets checked
into anything:

```bash
az login
```

This opens a browser window for interactive sign-in and, on success,
prints the subscription(s) the authenticated account can see as JSON to
the terminal. Confirm the active subscription matches the intended
free-tier one before running anything:

```bash
az account show
```

Terraform itself needs no separate login step for Azure — it authenticates
through the same Azure CLI session via the `azurerm` provider's
`use_cli = true` behavior (or by default, when no explicit credentials
block is set and an active `az login` session exists). Confirm a `.tf`
directory is ready with:

```bash
terraform init
terraform validate
```

`terraform init` downloads the provider plugins a configuration references
(the `azurerm` provider, and for the Terraform Cloud exercise, remote
backend configuration) into a local `.terraform/` directory. `terraform
validate` checks syntax and internal consistency without touching any real
cloud resources — safe to run repeatedly, and the right first check after
any edit. Per this lab's own honestly-documented status: every exercise in
`terraform-labs` passes `fmt`/`validate` clean, but none have ever been
`terraform apply`'d against the real Azure subscription. That's a
deliberate, stated gap, not an oversight in this walkthrough — `apply`
needs its own review of the spending cap and MFA state before it's run for
real, which is outside the scope of "get your environment set up."

**2.6 GitHub CLI (gh)**<!--h2-->

GitHub CLI **[FREE]** is used throughout this lab's workflow for pushing
the portfolio repos and managing pull requests/issues from the terminal
rather than the browser.

```bash
brew install gh
```

Authenticate:

```bash
gh auth login
```

This launches an interactive prompt: choose `GitHub.com`, choose `HTTPS`
or `SSH` for your preferred git protocol, and choose the browser-based
device-code authentication flow (simplest — it opens github.com in your
browser, shows an 8-character code, you paste it in, and the CLI session
authenticates once you approve). Alternatively, `gh auth login --with-token
< token.txt` accepts a pre-generated personal access token piped in,
useful for non-interactive/scripted setups, but the interactive browser
flow is the simpler default for a one-time human setup.

Verify:

```bash
gh auth status
```

This should report the authenticated account and confirm the token's
scopes. From here, `gh repo clone`, `gh pr create`, `gh repo create
--public`, etc. all work without further credential setup — this is how
this lab's public portfolio repos got created and pushed.

**2.7 Node.js, npm, and wrangler**<!--h2-->

Node.js and npm **[FREE]** are needed for one specific purpose in this lab:
running `wrangler`, Cloudflare's CLI, which manages the Cloudflare Pages
site (`soc-lab-target.pages.dev`) and — critically — tails its live request
logs for the Wazuh JSON-log pipeline described elsewhere in this document.

```bash
brew install node
node --version
npm --version
```

Install wrangler globally, or use `npx` to run it without a global install
— this lab uses the global install for convenience since it's invoked
frequently during live-traffic testing sessions:

```bash
npm install -g wrangler
wrangler --version
```

Authenticate wrangler to Cloudflare:

```bash
wrangler login
```

This opens a browser-based OAuth consent flow. This is worth spelling out
explicitly because it was a real, documented lesson from building this lab:
the OAuth login flow grants wrangler a broad, pre-defined set of scopes
sufficient for typical Pages/Workers management out of the box. The
alternative — hand-creating a scoped Cloudflare API token via the
dashboard's custom token permission-group UI — is easy to under-scope by
accident. During this lab's setup, the first hand-created token was scoped
only for R2 storage (wrong for Pages entirely), and two subsequent attempts
were missing the specific "Pages: Edit" permission group before a working
token was finally assembled. The `wrangler login` OAuth flow sidestepped
all of that by requesting a broader, correct scope in one step. For a
single-operator lab like this one, prefer `wrangler login` over hand-scoping
a token unless you specifically need a narrowly-scoped token for a
CI/automation context.

Once authenticated, the command this lab relies on for live traffic capture
(covered in depth in the Cloudflare/live-traffic section of this document)
is:

```bash
wrangler pages deployment tail <deployment-id> --format=json
```

Flagging one real limitation now, at the setup stage, because it affects
how you'd operate this day to day: this command binds to a specific
deployment ID, not "the current live deployment" — every time the Pages
site is redeployed, the tail command targeting the old deployment ID stops
receiving traffic and needs to be restarted against the new ID. There is no
setup fix for this; it's a real, current limitation of `wrangler pages
deployment tail` to plan around operationally.

**2.8 Python 3, and why venvs per project (not a global environment)**<!--h2-->

Python 3 is used across this lab for the relay scripts (MySQL log relay,
Cloudflare traffic relay) and the `llm-triage`/`log-correlation` tooling in
the `detection-engineering` repo. macOS ships a system Python, but do not
use it for project work — install a current Python via Homebrew instead:

```bash
brew install python@3.12
python3 --version
```

The general principle this lab follows, and that this section recommends
regardless of which specific scripts you're running: **use a fresh virtual
environment (venv) per project, never a single global site-packages
environment for everything.**

Why this matters concretely, not just as best-practice folklore: this lab
spans several genuinely different Python dependency sets — a relay script
using nothing but the standard library plus a couple of small parsing
libraries, `llm-triage` scripts depending on Anthropic's Python SDK, and
the `intune-endpoint-health-platform` repo's duplicate-asset-reconciliation
script depending on `pandas` for fuzzy matching. Installing all of that
into one global Python environment means every project's dependencies (and
their transitive version constraints) share one namespace — a `pandas`
version bump for one project can silently break an unrelated script that
imported a different `pandas` API surface, and there's no clean way to
answer "what does this specific script actually need to run" months later.
A dedicated venv per project directory keeps each project's dependency
graph isolated, reproducible via a per-project `requirements.txt`, and
disposable — deleting a stale project's venv directory cleans it up
completely with zero risk to any other project.

The standard pattern, run from inside each project directory:

```bash
cd ~/securitylab/<project-dir>
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt   # or pip install <packages>, then pip freeze > requirements.txt
```

`python3 -m venv .venv` creates an isolated Python environment (its own
`site-packages`, its own `pip`) in a `.venv` directory local to the
project. `source .venv/bin/activate` puts that environment's `python`/`pip`
first on PATH for the current shell session — your prompt typically grows
a `(.venv)` prefix as a visual confirmation it's active. From that point,
`pip install` only affects this project's isolated environment, not the
system or any other project's venv. `deactivate` (no arguments) exits back
to the normal shell environment when you're done.

A `.gitignore` entry for `.venv/` in every project is worth calling out
explicitly here too — venvs are large, machine-specific, and trivially
regenerable from `requirements.txt`, so they should never be committed.

**2.9 Verify your setup — full checklist**<!--h2-->

Run this block top to bottom in a fresh terminal after completing every
step above. Each line should succeed and print a version or status, not an
error. This is the fastest way to catch a PATH problem or an unlaunched
Docker Desktop before you're mid-way through standing up a stack and
confused about why it's failing.

```bash
# Homebrew itself
brew --version

# Docker — CLI presence, then daemon health
docker --version
docker compose version
docker info                     # fails with a socket error if Docker Desktop's app isn't running

# QEMU
qemu-img --version
qemu-system-x86_64 --version

# Terraform + Azure CLI
terraform -version
az version
az account show                 # confirms an active az login session

# GitHub CLI
gh --version
gh auth status                  # confirms authenticated

# Node/npm + wrangler
node --version
npm --version
wrangler --version
wrangler whoami                 # confirms authenticated to Cloudflare

# Python
python3 --version
python3 -m venv --help | head -1   # confirms the venv module is available
```

If `docker info` fails: launch Docker Desktop (`open -a Docker`) and wait
for the whale icon in the menu bar to stop animating, then retry.

If `az account show` errors with "Please run 'az login'": the CLI is
installed correctly but no session exists yet — run `az login` and retry.

If `gh auth status` or `wrangler whoami` report not-authenticated: re-run
the respective `login` command from the sections above — both use
browser-based flows and are quick to redo.

If any `brew`-installed binary reports "command not found" despite a
successful `brew install`: it's almost always a missing
`eval "$(/opt/homebrew/bin/brew shellenv)"` in your shell's startup file
(`~/.zshrc` on the default macOS shell) rather than a failed install —
confirm with `echo $PATH | grep -o /opt/homebrew/bin` before reinstalling
anything.

With every line in this checklist passing, the host is ready for the
tool-by-tool stack setup covered in Part 3.
