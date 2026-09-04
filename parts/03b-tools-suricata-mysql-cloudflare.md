**Part 3.4-3.6: Suricata, MySQL, Cloudflare Pages + Workers/Functions**<!--h1-->

This part covers three very different kinds of monitored target in the lab:
a network intrusion detection engine that is built but not yet wired in
(Suricata), a database that was stood up specifically to be attacked and
watched (MySQL), and a real, live, public web target whose logs have to be
smuggled out of a platform that doesn't want to give them to you for free
(Cloudflare Pages + Functions). Read together, they make a useful point:
how much detection work a target needs depends entirely on how close its
native log format already is to what your SIEM expects. MySQL needed zero
custom Wazuh rules or decoders. Cloudflare needed a custom rule but no
custom decoder. Suricata, if and when it gets wired in, will need custom
rules too — like Cloudflare, not like MySQL — because Wazuh ships no
built-in Suricata ruleset, even though its EVE JSON is already
well-structured enough that it won't need a custom decoder either. That
contrast is the throughline of this part.

**Part 3.4: Suricata — Network Intrusion Detection**<!--h2-->

**What a network IDS actually does**<!--h3-->

**Suricata** **[FREE]** (open source, GPLv2, maintained by the Open
Information Security Foundation) is a network intrusion detection and
prevention engine (NIDS/NIPS). At the level that matters for this lab, a
network IDS sits somewhere it can see raw traffic — a mirrored switch
port, a tap, a container network namespace, a host interface in promiscuous
mode — and inspects packets as they cross the wire, independent of whatever
the endpoint itself logs or doesn't log. This is a fundamentally different
vantage point from everything else in this lab so far. Wazuh's other
inputs (MySQL logs, Cloudflare Function logs) are all *application-layer,
after-the-fact* records: something already decided to write a log line, and
Wazuh consumes that decision. A NIDS doesn't wait for an application to
decide to log anything. It sees the packets themselves, so it can catch
things no application log would ever mention — a port scan, a C2 beacon
using a protocol nobody instrumented, a plaintext credential crossing the
wire in a protocol that was never supposed to carry it in the clear.

**Signature-based detection vs anomaly detection**<!--h3-->

Suricata (like its predecessor/sibling Snort) is primarily a
**signature-based** engine, though it supports some anomaly-style features.
The distinction matters and is worth being precise about:

**Signature-based detection** matches traffic against a database of known
patterns — a specific byte sequence in a payload, a specific combination of
protocol fields, a known-bad IP or domain, a regex against a URL. Suricata
uses rules written in a specific syntax (largely compatible with Snort's
rule language), for example a simplified illustrative rule shape:

```
alert tcp any any -> $HOME_NET 3306 (msg:"Possible MySQL brute force";
  flow:to_server; content:"|4d 79 53 51 4c|"; threshold:type both, track by_src,
  count 5, seconds 60; sid:1000001; rev:1;)
```

(This is an illustrative example of the rule *shape*, not a rule that has
been written, loaded, or tested against Suricata in this lab — Suricata is
currently stopped/idle, as noted below.) The strength of signature-based
detection is precision: when a signature fires, you know exactly what
matched and why, which makes triage fast and false-positive tuning
tractable. The weakness is coverage: a signature-based engine can only
catch what someone already wrote a signature for. Zero-days, novel
malware, and attackers who deliberately avoid known IOCs sail straight
through.

**Anomaly-based detection** (statistical baselining, machine-learning
classifiers, protocol-anomaly detection) instead tries to learn what
"normal" traffic looks like for an environment and flag deviations from
that baseline — a host that suddenly starts talking to a hundred new
destinations, a protocol used at a volume or time-of-day it's never used
at before. The strength is that it can catch genuinely novel attacks with
no prior signature. The weakness is noise: baselines drift, "normal" is
messy in a real network, and anomaly detectors are notorious for high
false-positive rates unless heavily tuned — which is itself a nontrivial
ongoing labor cost, not a one-time setup cost.

In production, the two approaches are complementary, not competing:
signature-based engines like Suricata catch known-bad fast and cheap;
anomaly/behavioral layers (increasingly, this is what "XDR" vendors sell as
their differentiator on top of a base like this) catch what signatures
miss, at the cost of more tuning and more analyst judgment on each alert.

**Why Suricata is "the obvious next thing to feed into Wazuh" — and why it isn't wired in yet**<!--h3-->

Suricata's container (`jasonish/suricata:latest`) was built previously in
this lab and is currently **stopped/idle** — it has not been running
during this document's session, and it is not currently feeding Wazuh
anything. This is a deliberate, honestly-documented gap, not an oversight
being glossed over.

The reasoning for calling it "the obvious next thing" is architectural, not
aspirational hand-waving: every other source Wazuh currently ingests in
this lab (MySQL logs, Cloudflare Function logs) is an *application* log —
something a specific piece of software chose to write down. Suricata would
give Wazuh its first *network-layer* visibility: traffic Wazuh currently
cannot see at all, regardless of what any application on top of that
traffic decides to log. Concretely, Suricata emits an EVE JSON log
(`eve.json`) with event types like `alert`, `dns`, `http`, `tls`, `flow` —
Wazuh's `<log_format>json</log_format>` localfile mechanism (the same
mechanism already proven out for the Cloudflare relay, see Part 3.6 below)
is the natural ingestion path, since EVE JSON is already structured JSON
Wazuh can auto-decode into `data.<field>` keys without a custom decoder.
What *would* be needed is custom Wazuh rules that match on Suricata's
specific field names (`alert.signature`, `alert.category`, `src_ip`,
`dest_port`, etc.) — Wazuh ships no built-in Suricata ruleset the way it
does for MySQL, so this would look architecturally like the Cloudflare
integration (custom rule, no custom decoder) rather than the MySQL one
(fully built-in). That parallel is exactly why it's called out as "next":
the pattern is already proven twice in this lab, just not yet applied to
network traffic.

**When to use this / when NOT to use this**<!--h3-->

Use a NIDS like Suricata when you need visibility into traffic your
endpoints and applications don't or can't log — lateral movement between
hosts that never touches an instrumented application, C2 beaconing,
protocol misuse, traffic to/from known-bad infrastructure. Don't expect it
to replace endpoint or application logging — it has zero visibility into
what happens *inside* an encrypted TLS session past the handshake/SNI
(without TLS interception, which this lab does not do and which carries
its own significant tradeoffs), and it says nothing about what a user did
once authenticated. In this lab specifically: do not describe Suricata as
"deployed" or "detecting" anything right now — it is a stopped container
with real prior build work behind it, not a live control.

**Part 3.5: MySQL as a Monitored, Attacked Lab Target**<!--h2-->

**Why a real MySQL container**<!--h3-->

A real MySQL 8.0 container (`soc-lab-mysql`) — **[FREE]** (MySQL Community
Edition, GPL) — was stood up in this lab session specifically to be a
monitored and attacked target, not a functional application backend. The
point was to generate real authentication log lines from real failed
login attempts and prove those lines reach Wazuh and fire a real rule —
end to end, not simulated.

**general_log vs error_log — and why that distinction is a real production tradeoff**<!--h3-->

MySQL ships (at minimum) two separate logging subsystems relevant here,
and conflating them is a common mistake:

- **error_log** — logs server-level events: startup/shutdown, crashes,
  and, critically for this lab, **authentication failures** (failed login
  attempts show up here as `Access denied for user '...'@'...'`). This
  log is bounded in practice — it only writes on events that actually
  matter (errors, warnings, connection failures), so its volume is
  proportional to how much is going *wrong*, not to overall traffic.
- **general_log** (the general query log) — logs *every single statement*
  the server executes: every `SELECT`, every `INSERT`, every connection
  and disconnection, from every client, successful or not. This is
  enabled in this lab (both general query logging and error logging are
  on for `soc-lab-mysql`) specifically for lab visibility.

The reason this distinction matters far beyond this lab is a real,
recurring production tradeoff: **general_log gives you complete audit
visibility — literally every query anyone ran — but at unbounded,
traffic-proportional cost.** On a busy production database, the general
query log can dwarf the actual data volume of the database itself in
short order, because it captures full statement text for every single
query, all the time. That has three concrete costs: disk (the log file
grows without bound if not rotated aggressively), I/O performance (every
query now incurs an extra synchronous or buffered write to the log target,
which for `FILE` output competes with the database's own I/O), and
potentially very serious data-exposure risk (query text often contains
literal values — including, in a badly designed application, plaintext
credentials or PII passed as query parameters — sitting in a log file with
whatever access controls that file happens to have, which are usually
much looser than the database's own access controls). This is precisely
why general_log is *off by default* in MySQL and why production DBAs
enable it only surgically — for a bounded diagnostic window, or filtered
to specific users/statement types — rather than leaving it on
indefinitely. In this lab it's left on because the lab's entire purpose is
generating visible activity to detect, and disk/performance cost is a
non-issue at this scale; a security engineer reading this should not
walk away thinking "just turn general_log on in production," they should
walk away understanding *why that's a real decision with a real cost*,
made deliberately here because the tradeoff doesn't bite at lab scale.

**Wazuh's built-in MySQL decoder and rules**<!--h3-->

Wazuh ships built-in support for MySQL's log format out of the box, in two
files inside its default ruleset:

- `ruleset/decoders/0150-mysql_decoders.xml` — the decoder(s) that parse a
  MySQL log line into fields Wazuh's rule engine can match against.
- `ruleset/rules/0295-mysql_rules.xml` — the rule definitions that fire
  based on what the decoder extracted, including rule ID **50106**,
  "MySQL: authentication failure" (level 9).

This is the single biggest practical difference between the MySQL
integration and the Cloudflare integration described in Part 3.6: **no
custom Wazuh rule or decoder was needed for MySQL at all.** Wazuh already
speaks MySQL's log dialect natively. The only integration work required
was getting MySQL's actual log lines into the exact shape Wazuh's existing
decoder is written to expect.

**The prematch problem, and how the relay bridges it**<!--h3-->

Wazuh's built-in MySQL decoder is written around a specific `prematch`
pattern — conceptually, it expects to see a log line that begins with a
literal string resembling `MySQL log: ` followed by the actual event text
(this is the decoder's anchor for "this line is MySQL, hand it to the
MySQL decoding logic"). Real MySQL log output — whether from
`error.log` or `general.log` — does **not** naturally start with that
string. MySQL writes its own native format (timestamped, with its own
prefix conventions per log type), and it has no setting that reformats its
output to match an arbitrary third-party SIEM's expected prematch string.

This is the gap a small **Python relay script** exists to bridge. The
relay's job, conceptually, is:

1. **Tail** MySQL's `error.log` and `general.log` files continuously
   (the same tailing-a-growing-file pattern used elsewhere in this lab,
   e.g. the Cloudflare `wrangler tail` relay, though this one reads local
   files directly rather than a streaming CLI).
2. **Filter/match** each new line against the patterns that indicate an
   event Wazuh's decoder cares about — in particular, authentication
   failure lines (`Access denied for user ...`).
3. **Reformat** each matching line by prepending the literal
   `MySQL log: ` prefix (and otherwise preserving the original event text)
   so the resulting line is byte-for-byte shaped the way Wazuh's built-in
   `0150-mysql_decoders.xml` decoder is written to expect.
4. **Append** the reformatted line to a separate output file that is
   bind-mounted into the Wazuh manager container's filesystem.
5. Wazuh's manager, via a `<localfile>` block configured with
   `<log_format>syslog</log_format>` pointed at that bind-mounted file
   path, picks up each new appended line, runs it through the decoder
   pipeline, and — because the line now matches the expected prematch —
   the MySQL decoder successfully parses it and hands it to the rule
   engine.

The relay is, in effect, a translation layer between "the log format the
source software actually writes" and "the log format the SIEM's built-in
content was written to expect." This is an extremely common real-world
pattern — very few security tools' out-of-the-box decoders match an
arbitrary application's actual log output byte-for-byte, and the practical
fix is almost always a small normalization step ahead of ingestion, not
rewriting the SIEM's decoder.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/03b-tools-suricata-mysql-cloudflare-6.png)

**The verified result**<!--h3-->

This was verified live, not simulated: **4 deliberate wrong-password login
attempts** against `soc-lab-mysql` produced 4 corresponding
`Access denied` lines in MySQL's error log, which the relay picked up,
reformatted, and appended to the bind-mounted file, which Wazuh's manager
ingested and correctly decoded, causing **rule 50106 ("MySQL:
authentication failure", level 9)** to fire. Because this rule already
ships in Wazuh's default ruleset with compliance mappings attached, the
resulting alert automatically carried **PCI DSS, GDPR, HIPAA, and NIST
800-53** control references — no manual mapping work was required, purely
because the rule was already tagged that way in Wazuh's shipped content.
This is a useful, honest illustration of what "compliance mapping" means
in a SIEM in practice: it's metadata attached to a rule ahead of time by
whoever wrote the rule, surfaced automatically when the rule fires — not
something computed dynamically from the alert content, and not something
this lab built itself.

**When to use this / when NOT to use this**<!--h3-->

Use built-in vendor decoders/rules whenever the target software is common
enough that the SIEM vendor already wrote content for it — MySQL, SSH,
sudo, Windows Security Event Log, and similar high-prevalence sources
usually have mature built-in coverage in Wazuh, and reinventing that
coverage from scratch is wasted effort. Do NOT assume built-in coverage
means zero integration work, though — as shown here, the log source still
has to actually reach the SIEM in the format the decoder expects, and
bridging "real log format" to "decoder-expected format" is very often
still necessary, via a relay/normalization step exactly like the one built
here. Do not enable full general query logging on anything that isn't a
disposable lab target without deliberately weighing the disk, I/O, and
data-exposure costs described above.

**Part 3.6: Cloudflare Pages + Workers/Functions**<!--h2-->

**Static hosting vs edge compute — the distinction that matters here**<!--h3-->

**Cloudflare Pages** **[FREEMIUM]** (static hosting is free; Logpush/log
retention requires a paid plan — the specific limit that matters most for
this lab, explained below) is, at its core, a static site host: it serves
pre-built HTML/CSS/JS files from Cloudflare's edge network, with no
server-side execution per request by default. **Cloudflare
Pages Functions** (built on the same underlying platform as **Cloudflare
Workers** **[FREEMIUM]**, free tier with a daily request-count cap) add
edge *compute* on top of that static hosting — small JavaScript functions
that execute at Cloudflare's edge, in front of or alongside the static
content, for every matching request. This is the same static-vs-dynamic
distinction that shows up everywhere in web architecture, just pushed all
the way out to the CDN edge instead of living in an origin server: static
hosting alone cannot observe, log, or react to individual requests beyond
what the CDN's own access logs might capture (and on Free tier, as below,
that's effectively nothing persistent); a Function can run arbitrary code
on every request — including, as built here, logging it.

**The lab's real setup**<!--h3-->

The live target is `soc-lab-target.pages.dev`, a real, public, Free-tier
Cloudflare Pages site — three static pages (a home page, a dummy
`/login.html` that logs to the browser console and does nothing else, a
dummy `/contact.html`), every page tagged `noindex,nofollow` and carrying
an on-page banner disclosing plainly that this is a synthetic lab fixture,
not a real company, and collects nothing. A Cloudflare Pages Function at
`functions/_middleware.js` runs on every real request to the site and logs
method, path, client IP (via the `cf-connecting-ip` header Cloudflare
attaches), country, and user-agent via `console.log`.

**Why Free tier has no Logpush, and what that means practically**<!--h3-->

Cloudflare's **Logpush** product — continuous, durable streaming of
request/log data out to an external destination (S3, a SIEM, etc.) — is a
paid-plan feature. On Free tier, `console.log` output from a Pages
Function exists only transiently, surfaced through Cloudflare's real-time
tailing tooling, with **no built-in persistence** and no way to query
"what happened yesterday" after the fact. Practically, this means the
Free tier gives you *visibility into traffic happening right now, while
you are actively watching*, and nothing else — there is no log storage
to fall back on, no historical query capability, nothing to backfill from
if you weren't tailing at the moment a request happened. Any persistence
has to be built by the user, which is exactly what this lab's Python relay
does (see below): live-tail, capture, and durably append to your own file
before Cloudflare's transient view of that request disappears.

**The wrangler-tail limitation: bound to a deployment ID**<!--h3-->

Live traffic is captured via:

```
wrangler pages deployment tail --format=json
```

**[FREE]** (`wrangler` is Cloudflare's free CLI). The critical limitation,
verified in this lab and worth stating plainly: `wrangler pages deployment
tail` is bound to a **specific deployment ID**, not to the project or
domain in general. Every time the Pages site is redeployed — including for
something as small as a content typo fix — Cloudflare creates a new
deployment ID, and the previously running tail session silently stops
receiving new traffic because it's still attached to the old, now-stale
deployment. This is a real, documented limitation that breaks the
intuitive expectation of "persistent monitoring": you cannot start one
tail process and assume it keeps working indefinitely across the site's
lifecycle. In practice this means the tail process has to be restarted
against the new deployment ID after every deploy, which is a manual step
today in this lab — there is no automated "always follow the latest
deployment" mode being used here. Anyone building this for real,
persistent monitoring would need to script deployment-ID discovery and
tail-process restart around every deploy, or move to a paid plan with
Logpush instead of relying on `wrangler tail` at all.

**The relay and Wazuh ingestion — and why this needed a custom rule but no custom decoder**<!--h3-->

The `wrangler pages deployment tail --format=json` output is parsed by a
Python relay script and appended to a file that Wazuh watches with
`<log_format>json</log_format>` configured on the corresponding
`<localfile>` block. Wazuh's JSON log format handling auto-decodes
top-level JSON keys into `data.<field>` namespacing for rule matching —
so `{"method": "GET", "path": "/login.html", "ip": "203.0.113.7", ...}`
becomes matchable as `data.method`, `data.path`, `data.ip`, and so on,
**with no custom decoder required.** This is a direct contrast with the
MySQL integration in Part 3.5: MySQL required *reformatting the log line*
(via the relay) to fit an *existing* decoder, because Wazuh ships a
purpose-built MySQL decoder and ruleset. Cloudflare's Pages Function log
is arbitrary JSON with field names nobody at Wazuh anticipated, so there
is no purpose-built decoder to fit — but because it's already
well-formed JSON, Wazuh's generic JSON handling parses its structure for
free. What Cloudflare's traffic *does* need, that MySQL's didn't, is a
**custom rule** — Wazuh has no pre-existing knowledge of what a request to
`/login.html` on this specific site should mean, because no vendor ships
detection content for one lab's own bespoke web app. A custom local rule
(id **100011**, level 7) was written to fire on any request to
`/login.html`, framed as "possible scanner/credential-testing activity."

This pairing — MySQL (built-in decoder + built-in rule, custom
reformatting relay only) vs Cloudflare (auto-parsed JSON, custom rule,
no decoder needed) — is a genuinely useful teaching contrast about how
detection engineering effort is distributed. The work is never uniform
across sources; it shifts entirely based on how close the target's native
output already is to (a) a format the SIEM's *parser* understands
structurally, and (b) a format the SIEM's *rule content* already has
opinions about semantically. A source can need heavy help on one axis and
none on the other, as both of these prove in opposite ways.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/03b-tools-suricata-mysql-cloudflare-7.png)

**Verified result**<!--h3-->

This was verified live with real `curl` traffic against the public site
producing real alerts in Wazuh — a genuine end-to-end path from an actual
HTTP request, through Cloudflare's edge, through the tail-and-relay
pipeline, into a firing custom rule.

**When to use this / when NOT to use this**<!--h3-->

Use Cloudflare Pages Functions when you want edge-level request visibility
or edge-level logic (auth checks, redirects, header injection, and here,
logging) without standing up and paying for an origin server. Do NOT treat
Free-tier `wrangler tail` as a substitute for real persistent log
retention in anything beyond a lab — the deployment-ID binding alone makes
it unsuitable for continuous production monitoring without real
automation wrapped around it, and Logpush (paid) or shipping logs via a
Worker to an external store on every request are the actual production
answers. When deciding whether a custom Wazuh decoder is needed for a new
JSON-emitting source, check first whether it's already well-formed JSON
(often no decoder needed, per this section) versus a bespoke text format
(usually needs one) — but expect to write a custom *rule* almost every
time the source is your own bespoke application rather than well-known
third-party software, since no SIEM vendor ships content for logic nobody
but you wrote.
