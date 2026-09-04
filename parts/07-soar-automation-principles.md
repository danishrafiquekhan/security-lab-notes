**Part 7: SOAR & Automation Principles**<!--h1-->

SOAR — Security Orchestration, Automation, and Response — is the practice of
turning repeatable response actions into code instead of a runbook a human
executes by hand every time. This lab's SOAR content lives in
`sentinel-soar-playbooks`, three playbook **designs** written for Microsoft
Sentinel **[PAID]** (consumption-based; a free trial tenant is reachable via
the M365 Developer Program) using Logic Apps as the automation engine. It is
important to be precise about what "playbook design" means here: these are
architecturally complete designs — trigger, logic, permissions, approval
gates all specified — but none of them are deployed, because no real
Sentinel tenant exists in this lab. Section 7.2 covers exactly what that
honestly means as a portfolio artifact.

**7.1 When to automate vs. keep a human in the loop**<!--h2-->

The real principle, and the one these three playbooks are each built around,
is a function of two variables: **reversibility** and **blast radius**.

- **Low-risk, high-volume, reversible actions** are exactly what automation
  is for. If an action can be undone with no lasting harm, and a human doing
  it manually a hundred times a day is pure toil, automate it without a
  gate. Enrichment — looking things up, attaching context to an alert —
  is the canonical example: it changes nothing in the environment, so there
  is no failure mode where automating it does damage.
- **Irreversible or high-blast-radius actions** — anything that changes a
  real user's or real system's state in a way that isn't trivially undone,
  or that affects someone's ability to do their job — need a human
  explicitly in the loop before execution, not just notified after the
  fact. The cost of a false positive here (disabling the wrong account,
  isolating the wrong device) is not "an analyst wastes five minutes
  reviewing a lookup" — it's an actual business disruption, which is a
  categorically different risk than automation-for-enrichment carries.

This is not a binary "automate everything cautious, gate everything risky"
rule applied uniformly — it's a spectrum, and the three playbooks in this
lab sit at three different points on it deliberately, which is exactly why
they're useful to study together rather than in isolation:

| Playbook | Reversibility | Blast radius | Human gate? |
|---|---|---|---|
| auto-enrich-signin-alert | Fully reversible (read-only) | None | No |
| disable-compromised-user | Reversible, but disrupts a real person immediately | High (one user's access) | Yes — Teams approval |
| isolate-infected-device | Reversible (selective isolation), un-isolation is the risky reverse | High (one device's network access) | Partial — isolate is automated, un-isolate is manual-only |

**7.2 Playbook design walkthroughs**<!--h2-->

**Playbook 1: auto-enrich-signin-alert — no approval gate, and why**<!--h3-->

**What it does.** Triggered by a Sentinel sign-in risk alert, this playbook
performs read-only lookups: resolving the signing-in user's normal
behavioral baseline, checking the source IP against threat intelligence /
geolocation, pulling recent sign-in history for the same account, and
attaching all of it back onto the alert as enrichment before a human analyst
ever looks at it.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/07-soar-automation-principles-13.png)

**Why no approval gate is needed here.** Every action this playbook takes is
a *read*. It queries state; it changes nothing. There is no scenario in
which running this playbook against the wrong alert, or running it twice, or
running it against a legitimate sign-in, causes any harm — the worst case is
wasted API calls. This is precisely the "low-risk, high-volume, reversible"
category from 7.1, and it's also the highest-value automation target in
practice, because enrichment is exactly the kind of repetitive lookup work
that eats analyst time without requiring analyst judgment — the judgment
still happens, it just happens with the evidence already assembled instead
of the analyst spending the first five minutes of triage gathering it
manually. This maps directly to the "evidence gathering" stage of the
generic triage runbook in Part 6.3 — this playbook exists to make that stage
faster, not to replace the "confirm or deny" judgment that comes after it.

**Playbook 2: disable-compromised-user — Teams approval gate, and why here specifically**<!--h3-->

**What it does.** Triggered manually by an analyst (or by a high-confidence
automated detection, depending on deployment posture) once a user account is
believed compromised, this playbook would: revoke all active sessions for
the user via the Microsoft Graph API's session-revocation endpoint
(invalidating refresh tokens so existing sign-ins are forced to
re-authenticate), and disable the account (`accountEnabled: false` via
Graph). Critically, **before either action executes**, the playbook posts an
approval card into a Microsoft Teams channel and blocks until a designated
approver responds.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/07-soar-automation-principles-14.png)

**Why an approval gate here specifically.** This is the playbook that sits
squarely in the "irreversible-ish, affects a real user's ability to work"
category. Disabling an account and revoking sessions is technically
reversible — you can re-enable the account and the user can sign back in —
but the *impact* is immediate and real: the person cannot work, cannot
access email, cannot access anything gated by that identity, from the moment
this executes. If the automation trigger is wrong (a false positive on
compromise, or the wrong user identified), the damage isn't undone by
flipping the flag back — the person already lost working time, and if it's
an executive or someone in a time-sensitive role, that cost is not trivial.
That asymmetry — fast to trigger, slow and disruptive to be wrong about — is
exactly the shape of risk that argues for a human approval gate rather than
full automation, even though the *individual actions* (revoke session,
disable account) are simple, well-understood Graph API calls that could
technically run unattended. The gate is not there because the automation
is hard to build; it's there because the cost of an automated false
positive here is categorically higher than in Playbook 1.

**Playbook 3: isolate-infected-device — selective isolation, and why un-isolation is manual-only**<!--h3-->

**What it does.** Triggered by a Defender for Endpoint detection, this
playbook would isolate a device suspected of infection using Defender for
Endpoint's **selective isolation** capability rather than full isolation.
Selective isolation cuts the device off from general network communication
while preserving specific allowed traffic — notably, continued communication
with the Defender for Endpoint management infrastructure itself, so the
device stays manageable and telemetry keeps flowing during containment. Full
isolation, by contrast, cuts everything, including the security tooling's
own management channel, which can leave a device isolated but unmanageable —
unable to receive the un-isolate command remotely, unable to keep reporting
telemetry that would help confirm the infection is actually contained.

![Diagram](/Users/dk/securitylab/knowledge-doc/diagrams/07-soar-automation-principles-15.png)

**Why selective is the safer automated default.** Selective isolation is a
narrower, more conservative action than full isolation — it removes the
device's ability to do damage (spread laterally, exfiltrate data, communicate
with C2) while deliberately keeping the one channel that matters for staying
in control of the device open. That makes it a better default for
*automated, unattended* triggering specifically: if the detection turns out
to be a false positive, the device is still reachable and manageable, and
the disruption to the user is contained-but-recoverable in a way that a
device gone completely dark over the network is not. This is the same
reversibility logic as 7.1 — selective isolation is the more reversible of
the two options for the same containment goal, so it's the one that gets to
run without a human in the loop first, whereas full isolation (or the
un-isolation step below) is not.

**Why un-isolation is kept strictly manual, always.** Isolating a possibly-
infected device automatically errs safe: worst case, a clean device gets
briefly inconvenienced. Un-isolating a device automatically errs unsafe: the
entire reason to isolate a device in the first place is that it might be
compromised, and reconnecting it to the network without a human confirming
remediation actually happened would just hand a possibly-still-compromised
device its network access back on the automation's schedule rather than on
verified evidence. There is no volume problem un-isolation-automation would
solve that's worth that risk — un-isolation happens far less often than
isolation, so the "high-volume" justification for automating simply isn't
present, and the downside if wrong is severe. This is the cleanest example
in the whole portfolio of the 7.1 principle applied asymmetrically to two
sides of what looks like "the same" action: isolate and un-isolate are
logical opposites, but they are not symmetric in risk, so they are not
treated symmetrically in the design.

**What "designed but not deployed" honestly means**<!--h3-->

None of these three playbooks have executed a single real action, because
there is no real Sentinel tenant in this lab to deploy them into — only a
free-trial-tenant possibility that has not been pursued. That is stated
plainly, not softened. As a portfolio artifact, what "designed but not
deployed" honestly represents is **design thinking made concrete and
reviewable** — the trigger conditions, the exact API calls, the permission
scopes, the approval-gate placement and reasoning, all specified precisely
enough that a reviewer (or a future version of this lab with a real tenant)
could deploy them largely as-is. What it does **not** represent is
operational proof: nobody can point to a log showing this playbook actually
revoked a session or isolated a device, because it never has. Claiming
otherwise — implying these ran when they didn't — would be exactly the kind
of dishonesty this whole document is built to avoid. The honest framing is
"here is evidence I can design SOAR automation correctly, including judgment
about where human gates belong," not "here is evidence this automation
works in production," and those are genuinely different, both-valuable
claims that should never be blurred together.

**7.3 A general SOAR playbook design checklist**<!--h2-->

Use this checklist structure when designing a new playbook, whether or not
it will ever be deployed. It's the same structure underlying all three
playbooks above, made explicit and reusable.

**Trigger conditions**<!--h3-->

- What exact event/alert fires this playbook? Be specific — a vague trigger
  ("suspicious activity") either never fires or fires constantly; a precise
  one (a specific Sentinel analytics rule ID, a specific Defender
  detection category) is testable and tunable.
- What's the expected trigger volume? This matters directly for the
  automate-vs-gate decision in 7.1 — a trigger that fires twice a year
  doesn't need the same automation investment as one that fires fifty
  times a day.

**Required permissions/scopes (principle of least privilege for the automation's own identity)**<!--h3-->

- What is the *minimum* Graph API / Defender API / cloud provider scope this
  playbook's service identity needs to do its job — not what's convenient,
  what's minimum? `auto-enrich-signin-alert`'s identity needs read-only
  scopes (`AuditLog.Read.All`, `User.Read.All`) and nothing else — it should
  be structurally incapable of writing to anything, so that even a bug in
  the playbook's logic can't cause a write it was never supposed to make.
  `disable-compromised-user`'s identity needs the specific write scopes for
  session revocation and account disable (`User.RevokeSessions.All`,
  `User.ReadWrite.All` or a narrower equivalent) — and nothing broader like
  full Directory admin, even though a broader grant might be more
  "convenient" to set up once.
- A playbook's own service identity is a real attack surface — if that
  identity's credentials leak, the blast radius of that leak is bounded by
  exactly the scopes granted. Scope minimally for that reason alone, not
  just for tidiness.

**Approval gates**<!--h3-->

- Does this action's reversibility and blast-radius combination (per 7.1)
  cross the line where a human needs to explicitly approve before
  execution, not just be notified after? If yes, specify exactly where in
  the flow the gate sits, who the valid approvers are, and what happens on
  timeout or rejection (never leave "approver doesn't respond" undefined —
  `disable-compromised-user`'s design treats a timeout the same as a
  rejection: no action taken, escalate manually).

**Rollback path**<!--h3-->

- If this action executes and turns out to be wrong, what's the exact
  reverse action, and is it itself automated or manual? State this even
  for actions that feel obviously reversible — "re-enable the account" is
  a real step with its own required permissions and its own decision about
  whether it needs a gate (per the isolate/un-isolate asymmetry in 7.2, the
  reverse of a gated or ungated action is not automatically the same
  category as the forward action).

**What stays manual, and why**<!--h3-->

- Explicitly list what this playbook does *not* automate, and state the
  reason — not as an afterthought, but as a first-class design decision.
  For `isolate-infected-device`, un-isolation staying manual is not a gap
  to fill later, it's the correct permanent design given the risk
  asymmetry. Writing this down prevents a later well-meaning contributor
  from "finishing" the automation by removing a safeguard that was placed
  deliberately.
