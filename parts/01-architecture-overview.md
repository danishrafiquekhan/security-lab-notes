# Part 1: Lab Architecture Overview

## What this lab actually is

A single MacBook (Apple Silicon, 16GB RAM) running a mix of self-hosted, containerized open-source security tools alongside a small number of free-tier cloud services, plus a public GitHub portfolio documenting the detection engineering, cloud security, and identity security work built on top of it. Nothing in this lab costs money to run in its current state — that was a deliberate constraint, not an accident, because the goal was to build genuine, defensible hands-on experience without needing an employer's budget or a training course's pre-built environment.

The lab is not one finished system. It is several independently useful pieces, some fully wired together and proven end-to-end with real traffic and real alerts, some built but not yet connected to anything else, and some still open questions. This document is honest about which is which — see the diagram below, and the "what's actually connected vs not yet" section immediately after it.

## Master architecture diagram

![Diagram](../diagrams/01-architecture-overview-1.png)

Solid arrows are real, verified, currently-working data flows. Dashed arrows are either genuinely absent connections (documented gaps) or "this repo documents/tests against this thing, but there's no live data flow" relationships. Reading the dashed arrows honestly is as important as reading the solid ones — a lab diagram that only shows solid arrows is lying by omission.

## What's actually connected vs not yet (read this before anything else)

**Actually working, verified with real traffic, right now:**

- Cloudflare Pages site → Python relay → Wazuh (custom rule, fires on `/login.html` hits)
- MySQL container → Python relay → Wazuh (built-in `mysql_log` rule, fires on failed auth)

**Built and running, but not wired to anything else:**

- TheHive + Cortex — a real case management/SOAR stack, sitting idle, not receiving alerts from Wazuh
- LocalStack — used standalone for AWS IAM testing content, not feeding any SIEM
- Suricata — network IDS running, not forwarding anything to Wazuh yet

**Built, but the next connection is the actual point of building it and hasn't happened yet:**

- The Windows Server VM — installed and reachable at a desktop, but has no Sysmon and no Wazuh agent installed on it yet. Until that happens, it cannot generate the telemetry the atomic-red-team-validation repo's case studies need to become real, run, evidenced work instead of "planned, not run yet" documentation.

**Documented as a plan, never actually built:**

- Auth0 as a second identity provider — a dashboard was set up, no working application credentials were ever configured.
- Any `terraform apply` against the real Azure subscription — every exercise in terraform-labs is syntax-valid and `terraform validate`-clean, and none has ever created a single real Azure resource.

## Why the lab is structured this way

Three deliberate architectural decisions run through everything else in this document, and understanding them up front makes every later section make more sense:

**1. Wazuh, not Sentinel, is the live SIEM — and the Sigma/KQL detection content stays written for Sentinel anyway.** Sentinel costs real money to run meaningfully; Wazuh is free and self-hosted. But Wazuh's architecture (agents + manager, built for host and network telemetry) is a genuinely poor fit for cloud identity provider log schemas like Entra ID sign-in logs — forcing that content onto Wazuh just to claim "it runs somewhere" would be a fake fit, not a real one. So the detection content that's meant to demonstrate Sentinel/KQL skill stays written for Sentinel's schema, syntax-validated but never fired against real Sentinel data (no free real Sentinel tenant exists yet — the Microsoft 365 Developer Program's E5 trial is the actual next step, not something blocked by cost). Meanwhile Wazuh gets its own, separate detection content (the Cloudflare and MySQL rules) written specifically for what Wazuh actually is. Part 5 covers this "platform translation problem" in full depth, because it's one of the most transferable lessons in the whole lab.

**2. Everything that touches real traffic is disclosed as synthetic, and audited for real-data leaks before going public.** The Cloudflare site has an on-page banner disclosing it's a lab fixture. Every IP in every committed sample uses documentation-reserved ranges. A full confidentiality audit (current files and entire git history, across every repo) was run before treating any of this as safe to be public, and it found and fixed one real leak — a specific former employer's tool name, genericized before that repo could go public. This isn't paranoia; it's a real discipline anyone building a public portfolio from real work experience needs, and it's worth doing deliberately rather than trusting that nothing slipped through.

**3. Gaps stay visible instead of getting quietly built around.** TheHive/Cortex not being wired to Wazuh, no terraform ever being applied, Auth0 never getting finished — none of these get hidden by only documenting the parts that work. A lab that shows you the finished, polished 20% teaches you a fraction of what one that shows the real, still-in-progress 100% does.
