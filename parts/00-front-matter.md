# Security Operations Lab — Complete Reference

## From First Setup to Advanced Identity Security Practice

### How to use this document

This is a single, complete reference for a real, working, self-hosted security operations lab — built on one Mac, using a mix of free open-source tools and free tiers of commercial products, deliberately kept close to zero recurring cost. It is written to take a reader from "I have never installed any of this" through to "I understand the principle behind every tool, why it was chosen over the alternative, and what I would do differently in a real production environment."

It is organized in the order you would actually build the lab, followed by the identity security and detection engineering theory that gives the practical work its meaning, followed by incident response, automation, and cloud security material, followed by fully reproducible practical labs, a real troubleshooting log from actually building this, a glossary, and a paid-vs-free summary table.

Read it front to back if you are new to this field. Use it as a reference if you already know the concepts and need the exact commands, the exact config, or the exact reasoning behind a specific decision in this lab.

### Who this is for

Any security persona: a SOC analyst learning to triage; a detection engineer learning to write and test detection logic; an identity/IAM engineer learning how identity governance actually breaks in practice; a cloud security engineer learning infrastructure-as-code security patterns; an incident responder learning a real triage methodology; a student or career-changer trying to build genuine, defensible hands-on experience instead of certificate-only knowledge.

### The philosophy behind this document

No shortcuts. Every tool section explains the principle behind the tool, not just the commands to run it — the goal is that a reader who finishes a section understands *why* the tool is built the way it is, not just *how* to operate it. Every claim of something working is backed by what was actually verified, not assumed. Every gap, every unfinished piece, every tool that was tried and abandoned, is documented honestly rather than smoothed over — a lab that only shows finished, successful work teaches less than one that shows the real process, including the parts that are still open questions.

Paid products are marked clearly wherever they appear, and the free-tier limits that actually matter are spelled out — the aim throughout was to build something close to zero-cost, and where a paid product was still worth discussing (because it's what real employers actually run), that's noted honestly rather than pretended around.

### A note on how this lab differs from a training course lab

Training courses give you a lab environment that's already built for you, usually pre-wired, usually disposable, usually forgotten the moment the course ends. This lab is the opposite: built from scratch, kept running, extended over time, with real bugs hit and real fixes applied — the actual bugs and fixes are documented in Part 10 specifically because that debugging process is itself the most transferable skill in this whole document. Anyone can follow a script that works. Learning to diagnose why it doesn't, the first time, is the actual job.

### Document structure at a glance

- **Part 1** — Lab architecture overview, with a master diagram of every component and how it connects (or, honestly, doesn't yet connect) to every other component.
- **Part 2** — Environment setup end-to-end: getting the host machine ready.
- **Part 3** — Tool-by-tool deep dives: what each tool is, the principle behind it, paid vs free, when to use it and when not to, install/config, and real troubleshooting.
- **Part 4** — Identity security deep dive: the theory that gives the identity-focused parts of this lab their meaning.
- **Part 5** — Detection engineering principles: Sigma, KQL, MITRE ATT&CK, false-positive discipline, and the real platform-translation problem this lab hit.
- **Part 6** — Incident response and triage workflows, walked through using this lab's real case studies.
- **Part 7** — SOAR and automation principles, walked through using this lab's real playbook designs.
- **Part 8** — Cloud security and infrastructure-as-code, walked through using this lab's real Terraform exercises.
- **Part 9** — End-to-end practical labs: fully reproducible, numbered, with exact commands and exact expected results.
- **Part 10** — A real troubleshooting log: the actual bugs hit while building this lab, and how they were diagnosed and fixed.
- **Part 11** — Glossary.
- **Part 12** — Appendix: a complete paid-vs-free summary table across every tool and service used.
