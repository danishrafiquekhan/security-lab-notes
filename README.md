**security-lab-notes**

The complete reference for how everything else in this portfolio actually works — every tool, why it was chosen, what's paid vs free, and the real bugs hit building it. If you only read one thing before the individual repos, read this.

Start here if you want the full picture, or jump straight to whichever part is relevant. Each repo elsewhere in this portfolio links back to the specific part(s) that explain the principles behind what's in it.

**Download the whole thing as one document**
- [Word (.docx)](download/security-lab-knowledge-doc.docx)
- [PDF](download/security-lab-knowledge-doc.pdf)

Both are ~95 pages / ~46,000 words, generated from the same source as the parts below, with all 18 diagrams embedded and a full table of contents.

**Or read it part by part**

- [Part 0 — Front matter: how to use this, who it's for](parts/00-front-matter.md)
- [Part 1 — Lab architecture overview](parts/01-architecture-overview.md) — the master diagram, and an honest account of what's actually connected vs not yet
- [Part 2 — Environment setup end-to-end](parts/02-environment-setup.md)
- [Part 3.1–3.3 — Wazuh, TheHive + Cortex, LocalStack](parts/03a-tools-wazuh-thehive-localstack.md)
- [Part 3.4–3.6 — Suricata, MySQL, Cloudflare Pages + Workers](parts/03b-tools-suricata-mysql-cloudflare.md)
- [Part 3.7–3.9 — QEMU/QuartzVM/Windows VM, Terraform + Azure, Sigma + KQL](parts/03c-tools-qemu-terraform-detection-as-code.md)
- [Part 4 — Identity security deep dive](parts/04-identity-security-deep-dive.md) — JML lifecycle, GUID triage methodology, PIM/RBAC, federation, BEC as an identity threat
- [Part 5 — Detection engineering principles](parts/05-detection-engineering-principles.md) — Sigma anatomy, KQL, ATT&CK mapping, and the real Sentinel-vs-Wazuh platform translation problem
- [Part 6 — Incident response & triage workflows](parts/06-incident-response-triage.md)
- [Part 7 — SOAR & automation principles](parts/07-soar-automation-principles.md)
- [Part 8 — Cloud security & infrastructure as code](parts/08-cloud-security-iac.md)
- [Part 9 — End-to-end practical labs](parts/09-practical-labs.md) — numbered, reproducible, with real commands
- [Part 10 — Real troubleshooting log](parts/10-troubleshooting-log.md) — the actual bugs hit building this, not a hypothetical FAQ
- [Part 11 — Glossary](parts/11-glossary.md)
- [Part 12 — Appendix: paid vs free summary table](parts/12-appendix-paid-vs-free.md)

**Why this exists**

Every other repo in this portfolio shows one piece — a Sigma rule, a Terraform exercise, a playbook design. None of them on their own explain why the lab is built the way it is, what's genuinely free vs what has a real cost ceiling, or what actually happened when something broke. This is that missing piece: the reasoning, not just the artifacts.

It's written the same way as everything else here — no shortcuts, no pretending something works when it hasn't been verified, gaps stated plainly instead of smoothed over. Part 1 in particular is worth reading first regardless of which tool you care about, since it lays out exactly what's real, live, and connected right now versus what's built but idle versus what's still just a plan.

**An earlier, smaller version of some of this exists in `detection-engineering/docs/`** (`Security-Lab-Guide.pdf`, `Test-Case-Catalog.pdf`) — personal running notes started before this document, predating the live Cloudflare/MySQL lab and the expanded terraform exercises. This repo supersedes it as the complete, current reference; the older notes stay where they are as a record of how the thinking evolved.
