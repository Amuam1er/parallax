# Parallax — Roadmap

Parallax is structured in tiers, each with a sharper measurement capability and a
clear, fundable deliverable. Tier A is built and proven; B and C are the proposed
funded work.

## Tier A — In-browser vantage comparison ✅ (this repository)

**Goal:** prove, with zero install, that a domain can be shown blocked *for the user's
network* while a clean-network control shows it up.

Delivered:
- Pure, reproducible verdict + measurement engines (browser + Node).
- Four-signal vantage model with sampling-based false-positive control.
- OONI-aligned open measurement records (`blocking` / `accessible` vocabulary).
- Zero-dependency self-hostable control endpoint (DNS → TCP → TLS, IPv4/IPv6).
- Hermetic test suite (`node --test`) + CI; privacy-by-design data policy.

**Known boundary:** the browser cannot read the OS resolver's answer, so Tier A cannot
attribute the interference *layer* (DNS vs IP/TCP). It reports transport-level blocking
with an explicit `layer_unconfirmed_in_browser` caveat. Removing this boundary is the
purpose of Tier B.

## Tier B — Layer attribution via a browser extension 🔜 (proposed)

**Goal:** confirm *how* a domain is blocked, not just *that* it is.

- Firefox extension using `browser.dns.resolve()` to read the resolver's actual answer.
- Compare the local answer against DoH ground truth and the control to classify:
  **DNS poisoning** (wrong/withheld answer) vs **IP/TCP blocking** (correct answer,
  blocked path) vs **TLS/SNI interference**.
- Promotes `BLOCKED_FOR_YOU` from `tcp_ip (probable)` to a layer-confirmed verdict with
  higher confidence, while keeping the same OONI-aligned record format.

**Fundable milestones:** extension scaffold + signed release; resolver-comparison
engine + tests; layer-classification methodology writeup; field validation on ≥1 known
filtering network.

## Tier C — Multi-ISP / multi-region field study 🔭 (proposed)

**Goal:** turn point measurements into evidence.

- Coordinate volunteer measurements across ISPs/regions.
- Aggregate Parallax records (carrying no user identifiers) into comparable datasets;
  align/co-publish with the OONI data ecosystem.
- Methodology for confidence under sparse/noisy field data; reproducible analysis.

**Fundable milestones:** opt-in submission pipeline preserving all privacy invariants;
aggregation + dashboards; a published field report on detected interference.

## Hardening backlog (cross-cutting)

- Dynamic CDN/IP-range awareness and DoH endpoint rotation/health.
- TLS/SNI inspection at the control for finer interference signals.
- Configurable, vetted calibration anchors per region.
- Optional, **opt-in** country/ASN context (never default; see [PRIVACY.md](PRIVACY.md)).
