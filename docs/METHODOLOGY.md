# Parallax — Methodology

This document specifies what Parallax measures, how it reaches a verdict, the limits
of those claims, the open-data format it emits, and how it relates to OONI Probe's
Web Connectivity test. It is written to be auditable: every verdict is reproducible
from the raw signals recorded in each measurement.

## 1. The question

> Is this domain blocked **on my own network**, or is it simply down for everyone?

Distinguishing *network interference* from *a site that is genuinely offline* is the
hard part of censorship measurement, and the part most prone to false positives.
Parallax answers it by **comparing vantage points** and treating the *difference*
between them as the signal — the property the name refers to.

## 2. Vantage points (the raw signals)

Each check gathers four independent signals, in parallel:

| Signal | Source | What it establishes |
|---|---|---|
| `doh` | Client-side DNS-over-HTTPS (Cloudflare → Google → Quad9) | Encrypted ground-truth resolution, bypassing the local resolver. All endpoints failing is itself evidence of DNS-layer interference. |
| `client_reach` | `no-cors` fetch to `https://<domain>/favicon.ico`, **sampled N=3 times** | Whether a socket opens from the user's *real* path (their OS/ISP resolver + routing). |
| `calibration` | Same probe against rarely-blocked anchors (`example.com`, `cloudflare.com`) | Whether the user's connection works *at all* — the guard against blaming the target when the whole link is down. |
| `control` | Clean-network reference server: DNS (A/AAAA) → TCP:443 → TLS:443 | What an *uncensored* network sees: is the domain actually up globally? |

### Sampling rule (false-positive control)
`client_reach` runs three times. A **single** success proves reachability (you cannot
both block and connect), so the aggregate is `connected` if *any* sample connects.
Only when **all** samples fail is the domain treated as unreachable, with the dominant
failure mode (`timeout` vs `error`) carried forward. This suppresses transient-network
flapping, the most common cause of false "blocked" readings.

### Calibration rule
The connection is considered healthy if **any** anchor is reachable. Using two
independent anchors means a check still calibrates correctly even if one anchor is
itself filtered.

## 3. Verdict logic

Evaluated in order; the engine **biases toward `INCONCLUSIVE`** rather than risk a
confident wrong answer (see §5).

1. **No anchor reachable** → `INCONCLUSIVE` — the user's connection itself is down/filtered.
2. **Control unavailable** → `INCONCLUSIVE` — without clean-network ground truth we cannot separate "down" from "blocked".
3. **Control says down** → `DOMAIN_DOWN` — not censorship (`blocking=false`).
4. **Control up AND reachable here** → `ACCESSIBLE` (`blocking=false`, `accessible=true`). Wins over a DoH failure, which is recorded as a secondary note rather than raised as an alarm.
5. **DoH all-endpoints-failed** (and not reachable) → `DOH_BLOCKED` (`blocking=dns`).
6. **Control up AND not reachable here** → `BLOCKED_FOR_YOU` — the headline case (`blocking=tcp_ip`, `accessible=false`).
7. Otherwise → `INCONCLUSIVE`.

`blocking` and `accessible` use **OONI Web Connectivity vocabulary**
(`false | "dns" | "tcp_ip" | "http-failure" | null` and `true | false | null`) so the
output is directly comparable to OONI data.

## 4. What Parallax can and cannot observe (honest scope)

From an **unmodified browser** Parallax:

- **CAN** observe whether a socket to the target opened from the user's path.
- **CAN** obtain encrypted ground-truth DNS via DoH.
- **CANNOT** read the IP address the user's OS resolver returned — it is opaque to
  JavaScript. `BLOCKED_FOR_YOU` uses `blocking="tcp_ip"` because OONI's vocabulary has
  no "layer unknown" value and our probe IS a socket/transport-layer test (it tries to
  open a TCP connection). DNS poisoning that returns an *unreachable* IP produces the
  same socket-failure observation, so the layer is not confirmed. The note
  `layer_unconfirmed_in_browser` documents this explicitly; confidence stays `medium`.
  `tcp_ip` is the closest-fit OONI vocabulary term, not a certain layer claim.

- **CANNOT detect DNS hijacking to a block page.** If an ISP redirects a domain's DNS
  to its own block-page server, a socket opens to that server, `client_reach` reads
  `connected`, and the verdict is `ACCESSIBLE` — even though the user is being served a
  censorship notice. Connectivity-only probing cannot catch this from the browser because
  JS cannot read the OS resolver's answer and compare it to ground truth.

Both limitations share the same fix: `browser.dns.resolve()` in **Tier B**
(see [ROADMAP.md](ROADMAP.md)) exposes the resolver's actual answer. Comparing it
against DoH ground truth catches DNS poisoning whether the block-page socket opens or
not, and confirms the interference layer for `BLOCKED_FOR_YOU`. These two cases are the
central technical justification for the Tier B extension.

## 5. Why bias toward INCONCLUSIVE

Parallax is for people who may face real risk. A false "your network is censoring this"
can provoke unwarranted, sometimes dangerous, action. An honest "not sure" is the safer
failure mode. Every branch that lacks corroborating ground truth abstains rather than
guesses.

## 6. Positioning vs. OONI Probe Web Connectivity

Parallax **complements, does not duplicate,** OONI Probe.

| | OONI Probe (Web Connectivity) | Parallax (Tier A) |
|---|---|---|
| Install | Native app / CLI | **None** — any browser, zero install |
| Vantage | The probe host's resolver & routing | The end-user's *own* browser path |
| Control | OONI's test-helper backend | A self-hostable clean-network control |
| Layer attribution | DNS / TCP-IP / TLS / HTTP-diff | Transport-level only in Tier A (by design); DNS-layer in Tier B |
| Reach | Requires the user to install/run a tool | Reaches users who can't or won't install software |
| Data | OONI open data pipeline | **OONI-aligned** records, exportable per check |

The wedge: **a zero-install, in-browser first-look** that a user already at risk can
run from a link, producing OONI-compatible evidence. It lowers the barrier to a first
measurement and can act as a funnel toward full OONI Probe runs, not a replacement for
them. Parallax intentionally reuses OONI's data vocabulary so its output can sit
alongside OONI measurements rather than in a silo.

## 7. Measurement format

Each check emits one JSON record. The **envelope** mirrors the OONI base data format
(df-000-base); nettest-specific evidence lives under `test_keys`, modeled on Web
Connectivity. Privacy fields are covered in [PRIVACY.md](PRIVACY.md).

```jsonc
{
  "annotations": {
    "platform": "browser",
    "vantage_model": "client_vs_clean_control",
    "client_geolocation": "disabled_by_design",
    "engine": "parallax-tier-a",
    "control_base": "https://control.example"
  },
  "data_format_version": "0.2.0",
  "input": "blocked.example",
  "measurement_start_time": "2026-06-24 12:00:00",  // UTC
  "probe_asn": null,            // not collected in Tier A (privacy)
  "probe_cc": null,             // not collected in Tier A (privacy)
  "probe_ip": "127.0.0.1",      // redacted by convention; never the user's IP
  "report_id": "…",
  "software_name": "parallax",
  "software_version": "0.2.0",
  "test_name": "parallax_vantage",
  "test_runtime": 4.2,
  "test_start_time": "2026-06-24 12:00:00",
  "test_version": "0.2.0",
  "test_keys": {
    "doh":          { "ok": true, "endpoint": "cloudflare", "rcode": 0, "addresses": ["…"], "failure": null },
    "client_reach": { "outcome": "timeout", "samples": [ … ], "connected": 0, "timeout": 3, "error": 0 },
    "calibration":  { "connection_ok": true, "anchors": [ { "domain": "example.com", "outcome": "connected" } ] },
    "control":      { "up": true, "addresses": ["…"], "tcp": true, "tls": true, "failure": null },

    "blocking": "tcp_ip",       // OONI vocabulary
    "accessible": false,        // OONI vocabulary

    "parallax_verdict": "BLOCKED_FOR_YOU",
    "confidence": "medium",
    "method_hint": "timeout-filtering (probable)",
    "recommendation": "…",
    "notes": ["layer_unconfirmed_in_browser", "control_tls_ok"]
  }
}
```

Because every raw signal is recorded, any reviewer can independently re-run
`computeVerdict()` over `test_keys` and reproduce the verdict.

## 8. Reproducibility

- Pure verdict and measurement engines (`web/verdict.js`, `web/measurement.js`) run
  identically in the browser and in Node.
- `node --test` exercises every verdict branch, the measurement envelope, the privacy
  invariants, and input validation — with **zero dependencies** and **no network**, so
  CI is hermetic and deterministic.
