# Parallax

**Is this domain blocked on my network, or is it just down?**

Parallax answers that question from *your* vantage point. It looks at a domain from
several positions at once — encrypted DoH ground truth, your OS/ISP resolver path, and
a clean-network control server — and treats the **difference** between those views as
the censorship signal. The name is the mechanism: parallax is the apparent shift of an
object seen from two positions.

Every check produces an **OONI-aligned, privacy-clean open measurement record** you can
download and share. No install, no account, no user data.

[![ci](https://img.shields.io/badge/tests-node--test-brightgreen)](.github/workflows/ci.yml)

## The one claim this proves

From an ordinary browser, with nothing installed, Parallax distinguishes real network
interference from a domain that is simply down — by combining:

1. **Ground truth** — a client-side DoH lookup over an encrypted channel.
2. **Your vantage** — a sampled reachability probe over your OS/ISP resolver path.
3. **A control** — a clean-network check of whether the domain is actually up.
4. **A calibration** — anchors that confirm your connection works at all.

The on-camera contrast: on a network that blocks a domain, Parallax reports
`BLOCKED_FOR_YOU` while a server-side tool reports `ACCESSIBLE` for the same domain —
because Parallax measures from *you*, not from the server.

## How it relates to OONI Probe

Parallax **complements, not duplicates,** OONI Probe's Web Connectivity test: it is the
**zero-install, in-browser first look** that a user already at risk can run from a link,
emitting OONI-compatible evidence and acting as a funnel toward full OONI Probe runs.
Full comparison and rationale in [docs/METHODOLOGY.md §6](docs/METHODOLOGY.md).

## Run it

```bash
# 1. Control endpoint — run on a clean network (zero dependencies):
npm run start:control            # listens on :8787   (or: node control/server.js)

# 2. Web client — point CONTROL_BASE in web/index.html at your control:
npm run serve:web                # serves web/ on :5500
#    then open http://localhost:5500

# 3. Tests (zero dependencies, no network):
npm test                         # or: node --test
```

## Layout

```
control/server.js        clean-network reference: GET /control?domain= -> {up, addresses, tcp, tls, ...}
web/verdict.js           pure verdict engine (browser + node), no I/O
web/measurement.js       pure OONI-style measurement-record builder (browser + node)
web/probe.js             DoH + sampled ISP-vantage reachability + calibration + orchestration
web/index.html           minimal UI: verdict, OONI summary, raw signals, JSON download
test/*.test.js           node:test suite — verdict branches, envelope, privacy, validation
docs/METHODOLOGY.md      what is measured, verdict logic, scope, OONI positioning, data format
docs/PRIVACY.md          data & privacy policy + threat model
docs/ROADMAP.md          Tier A (done) / Tier B (extension) / Tier C (field study)
.github/workflows/ci.yml CI: tests on Node 18/20/22 + control smoke test
```

## Verdicts

`ACCESSIBLE` · `BLOCKED_FOR_YOU` · `DOMAIN_DOWN` · `DOH_BLOCKED` · `INCONCLUSIVE`

Each verdict also carries OONI Web Connectivity fields — `blocking`
(`false | "dns" | "tcp_ip" | "http-failure" | null`) and `accessible`
(`true | false | null`) — so the output sits alongside OONI data.

The engine **biases toward `INCONCLUSIVE`** over a confident wrong answer. For users who
may face real risk, an honest "not sure" beats a false accusation.

## Honest scope

A plain browser cannot read the IP the user's OS resolver returned, so Tier A **cannot
distinguish DNS poisoning from IP/TCP blocking** — it reports transport-level
interference with an explicit caveat and never claims a layer it didn't measure.
Layer attribution (via `browser.dns.resolve()`) is **Tier B**; a multi-ISP field study
is **Tier C**. See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

GPL-3.0-only. Full text in [LICENSE](LICENSE).
