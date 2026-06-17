# Parallax

**Is this domain blocked on my network, or is it just down?**

Parallax answers that question from *your* vantage point. It looks at a domain
from several positions at once — your ISP's resolver, an encrypted DoH channel,
and a clean-network control server — and treats the **difference** between those
views as the censorship signal. The name is the mechanism: parallax is the
apparent shift of an object seen from two positions.

This repository is the **Tier A feasibility spike** — the smallest thing that
proves the core idea works in a plain browser with zero install. It is
deliberately not the full product.

## The one claim this spike proves

From an ordinary browser, with nothing installed, we can tell whether a domain
is blocked *on the user's own network* — distinguishing real interference from a
domain that is simply down — by combining:

1. **Ground truth** — a client-side DoH lookup over an encrypted channel.
2. **Your vantage** — a reachability probe that uses your OS/ISP resolver.
3. **A control** — a clean-network check of whether the domain is actually up.

The success test is one on-camera contrast: on a network that blocks a domain,
Parallax reports `BLOCKED_FOR_YOU` while a server-side tool reports `ACCESSIBLE`
for the same domain — because Parallax measures from *you*, not from the server.

## Run it

Control endpoint (run on a clean network; zero dependencies):

```
node control/server.js        # listens on :8787
```

Web client (any static server; point CONTROL_BASE in index.html at your control):

```
cd web && python3 -m http.server 5500
# open http://localhost:5500
```

Tests:

```
node test/verdict.test.js
```

## Layout

```
control/server.js   clean-network reference: GET /control?domain= -> {up, addresses, tcp, tls}
web/verdict.js      pure verdict engine (browser + node), no I/O
web/probe.js        DoH + ISP-vantage reachability + orchestration
web/index.html      minimal UI showing the verdict and the three raw signals
test/verdict.test.js unit tests for every verdict branch
```

## Verdicts

`ACCESSIBLE` · `BLOCKED_FOR_YOU` · `DOMAIN_DOWN` · `DOH_BLOCKED` · `INCONCLUSIVE`

The engine biases toward `INCONCLUSIVE` over a confident wrong answer. For users
who may face real risk, an honest "not sure" beats a false accusation.

## Deliberately out of scope here

Precise interference classification (poisoning vs. hijacking) → Tier B, a
Firefox extension using `browser.dns.resolve()`. Multi-ISP field study → Tier C.
Dynamic CDN range refresh, DoH endpoint rotation, TLS/SNI inspection → later
hardening. If a task isn't needed to produce the contrast above, it isn't in the spike.

## License

Intended GPL-3.0, to match the 1.0 toolkit and OTF's open-source priority. Drop
the full GPL-3.0 text into `LICENSE` before publishing.
