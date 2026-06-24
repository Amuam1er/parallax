# Parallax — Data & Privacy Policy

Parallax is built for people who may be measuring from hostile networks. Data
minimization is therefore a design constraint, not an afterthought. This policy
describes exactly what is and isn't collected, and aligns with the OONI Data Policy
principles (collect as little as possible; never collect what could identify a user).

## What Parallax measures

A measurement records **only**:

- the **domain** being tested (user-supplied input);
- the **outcomes** of the four vantage signals (DoH result, sampled reachability
  outcomes, calibration outcomes, control result);
- the derived **verdict** and timing.

## What Parallax deliberately does NOT collect

- **No user IP address.** `probe_ip` is fixed to `127.0.0.1` (OONI's redaction
  convention). The user's real IP is never read or stored.
- **No geolocation.** `probe_asn` and `probe_cc` are `null`. Tier A performs **no**
  client geolocation — the annotation `client_geolocation: "disabled_by_design"`
  records this as an intentional choice. (Country/ASN context, if ever added, must be
  opt-in and is tracked as a roadmap decision, not a default.)
- **No resolver identity.** The OS/ISP resolver IP is opaque to the browser and is not
  inferred.
- **No cookies, no local storage, no tracking, no analytics, no fingerprinting.**

## The control endpoint

The clean-network control server (`control/server.js`):

- receives **only a bare domain string** over `GET /control?domain=…`;
- **logs nothing tied to a user** — no request IPs, no query logging;
- validates input against a strict hostname regex (rejecting IP literals, schemes, and
  paths) to prevent it being used as an SSRF probe;
- returns only the global reachability facts for the domain.

Operators self-hosting a control endpoint should keep this no-logging posture and
should **not** place it behind infrastructure that logs client IPs against queries.

## Sharing / publication

Measurement records are produced **client-side** and are **not auto-submitted**
anywhere. The user explicitly chooses to download/share a record. Because records carry
no user identifiers, they are safe to publish as open data alongside OONI measurements.
A future opt-in submission pipeline must preserve every invariant above.

## Threat model (summary)

- **Adversary:** the user's own network (ISP / national filter) performing DNS or
  transport-layer interference, and capable of observing the user's traffic.
- **Protected:** the user's identity and location are never embedded in a measurement.
- **Residual exposure:** running any probe generates traffic to the tested domain, the
  DoH endpoints, and the control server, which an on-path adversary can observe — this
  is inherent to active measurement and is true of OONI Probe as well. Parallax does not
  claim to hide *that a measurement happened*; it ensures the *record* identifies no one.
