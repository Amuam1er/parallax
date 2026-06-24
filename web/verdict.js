// Parallax — verdict engine.
// Pure function, no I/O. Runs in the browser AND in Node tests.
//
// Inputs are the vantage signals; output is a verdict plus OONI-aligned summary
// fields (`blocking`, `accessible`) so the result drops cleanly into a measurement
// record. The engine deliberately biases toward INCONCLUSIVE over a confident wrong
// answer: for users who may face real risk, an honest "not sure" beats a false
// accusation. See docs/METHODOLOGY.md for the reasoning behind each branch.

// What Parallax can and cannot observe from a plain browser (this bounds every
// claim below):
//   - It CAN observe whether a socket to the target opened from the user's path.
//   - It CANNOT see the IP the user's OS resolver returned (opaque to JS), so it
//     CANNOT, in Tier A, distinguish DNS poisoning from IP/TCP blocking. That
//     layer-level attribution is the explicit job of Tier B (browser.dns.resolve).
// We therefore never assert a blocking *layer* we did not measure.

function computeVerdict({ doh, reach, control, calibration }) {
  const notes = [];

  // (0) Connectivity sanity check. `calibration` probes rarely-blocked anchor
  // domains; if NONE are reachable the user's whole path is down/filtered and we
  // must NOT blame the target domain.
  if (!calibration || calibration.connection_ok !== true) {
    notes.push("calibration_anchors_unreachable");
    return build("INCONCLUSIVE", "low", null, null, null,
      "Your connection itself looks down or filtered — can't isolate this domain.",
      { doh, reach, control }, notes);
  }

  // (1) The control endpoint is our clean-network ground truth. Without it we
  // cannot separate "down for everyone" from "blocked for you", so we abstain.
  const haveControl = control && control.up !== null && control.up !== undefined;
  if (!haveControl) {
    notes.push("control_unavailable");
    return build("INCONCLUSIVE", "low", null, null, null,
      "No clean-network reference available — can't tell 'down' from 'blocked'.",
      { doh, reach, control }, notes);
  }

  // (2) Genuinely unreachable from a clean network → not censorship.
  if (control.up === false) {
    return build("DOMAIN_DOWN", "high", "false", false, null,
      "This domain appears down or nonexistent globally — not censorship.",
      { doh, reach, control }, notes);
  }

  const reachable = reach && reach.outcome === "connected";

  // (3) Up on a clean network AND reachable from here → accessible. This wins over
  // a DoH failure: if the user can reach the site, encrypted-DNS trouble did not
  // block access (we note it as a secondary signal instead of crying wolf).
  if (control.up === true && reachable) {
    if (doh && doh.ok === false) notes.push("doh_failed_but_site_reachable");
    return build("ACCESSIBLE", "high", false, true, null,
      "Reachable from your network. No interference detected.",
      { doh, reach, control }, notes);
  }

  // (4) Encrypted ground-truth lookups all failed → DoH itself may be blocked.
  if (doh && doh.ok === false) {
    notes.push("doh_all_endpoints_failed");
    return build("DOH_BLOCKED", "medium", "dns", null, "dns-layer (probable)",
      "Encrypted DNS lookups are failing on your network — DoH itself may be blocked.",
      { doh, reach, control }, notes);
  }

  // (5) THE HEADLINE CASE: up elsewhere, not reachable here → your network is
  // interfering. We cannot isolate the layer in-browser, so `blocking` is reported
  // as transport-level ("tcp_ip") with an explicit caveat note rather than a
  // confident DNS-vs-IP claim. Confidence stays "medium" for the same reason.
  if (control.up === true && !reachable) {
    const hint = reach && reach.outcome === "timeout"
      ? "timeout-filtering (probable)"
      : "connection-reset/blocking (probable)";
    notes.push("layer_unconfirmed_in_browser"); // Tier B (DNS resolve) confirms layer
    if (control.tls === true) notes.push("control_tls_ok"); // up to and incl. TLS elsewhere
    return build("BLOCKED_FOR_YOU", "medium", "tcp_ip", false, hint,
      "Up elsewhere but unreachable from your network — your network is interfering. " +
      "Try enabling DNS over HTTPS in your browser, or switch your resolver to 1.1.1.1.",
      { doh, reach, control }, notes);
  }

  notes.push("signals_did_not_converge");
  return build("INCONCLUSIVE", "low", null, null, null,
    "Signals are inconclusive — try again.", { doh, reach, control }, notes);
}

// Map an internal verdict object into the shape callers/measurements consume.
// `blocking` / `accessible` mirror OONI Web Connectivity semantics:
//   blocking:   false | "dns" | "tcp_ip" | "http-failure" | null
//   accessible: true  | false | null
function build(verdict, confidence, blocking, accessible, method_hint, recommendation, s, notes) {
  return {
    verdict,
    confidence,
    blocking,
    accessible,
    method_hint: method_hint || null,
    recommendation,
    notes: notes || [],
    signals: {
      doh: s.doh ? (s.doh.ok ? "ok" : "failed") : "n/a",
      client_reach: s.reach ? s.reach.outcome : "n/a",
      control: s.control && s.control.up !== null && s.control.up !== undefined
        ? (s.control.up ? "up" : "down") : "n/a",
    },
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { computeVerdict };
}
if (typeof window !== "undefined") {
  window.Parallax = Object.assign(window.Parallax || {}, { computeVerdict });
}
