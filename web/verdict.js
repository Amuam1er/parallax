// Parallax — verdict engine.
// Pure function, no I/O. Runs in the browser AND in Node tests.
// Inputs are the three vantage signals; output is a plain-language verdict.

function computeVerdict({ doh, reach, control, controlSelf }) {
  // controlSelf = reach probe against our own known-good calibration domain.
  // If our own domain isn't reachable, the user's whole connection is down/filtered
  // and we must NOT blame the target domain.
  if (!controlSelf || controlSelf.outcome !== "connected") {
    return build("INCONCLUSIVE", "low", null,
      "Your connection itself looks down or filtered — can't isolate this domain.",
      { doh, reach, control });
  }

  // Domain is genuinely unreachable from a clean network → not censorship.
  if (control && control.up === false) {
    return build("DOMAIN_DOWN", "high", null,
      "This domain appears down or nonexistent globally — not censorship.",
      { doh, reach, control });
  }

  // Encrypted ground-truth lookups all failed → DoH itself may be blocked.
  if (doh && doh.ok === false) {
    return build("DOH_BLOCKED", "medium", null,
      "Encrypted DNS lookups are failing on your network — DoH itself may be blocked.",
      { doh, reach, control });
  }

  // Up on a clean network AND reachable from here → accessible.
  if (control && control.up === true && reach && reach.outcome === "connected") {
    return build("ACCESSIBLE", "high", null,
      "Reachable from your network. No interference detected.",
      { doh, reach, control });
  }

  // THE HEADLINE CASE: up elsewhere, not reachable here → your network is interfering.
  if (control && control.up === true && reach && reach.outcome !== "connected") {
    const hint = reach.outcome === "timeout"
      ? "timeout-filtering (probable)"
      : "blocking (probable)";
    return build("BLOCKED_FOR_YOU", "medium", hint,
      "Up elsewhere but unreachable from your network — your network is interfering. " +
      "Try enabling DNS over HTTPS in your browser, or switch your resolver to 1.1.1.1.",
      { doh, reach, control });
  }

  return build("INCONCLUSIVE", "low", null,
    "Signals are inconclusive — try again.", { doh, reach, control });
}

function build(verdict, confidence, method_hint, recommendation, s) {
  return {
    verdict, confidence, method_hint, recommendation,
    signals: {
      doh: s.doh ? (s.doh.ok ? "ok" : "failed") : "n/a",
      client_reach: s.reach ? s.reach.outcome : "n/a",
      control: s.control ? (s.control.up ? "up" : "down") : "n/a",
    },
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { computeVerdict };
}
if (typeof window !== "undefined") {
  window.Parallax = Object.assign(window.Parallax || {}, { computeVerdict });
}
