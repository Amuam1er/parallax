// Parallax — browser probe.
// Measures from the USER'S vantage: DoH ground truth + ISP-resolver reachability
// (sampled, to suppress transient false positives), asks the control endpoint what a
// clean network sees, computes a verdict, and emits an OONI-style measurement record.

const DOH_ENDPOINTS = [
  { name: "cloudflare", url: (d) => `https://cloudflare-dns.com/dns-query?name=${d}&type=A` },
  { name: "google",     url: (d) => `https://dns.google/resolve?name=${d}&type=A` },
  { name: "quad9",      url: (d) => `https://dns.quad9.net:5053/dns-query?name=${d}&type=A` },
];

// Rarely-blocked connectivity anchors. ANY reachable anchor proves the user's path is
// alive, so even if one anchor is itself filtered the calibration still holds.
const CALIBRATION_ANCHORS = ["example.com", "cloudflare.com"];

// Ground truth via an encrypted channel. All endpoints failing is itself a signal.
async function dohLookup(domain) {
  let lastErr = null;
  for (const ep of DOH_ENDPOINTS) {
    try {
      const r = await fetch(ep.url(domain), { headers: { accept: "application/dns-json" } });
      if (!r.ok) { lastErr = `http_${r.status}`; continue; }
      const j = await r.json();
      const addresses = (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
      return { ok: true, endpoint: ep.name, rcode: j.Status, addresses, failure: null };
    } catch (e) {
      lastErr = (e && e.name) ? e.name : "fetch_error";
    }
  }
  return { ok: false, endpoint: null, rcode: null, addresses: [], failure: lastErr || "all_endpoints_failed" };
}

// One reachability sample through the browser's normal (OS/ISP) resolver — the user's
// real path. CORS hides the body, but a no-cors fetch still reveals whether a socket
// opened. We classify the OUTCOME, not the contents.
async function reachSample(domain, timeoutMs = 4000) {
  const url = `https://${domain}/favicon.ico?cb=${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const t0 = Date.now();
  let outcome = "unknown";
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store", signal: controller.signal });
    outcome = "connected"; // opaque response is fine — a socket opened
  } catch (e) {
    outcome = controller.signal.aborted ? "timeout" : "error";
  } finally {
    clearTimeout(timer);
  }
  return { outcome, t_ms: Date.now() - t0 };
}

// Sample reachability N times and aggregate. Rule: a SINGLE success proves
// reachability (you cannot both block and connect), so `connected` wins if any sample
// connects. Only if every sample fails do we call it unreachable — and the dominant
// failure mode (timeout vs error) becomes the aggregate outcome. This is the main
// guard against transient-network false positives.
async function clientReachProbe(domain, { samples = 3, timeoutMs = 4000 } = {}) {
  const results = [];
  for (let i = 0; i < samples; i++) results.push(await reachSample(domain, timeoutMs));
  const tally = { connected: 0, timeout: 0, error: 0, unknown: 0 };
  for (const r of results) tally[r.outcome] = (tally[r.outcome] || 0) + 1;
  let outcome;
  if (tally.connected > 0) outcome = "connected";
  else if (tally.timeout >= tally.error) outcome = "timeout";
  else outcome = "error";
  return { outcome, samples: results, connected: tally.connected, timeout: tally.timeout, error: tally.error };
}

// Is the user's connection working at all? Probe anchors; ANY success = ok.
async function calibrate(anchors = CALIBRATION_ANCHORS, timeoutMs = 4000) {
  const results = await Promise.all(
    anchors.map(async (domain) => ({ domain, ...(await reachSample(domain, timeoutMs)) }))
  );
  return { connection_ok: results.some((r) => r.outcome === "connected"), anchors: results };
}

async function controlCheck(domain, controlBase) {
  try {
    const r = await fetch(`${controlBase}/control?domain=${encodeURIComponent(domain)}`);
    if (!r.ok) return { up: null, addresses: [], tcp: null, tls: null, failure: `http_${r.status}` };
    return await r.json();
  } catch (e) {
    return { up: null, addresses: [], tcp: null, tls: null, failure: (e && e.name) || "fetch_error" };
  }
}

// Orchestrate all vantage points in parallel, then compute verdict + measurement.
// Returns { verdict, measurement }.
async function runCheck(domain, { controlBase, anchors = CALIBRATION_ANCHORS, samples = 3 } = {}) {
  const startedAt = new Date();
  const [doh, reach, calibration, control] = await Promise.all([
    dohLookup(domain),
    clientReachProbe(domain, { samples }),
    calibrate(anchors),
    controlCheck(domain, controlBase),
  ]);
  const verdict = window.Parallax.computeVerdict({ doh, reach, control, calibration });
  const endedAt = new Date();
  const measurement = window.Parallax.buildMeasurement(
    { domain, startedAt, endedAt, doh, reach, calibration, control, verdict },
    { controlBase }
  );
  return { verdict, measurement };
}

window.Parallax = Object.assign(window.Parallax || {}, {
  runCheck, dohLookup, clientReachProbe, calibrate, controlCheck,
});
