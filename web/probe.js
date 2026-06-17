// Parallax — browser probe.
// Measures from the USER'S vantage: DoH ground truth + ISP-resolver reachability,
// then asks the control endpoint what a clean network sees, then computes a verdict.

const DOH_ENDPOINTS = [
  { name: "cloudflare", url: (d) => `https://cloudflare-dns.com/dns-query?name=${d}&type=A` },
  { name: "google",     url: (d) => `https://dns.google/resolve?name=${d}&type=A` },
  { name: "quad9",      url: (d) => `https://dns.quad9.net:5053/dns-query?name=${d}&type=A` },
];

// Ground truth via an encrypted channel. All endpoints failing is itself a signal.
async function dohLookup(domain) {
  for (const ep of DOH_ENDPOINTS) {
    try {
      const r = await fetch(ep.url(domain), { headers: { accept: "application/dns-json" } });
      if (!r.ok) continue;
      const j = await r.json();
      const addresses = (j.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
      return { ok: true, endpoint: ep.name, rcode: j.Status, addresses };
    } catch (_) { /* try next endpoint */ }
  }
  return { ok: false, endpoint: null, addresses: [] };
}

// Reachability through the browser's normal (OS/ISP) resolver — the user's real path.
// CORS hides the response body, but a no-cors fetch still reveals whether a
// connection happened. We classify the OUTCOME, not the contents.
async function clientReachProbe(domain, timeoutMs = 4000) {
  const url = `https://${domain}/favicon.ico?cb=${Date.now()}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let outcome = "unknown";
  try {
    await fetch(url, { mode: "no-cors", cache: "no-store", signal: controller.signal });
    outcome = "connected"; // opaque response is fine — a socket opened
  } catch (e) {
    outcome = controller.signal.aborted ? "timeout" : "error";
  } finally {
    clearTimeout(timer);
  }
  return { outcome };
}

async function controlCheck(domain, controlBase) {
  try {
    const r = await fetch(`${controlBase}/control?domain=${encodeURIComponent(domain)}`);
    if (!r.ok) return { up: null, error: true };
    return await r.json();
  } catch (_) {
    return { up: null, error: true };
  }
}

// Orchestrate all vantage points in parallel, then hand to the verdict engine.
async function runCheck(domain, { controlBase, calibrationDomain = "wikipedia.org" }) {
  const [doh, reach, controlSelf, control] = await Promise.all([
    dohLookup(domain),
    clientReachProbe(domain),
    clientReachProbe(calibrationDomain), // baseline: is the user's connection itself ok?
    controlCheck(domain, controlBase),
  ]);
  return window.Parallax.computeVerdict({ doh, reach, control, controlSelf });
}

window.Parallax = Object.assign(window.Parallax || {}, { runCheck });
