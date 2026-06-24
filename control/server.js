// Parallax — control endpoint.
// "What does the world see?" reference, run on a clean (uncensored) network.
// Zero dependencies: Node built-in http/dns/net/tls only. Run: node control/server.js
//
// GET /control?domain=example.com
//   -> { domain, up, addresses, addresses6, tcp, tls, failure, measured_at, software_version }
// GET /health -> { ok: true, software_version }
//
// PRIVACY: receives only a bare domain string. Logs nothing tied to a user — no IPs,
// no query logging. See docs/PRIVACY.md.

const http = require("http");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");
const { URL } = require("url");

const PORT = process.env.PORT || 8787;
const SOFTWARE_VERSION = "0.2.0"; // keep in sync with package.json
// Hostnames only: per-label 1-63 chars, no leading/trailing hyphen, IDN punycode
// (xn--) accepted in labels and TLD. Rejects IP literals, schemes, paths, spaces.
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,}|xn--[a-z0-9]+)$/i;

function tcpConnect(host, port, timeout = 4000) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (ok) => { sock.destroy(); resolve(ok); };
    sock.setTimeout(timeout);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

function tlsConnect(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false });
    const done = (ok) => { sock.destroy(); resolve(ok); };
    sock.setTimeout(timeout);
    sock.once("secureConnect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

// Reference reachability from a clean network: DNS (A/AAAA) → TCP:443 → TLS:443.
// `up` means a real connection is achievable globally. `failure` names the first
// stage that broke, so the verdict engine and reviewers can see *why*.
async function check(domain) {
  const [addresses, addresses6] = await Promise.all([
    dns.resolve4(domain).catch(() => []),
    dns.resolve6(domain).catch(() => []),
  ]);
  const dnsUp = addresses.length > 0 || addresses6.length > 0;
  if (!dnsUp) {
    return { domain, up: false, addresses, addresses6, tcp: false, tls: false,
      failure: "dns_nxdomain_or_empty", measured_at: new Date().toISOString(),
      software_version: SOFTWARE_VERSION };
  }
  const host = addresses[0] || domain;
  const tcp = await tcpConnect(host, 443);
  const tlsOk = tcp ? await tlsConnect(domain, 443) : false;
  const up = dnsUp && tcp;
  const failure = up ? null : (tcp ? null : "tcp_connect_failed");
  return { domain, up, addresses, addresses6, tcp, tls: tlsOk,
    failure, measured_at: new Date().toISOString(), software_version: SOFTWARE_VERSION };
}

function sendJSON(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // browser probe calls this cross-origin
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");

  if (req.method === "OPTIONS") { res.writeHead(204).end(); return; }
  if (req.method !== "GET") { sendJSON(res, 405, { error: "method_not_allowed" }); return; }

  const u = new URL(req.url, `http://localhost:${PORT}`);
  if (u.pathname === "/health") { sendJSON(res, 200, { ok: true, software_version: SOFTWARE_VERSION }); return; }
  if (u.pathname !== "/control") { sendJSON(res, 404, { error: "not_found" }); return; }

  const domain = (u.searchParams.get("domain") || "").toLowerCase().trim();
  if (!DOMAIN_RE.test(domain)) { sendJSON(res, 400, { error: "invalid_domain" }); return; }

  try {
    sendJSON(res, 200, await check(domain));
  } catch (_) {
    sendJSON(res, 500, { error: "check_failed" });
  }
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`parallax control on :${PORT}`));
}
module.exports = { check, DOMAIN_RE, SOFTWARE_VERSION };
