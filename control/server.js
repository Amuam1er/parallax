// Parallax — control endpoint.
// "What does the world see?" reference, run on a clean (uncensored) network.
// Zero dependencies: Node built-in http/dns/net/tls only. Run: node control/server.js
//
// GET /control?domain=example.com
//   -> { domain, up, addresses, tcp, tls }
// Logs nothing tied to a user. Receives only a bare domain string.

const http = require("http");
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");
const { URL } = require("url");

const PORT = process.env.PORT || 8787;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i;

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

async function check(domain) {
  const addresses = await dns.resolve4(domain).catch(() => []);
  const dnsUp = addresses.length > 0;
  const tcp = dnsUp ? await tcpConnect(domain, 443) : false;
  const tlsOk = tcp ? await tlsConnect(domain, 443) : false;
  return { domain, up: dnsUp && tcp, addresses, tcp, tls: tlsOk };
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // browser probe calls this cross-origin
  const u = new URL(req.url, `http://localhost:${PORT}`);
  if (u.pathname !== "/control") {
    res.writeHead(404).end(JSON.stringify({ error: "not_found" }));
    return;
  }
  const domain = (u.searchParams.get("domain") || "").toLowerCase().trim();
  if (!DOMAIN_RE.test(domain)) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid_domain" }));
    return;
  }
  const result = await check(domain);
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(result));
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`parallax control on :${PORT}`));
}
module.exports = { check };
