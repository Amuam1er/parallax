// Parallax — verdict engine tests. Run: node --test
const { test } = require("node:test");
const assert = require("node:assert");
const { computeVerdict } = require("../web/verdict.js");

const goodCal = { connection_ok: true, anchors: [{ domain: "example.com", outcome: "connected" }] };
const badCal = { connection_ok: false, anchors: [{ domain: "example.com", outcome: "timeout" }] };

test("headline: up elsewhere, timeout here -> BLOCKED_FOR_YOU (transport probe, layer unconfirmed)", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "timeout" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "BLOCKED_FOR_YOU");
  assert.strictEqual(r.blocking, "tcp_ip");
  assert.strictEqual(r.accessible, false);
  assert.match(r.method_hint, /timeout/);
  assert.ok(r.notes.includes("layer_unconfirmed_in_browser"));
});

test("up elsewhere, hard error here -> BLOCKED_FOR_YOU (reset/blocking)", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "error" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "BLOCKED_FOR_YOU");
  assert.match(r.method_hint, /reset|block/);
});

test("up elsewhere and reachable here -> ACCESSIBLE", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "connected" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "ACCESSIBLE");
  assert.strictEqual(r.blocking, false);
  assert.strictEqual(r.accessible, true);
});

test("DNS hijack to block page -> ACCESSIBLE (known Tier A false-negative)", () => {
  // If an ISP redirects the domain's DNS to a block-page server, a socket opens to
  // that server and reach.outcome is "connected". The verdict engine cannot distinguish
  // this from genuine reachability — JS cannot read the OS resolver's returned IP.
  // ACCESSIBLE is the correct output given what Tier A can observe. Tier B's
  // browser.dns.resolve() fixes this by comparing the resolver's answer to DoH truth.
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "connected" }, // socket opened — possibly to a block-page server
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "ACCESSIBLE"); // accurate given Tier A's observable scope
});

test("reachable but DoH failed -> still ACCESSIBLE, noted (no false alarm)", () => {
  const r = computeVerdict({
    doh: { ok: false, addresses: [] },
    reach: { outcome: "connected" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "ACCESSIBLE");
  assert.ok(r.notes.includes("doh_failed_but_site_reachable"));
});

test("down on a clean network -> DOMAIN_DOWN (not censorship)", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: [] },
    reach: { outcome: "error" },
    control: { up: false, tcp: false, tls: false },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "DOMAIN_DOWN");
  assert.strictEqual(r.blocking, "false");
  assert.strictEqual(r.accessible, false);
});

test("DoH failing, not reachable, up elsewhere -> DOH_BLOCKED", () => {
  const r = computeVerdict({
    doh: { ok: false, addresses: [] },
    reach: { outcome: "error" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "DOH_BLOCKED");
  assert.strictEqual(r.blocking, "dns");
});

test("user's own connection down -> INCONCLUSIVE (no false accusation)", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "timeout" },
    control: { up: true, tcp: true, tls: true },
    calibration: badCal,
  });
  assert.strictEqual(r.verdict, "INCONCLUSIVE");
  assert.ok(r.notes.includes("calibration_anchors_unreachable"));
});

test("control unavailable -> INCONCLUSIVE (can't tell down from blocked)", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "timeout" },
    control: { up: null, failure: "fetch_error" },
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "INCONCLUSIVE");
  assert.ok(r.notes.includes("control_unavailable"));
});

test("missing control object -> INCONCLUSIVE", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "timeout" },
    control: undefined,
    calibration: goodCal,
  });
  assert.strictEqual(r.verdict, "INCONCLUSIVE");
});

test("every verdict exposes OONI-aligned blocking + accessible keys", () => {
  const r = computeVerdict({
    doh: { ok: true, addresses: ["1.2.3.4"] },
    reach: { outcome: "connected" },
    control: { up: true, tcp: true, tls: true },
    calibration: goodCal,
  });
  assert.ok("blocking" in r && "accessible" in r);
  assert.ok(Array.isArray(r.notes));
});
