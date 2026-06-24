// Parallax — measurement record tests. Run: node --test
const { test } = require("node:test");
const assert = require("node:assert");
const { buildMeasurement, ooniTime } = require("../web/measurement.js");
const { computeVerdict } = require("../web/verdict.js");

function sample() {
  const doh = { ok: true, endpoint: "cloudflare", rcode: 0, addresses: ["1.2.3.4"], failure: null };
  const reach = { outcome: "timeout", samples: [{ outcome: "timeout", t_ms: 4001 }], connected: 0, timeout: 3, error: 0 };
  const calibration = { connection_ok: true, anchors: [{ domain: "example.com", outcome: "connected" }] };
  const control = { up: true, addresses: ["1.2.3.4"], tcp: true, tls: true, failure: null };
  const verdict = computeVerdict({ doh, reach, control, calibration });
  const startedAt = new Date("2026-06-24T12:00:00Z");
  const endedAt = new Date("2026-06-24T12:00:04Z");
  return buildMeasurement(
    { domain: "blocked.example", startedAt, endedAt, doh, reach, calibration, control, verdict },
    { reportId: "fixed-report-id", controlBase: "http://localhost:8787" }
  );
}

test("ooniTime formats as UTC 'YYYY-MM-DD HH:MM:SS'", () => {
  assert.strictEqual(ooniTime(new Date("2026-06-24T09:05:07Z")), "2026-06-24 09:05:07");
});

test("envelope carries the OONI base-format keys", () => {
  const m = sample();
  for (const k of [
    "annotations", "data_format_version", "input", "measurement_start_time",
    "probe_asn", "probe_cc", "probe_ip", "report_id", "software_name",
    "software_version", "test_name", "test_runtime", "test_start_time",
    "test_version", "test_keys",
  ]) {
    assert.ok(k in m, `missing key: ${k}`);
  }
  assert.strictEqual(m.input, "blocked.example");
  assert.strictEqual(m.software_name, "parallax");
  assert.strictEqual(m.test_name, "parallax_vantage");
  assert.strictEqual(m.report_id, "fixed-report-id");
  assert.strictEqual(m.test_runtime, 4);
});

test("privacy by design: no user IP / ASN / geolocation leaks", () => {
  const m = sample();
  assert.strictEqual(m.probe_ip, "127.0.0.1");
  assert.strictEqual(m.probe_asn, null);
  assert.strictEqual(m.probe_cc, null);
  assert.strictEqual(m.resolver_ip, null);
  assert.strictEqual(m.annotations.client_geolocation, "disabled_by_design");
});

test("test_keys preserve raw evidence and the OONI summary", () => {
  const m = sample();
  const k = m.test_keys;
  assert.strictEqual(k.blocking, "tcp_ip");
  assert.strictEqual(k.accessible, false);
  assert.strictEqual(k.parallax_verdict, "BLOCKED_FOR_YOU");
  assert.strictEqual(k.doh.endpoint, "cloudflare");
  assert.strictEqual(k.control.tls, true);
  assert.strictEqual(k.client_reach.outcome, "timeout");
  assert.strictEqual(k.calibration.connection_ok, true);
});

test("a report_id is generated when not supplied", () => {
  const doh = { ok: true, addresses: ["1.2.3.4"] };
  const reach = { outcome: "connected" };
  const calibration = { connection_ok: true, anchors: [] };
  const control = { up: true, tcp: true, tls: true };
  const verdict = computeVerdict({ doh, reach, control, calibration });
  const m = buildMeasurement({
    domain: "x.example", startedAt: new Date(), endedAt: new Date(),
    doh, reach, calibration, control, verdict,
  });
  assert.ok(typeof m.report_id === "string" && m.report_id.length > 0);
});
