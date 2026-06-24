// Parallax — measurement record builder.
// Pure (clock/id are injectable for tests). Runs in the browser AND in Node.
//
// Produces an OONI-aligned, privacy-clean measurement record. The envelope mirrors
// the OONI base data format (df-000-base) so the output is familiar to anyone in the
// censorship-measurement community and easy to ingest alongside OONI data. The
// nettest-specific evidence lives under `test_keys`, modeled on Web Connectivity.
//
// PRIVACY BY DESIGN (see docs/PRIVACY.md):
//   - probe_ip is fixed to "127.0.0.1" (OONI's redaction convention). Parallax never
//     records the user's IP.
//   - probe_asn / probe_cc are null by default: Tier A deliberately performs NO
//     client geolocation, so we cannot leak network/location. The annotation records
//     this as an intentional choice, not a missing field.

// Keep in sync with package.json "version".
const SOFTWARE_VERSION = "0.2.0";
const DATA_FORMAT_VERSION = "0.2.0";
const TEST_NAME = "parallax_vantage";
const TEST_VERSION = "0.2.0";

// OONI timestamps are "YYYY-MM-DD HH:MM:SS" in UTC.
function ooniTime(date) {
  const p = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${p(date.getUTCMonth() + 1)}-${p(date.getUTCDate())} ` +
    `${p(date.getUTCHours())}:${p(date.getUTCMinutes())}:${p(date.getUTCSeconds())}`
  );
}

function makeReportId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  } catch (_) { /* fall through */ }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

// inputs:
//   domain, startedAt (Date), endedAt (Date), doh, reach, calibration, control, verdict
//   opts: { reportId, controlBase }
function buildMeasurement(inputs, opts = {}) {
  const { domain, startedAt, endedAt, doh, reach, calibration, control, verdict } = inputs;
  const runtimeSec = Math.max(0, (endedAt.getTime() - startedAt.getTime()) / 1000);

  return {
    annotations: {
      // Honest provenance + the privacy stance, machine-readable.
      platform: "browser",
      vantage_model: "client_vs_clean_control",
      client_geolocation: "disabled_by_design",
      engine: "parallax-tier-a",
      control_base: opts.controlBase || null,
    },
    data_format_version: DATA_FORMAT_VERSION,
    input: domain,
    measurement_start_time: ooniTime(startedAt),
    probe_asn: null,            // intentionally not collected (Tier A)
    probe_cc: null,             // intentionally not collected (Tier A)
    probe_ip: "127.0.0.1",      // redacted by convention; never the user's real IP
    probe_network_name: null,
    report_id: opts.reportId || makeReportId(),
    resolver_asn: null,
    resolver_ip: null,          // the OS/ISP resolver IP is opaque to the browser
    resolver_network_name: null,
    software_name: "parallax",
    software_version: SOFTWARE_VERSION,
    test_name: TEST_NAME,
    test_runtime: Number(runtimeSec.toFixed(3)),
    test_start_time: ooniTime(startedAt),
    test_version: TEST_VERSION,
    test_keys: buildTestKeys({ doh, reach, calibration, control, verdict }),
  };
}

function buildTestKeys({ doh, reach, calibration, control, verdict }) {
  return {
    // --- Raw vantage evidence (so any reviewer can re-derive the verdict) ---
    doh: doh
      ? {
          ok: !!doh.ok,
          endpoint: doh.endpoint || null,
          rcode: doh.rcode === undefined ? null : doh.rcode,
          addresses: doh.addresses || [],
          failure: doh.failure || null,
        }
      : null,
    client_reach: reach
      ? {
          outcome: reach.outcome,
          samples: reach.samples || [],
          connected: reach.connected ?? null,
          timeout: reach.timeout ?? null,
          error: reach.error ?? null,
        }
      : null,
    calibration: calibration
      ? {
          connection_ok: !!calibration.connection_ok,
          anchors: calibration.anchors || [],
        }
      : null,
    control: control
      ? {
          up: control.up ?? null,
          addresses: control.addresses || [],
          tcp: control.tcp ?? null,
          tls: control.tls ?? null,
          failure: control.failure || null,
        }
      : null,

    // --- OONI-aligned summary (Web Connectivity vocabulary) ---
    blocking: verdict ? verdict.blocking : null,
    accessible: verdict ? verdict.accessible : null,

    // --- Parallax verdict surface ---
    parallax_verdict: verdict ? verdict.verdict : null,
    confidence: verdict ? verdict.confidence : null,
    method_hint: verdict ? verdict.method_hint : null,
    recommendation: verdict ? verdict.recommendation : null,
    notes: verdict ? verdict.notes || [] : [],
  };
}

const api = { buildMeasurement, ooniTime, makeReportId, SOFTWARE_VERSION, DATA_FORMAT_VERSION };
if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}
if (typeof window !== "undefined") {
  window.Parallax = Object.assign(window.Parallax || {}, api);
}
