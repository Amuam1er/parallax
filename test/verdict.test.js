// Parallax — verdict engine tests. Run: node test/verdict.test.js
const assert = require("assert");
const { computeVerdict } = require("../web/verdict.js");

const goodSelf = { outcome: "connected" }; // our calibration domain is reachable
let passed = 0;

function t(name, got, expected) {
  assert.strictEqual(got.verdict, expected, `${name}: expected ${expected}, got ${got.verdict}`);
  console.log(`  ok  ${name} -> ${got.verdict}`);
  passed++;
}

// The headline case: up on a clean network, unreachable here = censored for this user.
t("blocked (timeout)", computeVerdict({
  doh: { ok: true, addresses: ["1.2.3.4"] },
  reach: { outcome: "timeout" },
  control: { up: true },
  controlSelf: goodSelf,
}), "BLOCKED_FOR_YOU");

t("accessible", computeVerdict({
  doh: { ok: true, addresses: ["1.2.3.4"] },
  reach: { outcome: "connected" },
  control: { up: true },
  controlSelf: goodSelf,
}), "ACCESSIBLE");

t("domain genuinely down (not censorship)", computeVerdict({
  doh: { ok: true, addresses: [] },
  reach: { outcome: "error" },
  control: { up: false },
  controlSelf: goodSelf,
}), "DOMAIN_DOWN");

t("DoH itself blocked", computeVerdict({
  doh: { ok: false, addresses: [] },
  reach: { outcome: "error" },
  control: { up: true },
  controlSelf: goodSelf,
}), "DOH_BLOCKED");

t("user's own connection down -> no false accusation", computeVerdict({
  doh: { ok: true, addresses: ["1.2.3.4"] },
  reach: { outcome: "timeout" },
  control: { up: true },
  controlSelf: { outcome: "timeout" },
}), "INCONCLUSIVE");

console.log(`\n${passed}/5 passed`);
