// Parallax — control endpoint tests (hermetic: no network). Run: node --test
const { test } = require("node:test");
const assert = require("node:assert");
const { DOMAIN_RE, check, SOFTWARE_VERSION } = require("../control/server.js");

test("DOMAIN_RE accepts well-formed domains", () => {
  for (const d of ["example.com", "sub.example.co.uk", "a.io", "xn--80ak6aa92e.com"]) {
    assert.ok(DOMAIN_RE.test(d), `should accept ${d}`);
  }
});

test("DOMAIN_RE rejects junk, schemes, paths, and SSRF-ish inputs", () => {
  for (const d of [
    "", "localhost", "example", "http://example.com", "example.com/path",
    "192.168.0.1", "exam ple.com", "-bad.com", "a..b.com", "例え.テスト",
  ]) {
    assert.ok(!DOMAIN_RE.test(d), `should reject ${d}`);
  }
});

test("module surface is exported and versioned", () => {
  assert.strictEqual(typeof check, "function");
  assert.match(SOFTWARE_VERSION, /^\d+\.\d+\.\d+$/);
});
