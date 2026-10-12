// Offline test suite for Leak Guard. No network. Uses only dummy/fake secrets.
const assert = require('assert');
const { scanFile, redact, addedLinesWithNumbers, renderComment, RULES } = require('../dist/index.js');

let pass = 0;
const ok = (c, m) => {
  assert.ok(c, m);
  pass++;
};

// helper: build a file object from added lines
function file(name, lines) {
  const patch = '@@ -0,0 +1,' + lines.length + ' @@\n' + lines.map((l) => '+' + l).join('\n');
  return { filename: name, status: 'modified', patch, _added: addedLinesWithNumbers(patch) };
}
const cfg = { 'fail-on': null, ignore: [], disable: [], allow: [] };
const scan = (f) => scanFile(f, cfg, RULES);

// --- content detections (all fake) -------------------------------------------
ok(scan(file('a.js', ['const k = "AKIAIOSFODNN7EXAMPLE";'])).some((x) => x.rule === 'aws-access-key'), 'aws key');
ok(scan(file('a.js', ['token=ghp_0123456789012345678901234567890123AB'])).some((x) => x.rule === 'github-token'), 'github token');
ok(scan(file('a.js', ['key = "AIza' + 'b'.repeat(35) + '"'])).some((x) => x.rule === 'google-api-key'), 'google key');
ok(scan(file('a.js', ['stripe="sk_live_0123456789abcdefABCD"'])).some((x) => x.rule === 'stripe-key'), 'stripe key');
ok(scan(file('k.pem', ['-----BEGIN RSA PRIVATE KEY-----'])).some((x) => x.rule === 'private-key-block'), 'private key');

// --- filename detection ------------------------------------------------------
ok(scan({ filename: '.env', status: 'added', patch: '', _added: [] }).some((x) => x.rule === 'committed-env-file'), 'committed .env');
ok(scan({ filename: 'config/id_rsa', status: 'added', patch: '', _added: [] }).some((x) => x.rule === 'committed-env-file'), 'committed id_rsa');

// --- clean file: no findings -------------------------------------------------
ok(scan(file('ok.js', ['const total = a + b;', 'return total;'])).length === 0, 'clean file → no findings');

// --- redaction never exposes full secret -------------------------------------
const f = scan(file('a.js', ['const k = "AKIAIOSFODNN7EXAMPLE";']))[0];
ok(!f.message.includes('AKIAIOSFODNN7EXAMPLE'), 'secret is redacted in message');
ok(redact('AKIAIOSFODNN7EXAMPLE').includes('…'), 'redact() elides the middle');

// --- inline suppression ------------------------------------------------------
ok(scan(file('a.js', ['const k = "AKIAIOSFODNN7EXAMPLE"; // leak-guard:allow'])).length === 0, 'inline suppression works');

// --- allowlist ---------------------------------------------------------------
const cfgAllow = { 'fail-on': null, ignore: [], disable: [], allow: ['AKIAIOSFODNN7EXAMPLE'] };
ok(scanFile(file('a.js', ['const k = "AKIAIOSFODNN7EXAMPLE";']), cfgAllow, RULES).length === 0, 'allowlist suppresses match');

// --- ignore path -------------------------------------------------------------
const cfgIgnore = { 'fail-on': null, ignore: ['test/fixtures/'], disable: [], allow: [] };
ok(scanFile(file('test/fixtures/a.js', ['const k = "AKIAIOSFODNN7EXAMPLE";']), cfgIgnore, RULES).length === 0, 'ignore path works');

// --- disable rule ------------------------------------------------------------
const activeNoAws = RULES.filter((r) => r.id !== 'aws-access-key');
ok(scanFile(file('a.js', ['const k = "AKIAIOSFODNN7EXAMPLE";']), cfg, activeNoAws).every((x) => x.rule !== 'aws-access-key'), 'disabled rule skipped');

// --- comment render ----------------------------------------------------------
ok(renderComment([]).includes('no secrets detected'), 'clean comment');
ok(renderComment([{ severity: 'error', file: '.env', line: 0, title: 'X' }]).includes('leak-guard'), 'finding comment has marker');

console.log(`✓ ${pass} assertions passed`);
