// Leak Guard — zero-dependency GitHub Action (Node 20).
// Scans a PR's added lines and new filenames for leaked secrets, annotates the
// exact line, posts a single (updated) PR comment, and fails per `fail-on`.
// Matched secrets are ALWAYS redacted before logging. No npm install required.

const fs = require('fs');

// ---- Workflow command helpers -------------------------------------------------
const log = (m) => process.stdout.write(m + '\n');
const annotate = (level, f) => {
  const loc = f.line ? `,line=${f.line}` : '';
  log(`::${level} file=${f.file}${loc},title=${f.title}::${f.message}`);
};
const setOutput = (name, val) => {
  const out = process.env.GITHUB_OUTPUT;
  if (out) fs.appendFileSync(out, `${name}<<__EOF__\n${val}\n__EOF__\n`);
};

const RULES = require('./index.rules.js');

// ---- Redaction ----------------------------------------------------------------
// Never expose a full secret. Keep a short prefix so humans can locate it.
function redact(match) {
  const s = String(match);
  if (s.length <= 8) return s[0] + '***';
  return s.slice(0, 4) + '…' + s.slice(-2) + ` (${s.length} chars)`;
}

// ---- Config (subset of YAML, no dependency) -----------------------------------
// fail-on: error | ignore:\n - path | disable:\n - rule-id | allow:\n - substring
function loadConfig() {
  const cfg = { 'fail-on': null, ignore: [], disable: [], allow: [] };
  const path = process.env.INPUT_CONFIG || '.leakguard.yml';
  let text;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch {
    return cfg;
  }
  let current = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').replace(/\s+$/, '');
    if (!line.trim()) continue;
    const kv = line.match(/^([A-Za-z_-]+):\s*(.*)$/);
    if (kv) {
      const key = kv[1];
      const val = kv[2].trim().replace(/^["']|["']$/g, '');
      if (key === 'fail-on') {
        cfg['fail-on'] = val.toLowerCase();
        current = null;
      } else if (key === 'ignore' || key === 'disable' || key === 'allow') {
        current = key;
      } else current = null;
      continue;
    }
    const item = line.match(/^\s*-\s*(.+)$/);
    if (item && current) cfg[current].push(item[1].trim().replace(/^["']|["']$/g, ''));
  }
  return cfg;
}

// ---- Patch parsing: added lines with their new-file line numbers --------------
function addedLinesWithNumbers(patch) {
  const out = [];
  let newLine = 0;
  for (const raw of patch.split('\n')) {
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      newLine = parseInt(hunk[1], 10);
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      out.push({ text: raw.slice(1), line: newLine });
      newLine++;
    } else if (raw.startsWith('-') && !raw.startsWith('---')) {
      // removed line: no advance
    } else newLine++;
  }
  return out;
}

// ---- Core scan (pure, testable) ----------------------------------------------
const SUPPRESS = /(leak-guard|gitleaks?):\s*allow/i;

function scanFile(file, cfg, rules) {
  const findings = [];
  if (cfg.ignore.some((p) => p && file.filename.includes(p))) return findings;

  for (const rule of rules) {
    if (rule.kind === 'filename') {
      if (rule.pattern.test(file.filename)) {
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          file: file.filename,
          line: 0,
          title: rule.title,
          message: `${rule.title}: this file should not be committed.`,
        });
      }
      continue;
    }
    // content rules
    if (!file.patch) continue;
    for (const { text, line } of file._added) {
      if (SUPPRESS.test(text)) continue;
      const m = rule.pattern.exec(text);
      if (!m) continue;
      if (cfg.allow.some((a) => a && m[0].includes(a))) continue;
      findings.push({
        rule: rule.id,
        severity: rule.severity,
        file: file.filename,
        line,
        title: rule.title,
        message: `${rule.title} detected — ${redact(m[0])}. Rotate it and move to a secret store.`,
      });
      break; // one hit per rule per file
    }
  }
  return findings;
}

// ---- GitHub API ---------------------------------------------------------------
const GH = 'https://api.github.com';
const ghHeaders = (token) => ({
  Authorization: `Bearer ${token}`,
  Accept: 'application/vnd.github+json',
  'User-Agent': 'leak-guard',
});

async function getPrContext() {
  const token = process.env.GITHUB_TOKEN || process.env.INPUT_TOKEN;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) throw new Error('No GITHUB_EVENT_PATH — run this on a pull_request event.');
  const event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  const pr = event.pull_request;
  if (!pr) {
    log('::notice::Leak Guard only runs on pull_request events. Skipping.');
    return null;
  }
  return { token, repo: process.env.GITHUB_REPOSITORY, number: pr.number };
}

async function getChangedFiles(ctx) {
  const files = [];
  let page = 1;
  while (true) {
    const res = await fetch(
      `${GH}/repos/${ctx.repo}/pulls/${ctx.number}/files?per_page=100&page=${page}`,
      { headers: ghHeaders(ctx.token) }
    );
    if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
    const batch = await res.json();
    files.push(...batch);
    if (batch.length < 100) break;
    page++;
  }
  return files;
}

const COMMENT_MARKER = '<!-- leak-guard -->';

async function upsertComment(ctx, body) {
  const listRes = await fetch(
    `${GH}/repos/${ctx.repo}/issues/${ctx.number}/comments?per_page=100`,
    { headers: ghHeaders(ctx.token) }
  );
  if (listRes.ok) {
    const comments = await listRes.json();
    const existing = comments.find((c) => c.body && c.body.includes(COMMENT_MARKER));
    if (existing) {
      await fetch(`${GH}/repos/${ctx.repo}/issues/comments/${existing.id}`, {
        method: 'PATCH',
        headers: ghHeaders(ctx.token),
        body: JSON.stringify({ body }),
      });
      return;
    }
  }
  await fetch(`${GH}/repos/${ctx.repo}/issues/${ctx.number}/comments`, {
    method: 'POST',
    headers: ghHeaders(ctx.token),
    body: JSON.stringify({ body }),
  });
}

function renderComment(findings) {
  if (findings.length === 0) {
    return `${COMMENT_MARKER}\n### 🔑 Leak Guard — ✅ no secrets detected\n\nNo leaked credentials found in this PR.`;
  }
  const rows = findings
    .map(
      (f) =>
        `| ${f.severity === 'error' ? '🔴 error' : '🟡 warn'} | \`${f.file}\`${
          f.line ? `:${f.line}` : ''
        } | ${f.title} |`
    )
    .join('\n');
  const errors = findings.filter((f) => f.severity === 'error').length;
  return (
    `${COMMENT_MARKER}\n### 🔑 Leak Guard — ${errors} error, ${findings.length - errors} warn\n\n` +
    `Secrets are redacted below. **Rotate any real credential immediately** — it is already in git history.\n\n` +
    `| Severity | Location | What |\n|---|---|---|\n${rows}\n\n` +
    `<sub>Suppress a false positive with \`leak-guard:allow\` on the line, or via \`.leakguard.yml\`. Part of [DevGuard Tools](https://ivosetyadi.github.io).</sub>`
  );
}

// ---- Main ---------------------------------------------------------------------
async function run() {
  const ctx = await getPrContext();
  if (!ctx) return;

  const cfg = loadConfig();
  const failOn = (cfg['fail-on'] || process.env.INPUT_FAIL_ON || 'error').toLowerCase();
  const disabled = new Set(cfg.disable);
  const rules = RULES.filter((r) => !disabled.has(r.id));

  const files = await getChangedFiles(ctx);
  const findings = [];
  for (const file of files) {
    if (file.status === 'removed') continue;
    file._added = file.patch ? addedLinesWithNumbers(file.patch) : [];
    findings.push(...scanFile(file, cfg, rules));
  }

  for (const f of findings) annotate(f.severity === 'error' ? 'error' : 'warning', f);
  setOutput('findings', JSON.stringify(findings));

  if ((process.env.INPUT_COMMENT || 'true') === 'true') {
    try {
      await upsertComment(ctx, renderComment(findings));
    } catch (e) {
      log(`::warning::Could not post PR comment: ${e.message}`);
    }
  }

  const errors = findings.filter((f) => f.severity === 'error');
  log('');
  log(
    `Leak Guard: ${findings.length} finding(s) — ${errors.length} error, ${
      findings.length - errors.length
    } warn. (fail-on=${failOn})`
  );

  if (failOn === 'off') return;
  if (failOn === 'warn' && findings.length > 0) process.exit(1);
  if (failOn === 'error' && errors.length > 0) process.exit(1);
}

if (require.main === module) {
  run().catch((e) => {
    log(`::error::Leak Guard failed: ${e.message}`);
    process.exit(1);
  });
}

module.exports = { loadConfig, addedLinesWithNumbers, scanFile, redact, renderComment, RULES };
