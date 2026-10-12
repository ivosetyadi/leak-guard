// Secret-detection rules for Leak Guard. Required by dist/index.js and tests.
// Each rule matches an added line (leading '+' stripped). The matched substring
// is redacted before it ever reaches logs or comments.
//
// kind: 'content' (scan added lines) | 'filename' (flag the file itself)
// severity: error (fails) | warn

module.exports = [
  // ---- Provider-specific credentials (high confidence) ----------------------
  {
    id: 'aws-access-key',
    kind: 'content',
    severity: 'error',
    title: 'AWS access key ID',
    pattern: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/,
  },
  {
    id: 'aws-secret-key',
    kind: 'content',
    severity: 'error',
    title: 'AWS secret access key',
    pattern: /\baws_secret_access_key\b\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/i,
  },
  {
    id: 'github-token',
    kind: 'content',
    severity: 'error',
    title: 'GitHub token',
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/,
  },
  {
    id: 'google-api-key',
    kind: 'content',
    severity: 'error',
    title: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  {
    id: 'stripe-key',
    kind: 'content',
    severity: 'error',
    title: 'Stripe secret key',
    pattern: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b/,
  },
  {
    id: 'slack-token',
    kind: 'content',
    severity: 'error',
    title: 'Slack token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
  },
  {
    id: 'openai-key',
    kind: 'content',
    severity: 'error',
    title: 'OpenAI / LLM API key',
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'private-key-block',
    kind: 'content',
    severity: 'error',
    title: 'Private key material',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
  {
    id: 'jwt',
    kind: 'content',
    severity: 'warn',
    title: 'Hardcoded JWT',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  // ---- Generic assignment (medium confidence) -------------------------------
  {
    id: 'generic-secret-assignment',
    kind: 'content',
    severity: 'warn',
    title: 'Possible hardcoded secret',
    pattern:
      /\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"][^'"\s]{12,}['"]/i,
  },
  // ---- Committed secret files (flag the filename) ---------------------------
  {
    id: 'committed-env-file',
    kind: 'filename',
    severity: 'error',
    title: 'Committed .env / secrets file',
    pattern: /(^|\/)(\.env(\.[\w-]+)?|secrets?\.(ya?ml|json|php|txt)|id_(rsa|ed25519)|.*\.pem|.*\.ppk)$/i,
  },
];
