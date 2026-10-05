/**
 * @file Credential protection — detects and blocks credential exfiltration.
 *
 * Scans tool arguments and subprocess commands for:
 *  - API keys, tokens, passwords in environment variables or arguments
 *  - Credential file paths (~/.ssh, ~/.aws/credentials, .credentials.yaml)
 *  - Patterns that look like secrets being sent to network destinations
 */

/** Patterns that indicate credential-like values. */
const SECRET_PATTERNS = [
  // OpenAI / Anthropic / generic API keys
  { pattern: /sk-[A-Za-z0-9_-]{20,}/g, label: 'API key (sk-...)' },
  { pattern: /ghp_[A-Za-z0-9]{36,}/g, label: 'GitHub token' },
  { pattern: /gho_[A-Za-z0-9]{36,}/g, label: 'GitHub OAuth token' },
  { pattern: /github_pat_[A-Za-z0-9_]{82,}/g, label: 'GitHub fine-grained PAT' },
  { pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: 'Slack token' },
  { pattern: /AKIA[0-9A-Z]{16}/g, label: 'AWS access key' },
  { pattern: /ASIA[0-9A-Z]{16}/g, label: 'AWS session token' },
  // Private key blocks
  { pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'private key block' },
  // Generic high-entropy assignment patterns
  { pattern: /(?:api[_-]?key|secret|token|password|passwd|auth|credential)["'\s:=]+["']?[A-Za-z0-9_\-]{16,}["']?/gi, label: 'credential assignment' },
];

/** Credential file path patterns that should never be read by untrusted tools. */
const CREDENTIAL_PATHS = [
  /\/\.ssh\//,
  /\/\.aws\/credentials/,
  /\/\.gnupg\//,
  /\/\.netrc$/,
  /\/\.pgpass$/,
  /\.credentials\.ya?ml/,
  /\/\.env(\.|$)/,
  /\/\.docker\/config\.json/,
  /\/\.kube\/config/,
  /\/\.config\/gcloud\//,
  /\/\.azure\//,
  /id_rsa\b/,
  /id_ed25519\b/,
  /authorized_keys\b/,
];

/** Process environment variable names that hold secrets. */
const SECRET_ENV_VARS = /^(?:.*_)?(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY)$/i;

/**
 * Scan a value (recursively) for secret patterns.
 * @param {unknown} value - value to scan.
 * @returns {Array<{label: string, snippet: string}>} findings.
 */
export function scanForSecrets(value) {
  const findings = [];
  const seen = new WeakSet();

  function walk(val, path) {
    if (val === null || val === undefined) return;
    if (typeof val === 'string') {
      for (const { pattern, label } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(val)) !== null) {
          // Redact in snippet
          const start = Math.max(0, match.index - 4);
          const end = Math.min(val.length, match.index + match[0].length + 4);
          const snippet = val.slice(start, end).replace(match[0], '[REDACTED]');
          findings.push({ label, snippet: `...${snippet}...` });
        }
      }
    } else if (typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) {
        val.forEach((v, i) => walk(v, `${path}[${i}]`));
      } else {
        for (const [k, v] of Object.entries(val)) {
          // Check if the key name itself is secret-like
          if (SECRET_ENV_VARS.test(k) && typeof v === 'string' && v.length > 4) {
            findings.push({ label: `secret env/field "${k}"`, snippet: '[REDACTED]' });
          }
          walk(v, path ? `${path}.${k}` : k);
        }
      }
    }
  }

  walk(value, '');
  return findings;
}

/**
 * Redact every known secret pattern inside a text string.
 * Used by the post-execute hook to return cleaned output via
 * `{ kind: 'accept', content }` under the v0.2.1 PostToolDecision contract.
 *
 * @param {string} text - text to clean.
 * @returns {{ text: string, found: number, labels: string[] }} cleaned text,
 *   match count, and de-duplicated pattern labels.
 */
export function redactSecretsInText(text) {
  if (typeof text !== 'string' || text === '') return { text: text ?? '', found: 0, labels: [] };
  let out = text;
  let found = 0;
  const labels = [];
  for (const { pattern, label } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    out = out.replace(pattern, (match) => {
      found++;
      if (!labels.includes(label)) labels.push(label);
      return '[REDACTED]';
    });
  }
  return { text: out, found, labels };
}

/**
 * Check whether a file path targets a known credential location.
 * @param {string} filePath
 * @returns {string|null} matched pattern label, or null.
 */
export function isCredentialPath(filePath) {
  for (const pattern of CREDENTIAL_PATHS) {
    if (pattern.test(filePath)) {
      return pattern.source;
    }
  }
  return null;
}

/**
 * Check whether a subprocess command or environment includes secrets.
 * @param {object} spec - subprocess spawn spec.
 * @returns {Array<{label: string, detail: string}>} findings.
 */
export function scanSubprocessForCredentials(spec) {
  const findings = [];

  // Check argv for secret patterns
  const argv = Array.isArray(spec?.argv) ? spec.argv : [];
  const cmdStr = argv.join(' ');
  if (cmdStr) {
    const secretHits = scanForSecrets(cmdStr);
    for (const hit of secretHits) {
      findings.push({ label: hit.label, detail: `in command: ${hit.snippet}` });
    }
  }

  // Check for credential file access in the command
  for (const arg of argv) {
    if (typeof arg === 'string') {
      const credPath = isCredentialPath(arg);
      if (credPath) {
        findings.push({ label: 'credential file access', detail: `command references ${arg}` });
      }
    }
  }

  // Check environment variables being passed
  const env = spec?.env;
  if (env && typeof env === 'object') {
    for (const [key, val] of Object.entries(env)) {
      if (SECRET_ENV_VARS.test(key)) {
        findings.push({ label: 'secret in subprocess env', detail: `env var ${key} exposed to child process` });
      }
    }
  }

  return findings;
}
