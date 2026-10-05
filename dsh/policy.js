/**
 * @file CCS policy engine — combines all detectors into a unified decision.
 *
 * The 7 CCS dimensions enforced at runtime:
 *  1. Structure  — tool call arguments match declared JSON Schema
 *  2. Schema     — input/output types are well-formed
 *  3. Latency    — call duration within budget (observability only)
 *  4. Cost       — token/API cost within budget (observability only)
 *  5. Identity   — caller and tool identity are known and trusted
 *  6. Integrity  — no prompt injection, no credential exfiltration
 *  7. Security   — no SSRF, command injection, path traversal, destructive ops
 */

import { validateFetchUrl } from './ssrf.js';
import { scanForSecrets, isCredentialPath, scanSubprocessForCredentials } from './credentials.js';
import { detectInjection } from './injection.js';
import { inspectSpawn } from './cmdi.js';

/** Default policy configuration. */
export const DEFAULT_POLICY = {
  // Dimension 7: Security
  ssrf: { enabled: true, allowPrivate: false },
  commandInjection: { enabled: true, threshold: 6 },
  credentialExfil: { enabled: true },
  pathTraversal: { enabled: true, blockedPaths: ['/etc/shadow', '/etc/passwd', '/etc/sudoers'] },
  destructiveTools: {
    enabled: true,
    // Tool names that require explicit approval (case-insensitive substring match)
    requireApproval: [
      'execute_payment', 'pay', 'transfer', 'send_transaction',
      'delete', 'drop', 'truncate', 'destroy', 'rm',
      'deploy', 'apply', 'push', 'merge',
      'revoke', 'disable', 'shutdown', 'terminate',
    ],
  },

  // Dimension 6: Integrity
  promptInjection: { enabled: true, threshold: 6 },

  // Dimension 5: Identity
  requireToolAnnotations: { enabled: false }, // warn-only by default

  // Observability (dimensions 3, 4)
  latencyBudgetMs: 30000,
  costBudgetTokens: 100000,

  // Output scanning
  scanOutput: { enabled: true, maxScanLength: 100000 },

  // Allowlist for safe tools (skip deep scanning)
  safeToolAllowlist: [],
};

/**
 * Deep-merge user config with defaults.
 */
function mergeConfig(defaults, user) {
  if (!user) return structuredClone(defaults);
  const out = structuredClone(defaults);
  for (const [k, v] of Object.entries(user)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && k in out && typeof out[k] === 'object') {
      out[k] = mergeConfig(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Check for path traversal in string arguments.
 */
function checkPathTraversal(args, blockedPaths) {
  const findings = [];
  const seen = new WeakSet();

  function walk(val) {
    if (typeof val === 'string') {
      // Directory traversal
      if (val.includes('../') || val.includes('..\\')) {
        // Check if it targets a blocked absolute path
        for (const blocked of blockedPaths) {
          if (val.includes(blocked) || val.endsWith(blocked)) {
            findings.push(`path traversal targeting ${blocked}: ${val.slice(0, 100)}`);
          }
        }
        // Even without a specific target, flag obvious traversal
        if (/\.\.\/(?:etc|root|home|var|usr|proc|sys)\//.test(val)) {
          findings.push(`directory traversal to system path: ${val.slice(0, 100)}`);
        }
      }
      // Absolute sensitive paths
      if (/^\/(?:etc\/shadow|etc\/passwd|etc\/sudoers|root\/\.ssh)/.test(val)) {
        findings.push(`direct access to sensitive path: ${val}`);
      }
    } else if (val && typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) val.forEach(walk);
      else Object.values(val).forEach(walk);
    }
  }

  walk(args);
  return findings;
}

/**
 * Determine whether a tool name matches the destructive list.
 */
function isDestructive(toolName, requireApproval) {
  const lower = toolName.toLowerCase();
  return requireApproval.some(d => lower.includes(d.toLowerCase()));
}

/**
 * Evaluate a tool call against the CCS policy.
 *
 * @param {object} call - { name, arguments, agent? }
 * @param {object} [userConfig] - policy overrides.
 * @returns {Promise<{ allow: boolean, reason?: string, warnings: string[], dimension: string }>}
 */
export async function evaluateToolCall(call, userConfig) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];
  const { name, arguments: args } = call;

  // Skip deep scanning for allowlisted safe tools
  if (config.safeToolAllowlist.includes(name)) {
    return { allow: true, warnings, dimension: 'allowlist' };
  }

  // Dimension 7: Destructive tool check
  if (config.destructiveTools.enabled && isDestructive(name, config.destructiveTools.requireApproval)) {
    return {
      allow: false,
      reason: `[CCS/Security] destructive tool "${name}" requires explicit human approval (auto-approve is blocked by CCS policy)`,
      warnings,
      dimension: 'Security',
    };
  }

  // Scan string arguments for various threats
  const argStrings = [];
  const seen = new WeakSet();
  function collectStrings(val) {
    if (typeof val === 'string') argStrings.push(val);
    else if (val && typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) val.forEach(collectStrings);
      else Object.values(val).forEach(collectStrings);
    }
  }
  collectStrings(args);

  // Dimension 7: SSRF — check URL arguments
  if (config.ssrf.enabled) {
    for (const str of argStrings) {
      if (/^https?:\/\//i.test(str)) {
        const ssrfReason = await validateFetchUrl(str, { allowPrivate: config.ssrf.allowPrivate });
        if (ssrfReason) {
          return { allow: false, reason: `[CCS/Security] ${ssrfReason}`, warnings, dimension: 'Security' };
        }
      }
    }
  }

  // Dimension 7: Command injection — check arguments that look like commands
  if (config.commandInjection.enabled) {
    for (const str of argStrings) {
      if (str.length > 5000) continue; // skip very long strings (likely data, not commands)
      // Only scan strings that look like they could contain shell commands
      if (/[;&|`$]|\b(?:curl|wget|bash|sh|nc|python|perl|ruby|chmod|rm)\b/.test(str)) {
        const result = inspectSpawn({ command: str }, config.commandInjection.threshold);
        if (result.blocked) {
          return { allow: false, reason: `[CCS/Security] ${result.reason}`, warnings, dimension: 'Security' };
        }
      }
    }
  }

  // Dimension 7: Credential exfiltration
  if (config.credentialExfil.enabled) {
    const secrets = scanForSecrets(args);
    if (secrets.length > 0) {
      // If the tool is network-facing (fetch, request, send), block
      const networkFacing = /^(fetch|request|web|http|send|post|put|upload|curl|api_call|call)/i.test(name);
      if (networkFacing) {
        return {
          allow: false,
          reason: `[CCS/Security] credential pattern detected in network-facing tool "${name}" arguments: ${secrets.map(s => s.label).join(', ')}`,
          warnings,
          dimension: 'Security',
        };
      }
      // For non-network tools, warn only
      warnings.push(`credential pattern detected: ${secrets.map(s => s.label).join(', ')}`);
    }

    // Check for credential file paths
    for (const str of argStrings) {
      const credPath = isCredentialPath(str);
      if (credPath) {
        const readTool = /^(read|cat|get|fetch|open|load|view|show|list)/i.test(name);
        if (readTool) {
          return {
            allow: false,
            reason: `[CCS/Security] tool "${name}" attempting to read credential file: ${str}`,
            warnings,
            dimension: 'Security',
          };
        }
        warnings.push(`credential file path referenced: ${str}`);
      }
    }
  }

  // Dimension 7: Path traversal
  if (config.pathTraversal.enabled) {
    const traversal = checkPathTraversal(args, config.pathTraversal.blockedPaths);
    if (traversal.length > 0) {
      return {
        allow: false,
        reason: `[CCS/Security] path traversal detected: ${traversal[0]}`,
        warnings,
        dimension: 'Security',
      };
    }
  }

  // Dimension 6: Prompt injection — scan all string arguments concatenated
  if (config.promptInjection.enabled) {
    const combined = argStrings.join('\n').slice(0, 50000);
    if (combined.length > 10) {
      const injection = detectInjection(combined, { threshold: config.promptInjection.threshold });
      if (injection.blocked) {
        return {
          allow: false,
          reason: `[CCS/Integrity] ${injection.reason}`,
          warnings,
          dimension: 'Integrity',
        };
      }
      if (injection.hits.length > 0) {
        warnings.push(`prompt injection pattern (score ${injection.score}): ${injection.hits.map(h => h.label).join(', ')}`);
      }
    }
  }

  return { allow: true, warnings, dimension: 'pass' };
}

/**
 * Evaluate a tool result/output for credential leakage.
 *
 * @param {object} result - { content?, isError? }
 * @param {object} [userConfig]
 * @returns {{ allow: boolean, reason?: string, warnings: string[] }}
 */
export function evaluateToolResult(result, userConfig) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];

  if (!config.scanOutput.enabled || result.isError) return { allow: true, warnings };

  // Extract text from content blocks
  let text = '';
  if (Array.isArray(result.content)) {
    for (const block of result.content) {
      if (block?.type === 'text' && typeof block.text === 'string') {
        text += block.text + '\n';
      }
    }
  } else if (typeof result.content === 'string') {
    text = result.content;
  }

  if (text.length > config.scanOutput.maxScanLength) {
    text = text.slice(0, config.scanOutput.maxScanLength);
  }

  if (!text) return { allow: true, warnings };

  // Scan output for leaked secrets
  const secrets = scanForSecrets(text);
  if (secrets.length > 0) {
    warnings.push(`output contains credential patterns: ${secrets.map(s => s.label).join(', ')}`);
    // Redact in a future version; for now warn
  }

  // Scan output for injection attempts (fetched web content trying to hijack)
  if (config.promptInjection.enabled) {
    const injection = detectInjection(text, { threshold: config.promptInjection.threshold });
    if (injection.blocked) {
      return {
        allow: false,
        reason: `[CCS/Integrity] tool output contains prompt injection: ${injection.reason}`,
        warnings,
      };
    }
  }

  return { allow: true, warnings };
}

/**
 * Evaluate a subprocess spawn for security violations.
 *
 * @param {object} spec - spawn spec
 * @param {object} [userConfig]
 * @returns {{ allow: boolean, reason?: string, warnings: string[] }}
 */
export function evaluateSubprocess(spec, userConfig) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];

  // Command injection
  if (config.commandInjection.enabled) {
    const result = inspectSpawn(spec, config.commandInjection.threshold);
    if (result.blocked) {
      return { allow: false, reason: `[CCS/Security] ${result.reason}`, warnings };
    }
    if (result.hits.length > 0) {
      warnings.push(`command patterns: ${result.hits.map(h => h.label).join(', ')}`);
    }
  }

  // Credential exposure
  if (config.credentialExfil.enabled) {
    const credFindings = scanSubprocessForCredentials(spec);
    if (credFindings.length > 0) {
      return {
        allow: false,
        reason: `[CCS/Security] credential exposure in subprocess: ${credFindings.map(f => f.label).join(', ')}`,
        warnings,
      };
    }
  }

  // Check argv for URLs (SSRF via subprocess)
  if (config.ssrf.enabled) {
    const argv = Array.isArray(spec?.argv) ? spec.argv : [];
    for (const arg of argv) {
      if (typeof arg === 'string' && /^https?:\/\//i.test(arg)) {
        // Synchronous URL check for common private IP patterns (no DNS lookup in sync path)
        if (/^https?:\/\/(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|localhost|0\.0\.0\.0|\[::1\])/i.test(arg)) {
          return {
            allow: false,
            reason: `[CCS/Security] subprocess targets private/internal network: ${arg}`,
            warnings,
          };
        }
      }
    }
  }

  return { allow: true, warnings };
}
