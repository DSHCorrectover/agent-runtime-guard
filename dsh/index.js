/**
 * @file correctover/dsh — DeepSeek Harness runtime security guard.
 *
 * CCS (Correctover Conformance Shape) is a 7-dimension runtime verification
 * standard for AI agents. This DSH plugin enforces security dimensions at
 * the tool-call, subprocess, and fetch boundaries — not by static scanning
 * plugin source files, but by inspecting every runtime operation before it
 * executes.
 *
 * v1.1.0 — adapted to DeepSeek Harness host v0.2.1-alpha.1 event contract:
 *  - `tools/pre-execute` is a WATERFALL: listener `(exec, next)`. Pass-through
 *    MUST `return next(exec)`; only a confirmed hit short-circuits with a deny.
 *  - `tools/post-execute` is a WATERFALL: listener `(exec, result, next)`.
 *    Pass-through MUST `return next(exec, result)`; redacted outputs are
 *    returned as `{ kind: 'accept', content }`; blocks use `{kind:'block'}`.
 *  - SSRF main line: native-tool-name audit of `web_fetch` arguments.url.
 *  - Command-injection main line: native-tool-name audit of `bash`
 *    arguments.command. The subprocess.spawn wrapper remains as
 *    defense-in-depth only.
 *  - No global-state side effects (globalThis.__dshCcsCtx removed).
 *
 * Registers:
 *  - `ccs_status` model tool: report current policy and stats
 *  - `ccs_audit` model tool: run a security audit on installed plugins
 *  - tools/pre-execute hook: block dangerous tool calls
 *  - tools/post-execute hook: scan outputs for leaked secrets / injection
 *  - subprocess spawn wrapper (defense-in-depth): block command injection
 *  - optional registerFetchProvider wrapper (defense-in-depth): block SSRF
 *
 * @module correctover/dsh
 */

import { homedir } from 'node:os';
import { existsSync, readdirSync, readFileSync, mkdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { evaluateToolCall, evaluateSubprocess, DEFAULT_POLICY } from './policy.js';
import { scanForSecrets, isCredentialPath, redactSecretsInText } from './credentials.js';
import { detectInjection } from './injection.js';
import { inspectSpawn } from './cmdi.js';
import { validateFetchUrl } from './ssrf.js';

const name = 'correctover-dsh';
const inject = ['tools'];

const VERSION = '1.1.0';

// Native v0.2.1 tool names / argument locations (authoritative contract).
const NATIVE_BASH = 'bash';                 // args.command (+description/workdir/run_in_background)
const NATIVE_WEB_FETCH = 'web_fetch';       // args.url
const NATIVE_WEB_SEARCH = 'web_search';     // args.queries (array) — generic policy path
const NATIVE_RUN_CODE = 'run_code';         // PTC mode tool — generic policy path

// ── State ────────────────────────────────────────────────────────────────

let stats = {
  toolCallsChecked: 0,
  toolCallsBlocked: 0,
  toolResultsScanned: 0,
  outputsRedacted: 0,
  subprocessesChecked: 0,
  subprocessesBlocked: 0,
  fetchCallsChecked: 0,
  fetchCallsBlocked: 0,
  secretsDetected: 0,
  injectionAttempts: 0,
  internalErrors: 0,
  blockReasons: [],
};

let config = structuredClone(DEFAULT_POLICY);
let logFile;
let ctxLogger;

function resolveDshHome() {
  return process.env.DSH_HOME ?? join(homedir(), '.dsh');
}

function initLog() {
  const logDir = join(resolveDshHome(), '.correctover-dsh');
  try {
    mkdirSync(logDir, { recursive: true });
    logFile = join(logDir, 'security.log');
  } catch {
    logFile = undefined;
  }
}

function log(level, message, detail) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    message,
    ...detail && { detail },
  });
  if (logFile) {
    try { appendFileSync(logFile, entry + '\n', 'utf8'); } catch { /* best-effort */ }
  }
  if (ctxLogger?.[level]) {
    try { ctxLogger[level](`[ccs] ${message}`); } catch { /* best-effort */ }
  }
}

function recordBlock(reason) {
  stats.toolCallsBlocked++;
  stats.blockReasons.push({ ts: new Date().toISOString(), reason: reason.slice(0, 200) });
  if (stats.blockReasons.length > 50) stats.blockReasons.shift();
  log('warn', 'blocked', { reason: reason.slice(0, 500) });
}

// ── Tool definitions ─────────────────────────────────────────────────────

const STATUS_TOOL = {
  name: 'ccs_status',
  description: 'Report CCS runtime security guard status: policy configuration, cumulative block/scan statistics, and recent security events. Use this to verify CCS is active and review what has been blocked.',
  parameters: { type: 'object', properties: {} },
  output: {
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        active: { type: 'boolean' },
        version: { type: 'string' },
        policy: { type: 'object' },
        stats: { type: 'object' },
        recentBlocks: { type: 'array', items: { type: 'object' } },
      },
    },
    render: (_args, value) => {
      const lines = [
        '# CCS Runtime Security Guard',
        '',
        `**Status**: ${value.active ? 'ACTIVE / 运行中' : 'INACTIVE'}`,
        `**Version**: ${value.version}`,
        '',
        '## Statistics / 统计',
        '',
        `- Tool calls checked: ${value.stats.toolCallsChecked}`,
        `- Tool calls blocked: ${value.stats.toolCallsBlocked}`,
        `- Tool results scanned: ${value.stats.toolResultsScanned}`,
        `- Outputs redacted: ${value.stats.outputsRedacted}`,
        `- Subprocesses checked: ${value.stats.subprocessesChecked}`,
        `- Subprocesses blocked: ${value.stats.subprocessesBlocked}`,
        `- Fetch calls checked: ${value.stats.fetchCallsChecked}`,
        `- Fetch calls blocked: ${value.stats.fetchCallsBlocked}`,
        `- Secrets detected: ${value.stats.secretsDetected}`,
        `- Injection attempts: ${value.stats.injectionAttempts}`,
        `- Internal errors (fail-open): ${value.stats.internalErrors}`,
      ];
      if (value.recentBlocks.length > 0) {
        lines.push('', '## Recent Blocks / 最近拦截', '');
        for (const b of value.recentBlocks.slice(-10)) {
          lines.push(`- [${b.ts}] ${b.reason}`);
        }
      }
      return [{ type: 'text', text: lines.join('\n') }];
    },
  },
  async execute() {
    return {
      active: true,
      version: VERSION,
      policy: {
        ssrf: config.ssrf,
        commandInjection: config.commandInjection,
        credentialExfil: config.credentialExfil,
        promptInjection: config.promptInjection,
        destructiveTools: { enabled: config.destructiveTools.enabled, requireApprovalCount: config.destructiveTools.requireApproval.length },
      },
      stats: { ...stats },
      recentBlocks: stats.blockReasons.slice(-10),
    };
  },
};

const AUDIT_TOOL = {
  name: 'ccs_audit',
  description: 'Run a CCS security audit on installed DSH plugins. Scans plugin source for credential access patterns, command injection risks, and network exfiltration indicators — with runtime-intent analysis (not just keyword matching). Returns per-plugin risk assessment.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Optional path to scan. Defaults to all profiles under $DSH_HOME/profiles.' },
    },
  },
  output: {
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        scanned: { type: 'number' },
        plugins: { type: 'array', items: { type: 'object' } },
        summary: { type: 'object' },
      },
    },
    render: (_args, value) => {
      const lines = [
        `# CCS Plugin Audit — ${value.scanned} plugin(s) scanned`,
        '',
        `High: ${value.summary.high}  Medium: ${value.summary.medium}  Low: ${value.summary.low}  Safe: ${value.summary.safe}`,
      ];
      for (const p of value.plugins) {
        lines.push('', `## [${p.risk}] ${p.name}@${p.version}`, '');
        for (const f of p.findings.slice(0, 8)) {
          lines.push(`- **${f.severity}** ${f.category}: ${f.detail}`);
        }
      }
      return [{ type: 'text', text: lines.join('\n') }];
    },
  },
  async execute(args) {
    const roots = [];
    if (args?.path) {
      roots.push(args.path);
    } else {
      const profiles = join(resolveDshHome(), 'profiles');
      if (existsSync(profiles)) {
        for (const entry of readdirSync(profiles, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue;
          const nm = join(profiles, entry.name, 'node_modules');
          if (existsSync(nm)) roots.push(nm);
        }
      }
    }

    const plugins = [];
    const summary = { high: 0, medium: 0, low: 0, safe: 0 };

    for (const root of roots) {
      let entries;
      try { entries = readdirSync(root, { withFileTypes: true }); } catch { continue; }
      for (const entry of entries) {
        if (!entry.isDirectory() && !entry.name.startsWith('@')) continue;
        const pkgDir = join(root, entry.name);
        const pkgJsonPath = join(pkgDir, 'package.json');
        if (!existsSync(pkgJsonPath)) continue;

        let pkg;
        try { pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8')); } catch { continue; }

        // Skip official packages
        if (pkg.name?.startsWith('@deepseek-ai/')) continue;

        const findings = auditPlugin(pkgDir, pkg);
        let risk = 'SAFE';
        const score = findings.reduce((s, f) => s + ({ HIGH: 10, MEDIUM: 5, LOW: 2 }[f.severity] || 0), 0);
        if (score >= 10) { risk = 'HIGH'; summary.high++; }
        else if (score >= 5) { risk = 'MEDIUM'; summary.medium++; }
        else if (score > 0) { risk = 'LOW'; summary.low++; }
        else { summary.safe++; }

        plugins.push({ name: pkg.name || entry.name, version: pkg.version || '0.0.0', risk, findings });
      }
    }

    return { scanned: plugins.length, plugins, summary };
  },
};

/**
 * Audit a single plugin package for security risks.
 * Uses runtime-intent analysis rather than pure keyword matching.
 */
function auditPlugin(pkgDir, pkg) {
  const findings = [];

  // Collect source files
  const sourceFiles = [];
  const SKIP = new Set(['node_modules', '.git', 'dist', '.DS_Store']);
  function walk(dir, depth = 0) {
    if (depth > 5 || sourceFiles.length >= 200) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (sourceFiles.length >= 200) return;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) walk(full, depth + 1);
      } else if (/\.(js|mjs|cjs|ts)$/.test(e.name)) {
        sourceFiles.push(full);
      }
    }
  }
  walk(pkgDir);

  let allSource = '';
  for (const file of sourceFiles) {
    try { allSource += readFileSync(file, 'utf8') + '\n'; } catch { /* skip */ }
  }

  if (!allSource) return findings;

  // Check for network exfiltration capability
  if (/\bfetch\s*\(/.test(allSource) || /\bhttps?\.request\b/.test(allSource) || /\bnet\.connect\b/.test(allSource)) {
    const hasSecrets = scanForSecrets(allSource);
    if (hasSecrets.length > 0) {
      findings.push({ severity: 'HIGH', category: 'data-exfiltration', detail: `makes network requests AND references credential patterns (${hasSecrets.map(s => s.label).join(', ')})` });
    } else {
      findings.push({ severity: 'LOW', category: 'network-access', detail: 'makes outbound network requests' });
    }
  }

  // Check for subprocess execution
  if (/child_process|\bspawn\s*\(|\bexec(Sync)?\s*\(/.test(allSource)) {
    const cmdResult = inspectSpawn({ command: allSource.slice(0, 5000) }, 12);
    if (cmdResult.blocked) {
      findings.push({ severity: 'HIGH', category: 'command-injection', detail: cmdResult.reason });
    } else {
      findings.push({ severity: 'MEDIUM', category: 'subprocess', detail: 'spawns child processes' });
    }
  }

  // Check for dynamic code execution
  if (/\beval\s*\(|new Function\s*\(|vm\.runIn/.test(allSource)) {
    findings.push({ severity: 'HIGH', category: 'code-execution', detail: 'uses dynamic code execution (eval/Function/vm) — runtime behavior cannot be statically determined' });
  }

  // Check for credential file access
  if (/\.ssh\/id_rsa|\.aws\/credentials|\.credentials\.ya?ml|\.netrc|\.pgpass/.test(allSource)) {
    findings.push({ severity: 'HIGH', category: 'credential-access', detail: 'references known credential file paths' });
  }

  // Check for env credential reads
  if (/process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'credential-access', detail: 'reads credential-like environment variables' });
  }

  // Check for prompt injection patterns in source
  const injection = detectInjection(allSource.slice(0, 10000), { threshold: 10 });
  if (injection.blocked) {
    findings.push({ severity: 'MEDIUM', category: 'prompt-injection', detail: `source contains injection-like patterns: ${injection.hits.map(h => h.label).join(', ')}` });
  }

  // Check for persistence mechanisms
  if (/\.bashrc|\.zshrc|\.profile|authorized_keys|schtasks|cron/.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'persistence', detail: 'references persistence mechanisms' });
  }

  // Check for obfuscation
  if (/String\.fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}/.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'obfuscation', detail: 'uses obfuscation techniques' });
  }

  // Check npm lifecycle scripts
  if (pkg.scripts) {
    const lifecycle = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublishOnly'];
    for (const hook of lifecycle) {
      if (pkg.scripts[hook]) {
        findings.push({ severity: 'LOW', category: 'supply-chain', detail: `has "${hook}" lifecycle script: ${pkg.scripts[hook].slice(0, 100)}` });
      }
    }
  }

  return findings;
}

// ── Native-tool-name auditors (v0.2.1 main defense lines) ────────────────

/**
 * Audit a native `bash` tool call by its arguments.command.
 * Unlike the generic policy (which only deep-runs cmdi patterns when a loose
 * gate matches), this always runs the full pattern set against the command,
 * checks credential locations/patterns, and fully (DNS-aware) validates every
 * http(s) URL embedded in the command.
 *
 * @returns {Promise<{allow: boolean, reason?: string, warnings: string[]}>}
 */
async function auditBashCall(args) {
  const warnings = [];
  const command = typeof args?.command === 'string' ? args.command : '';
  if (!command) return { allow: true, warnings };

  // 1. Command injection / dangerous commands — full pattern set, no gate.
  if (config.commandInjection.enabled) {
    const result = inspectSpawn({ argv: [command] }, config.commandInjection.threshold);
    if (result.blocked) {
      return { allow: false, reason: `[CCS/Security] ${result.reason}`, warnings };
    }
    if (result.hits.length > 0) {
      warnings.push(`command patterns (score ${result.score}): ${result.hits.map(h => h.label).join(', ')}`);
    }
  }

  // 2. Credential file locations and secret patterns inside the command.
  if (config.credentialExfil.enabled) {
    if (isCredentialPath(command)) {
      return { allow: false, reason: `[CCS/Security] bash command accesses a credential location: ${command.slice(0, 150)}`, warnings };
    }
    const secrets = scanForSecrets(command);
    if (secrets.length > 0) {
      return { allow: false, reason: `[CCS/Security] credential pattern in bash command: ${secrets.map(s => s.label).join(', ')}`, warnings };
    }
  }

  // 3. SSRF — every URL in the command gets the DNS-aware validator.
  if (config.ssrf.enabled) {
    const urls = command.match(/https?:\/\/[^\s"'`<>|)]+/gi) || [];
    for (const url of urls) {
      const reason = await validateFetchUrl(url, { allowPrivate: config.ssrf.allowPrivate });
      if (reason) {
        return { allow: false, reason: `[CCS/Security] ${reason}`, warnings };
      }
    }
  }

  return { allow: true, warnings };
}

/**
 * Audit a native `web_fetch` tool call by its arguments.url (SSRF main line).
 *
 * @returns {Promise<{allow: boolean, reason?: string, warnings: string[]}>}
 */
async function auditWebFetchCall(args) {
  const warnings = [];
  const url = args?.url;
  if (typeof url !== 'string' || !url) return { allow: true, warnings };

  if (config.ssrf.enabled) {
    const reason = await validateFetchUrl(url, { allowPrivate: config.ssrf.allowPrivate });
    if (reason) {
      return { allow: false, reason: `[CCS/Security] ${reason}`, warnings };
    }
  }

  // Credential patterns in a network-facing call must not leave the host.
  if (config.credentialExfil.enabled) {
    const secrets = scanForSecrets(args);
    if (secrets.length > 0) {
      return { allow: false, reason: `[CCS/Security] credential pattern in web_fetch arguments: ${secrets.map(s => s.label).join(', ')}`, warnings };
    }
  }

  return { allow: true, warnings };
}

/**
 * Extract concatenated text from ContentBlocks for policy scanning.
 */
function contentText(content) {
  let text = '';
  if (Array.isArray(content)) {
    for (const block of content) {
      if (block?.type === 'text' && typeof block.text === 'string') text += block.text + '\n';
    }
  } else if (typeof content === 'string') {
    text = content;
  }
  return text;
}

// ── Plugin apply ─────────────────────────────────────────────────────────

function apply(ctx, userConfig) {
  // Merge user config
  if (userConfig && typeof userConfig === 'object') {
    config = deepMerge(config, userConfig);
  }

  ctxLogger = ctx.logger;
  initLog();
  log('info', `CCS runtime security guard starting (v${VERSION})`);

  // Register tools (output schema/render already conform to v0.2.1 contract)
  ctx.effect(() => ctx.tools.register(STATUS_TOOL), 'ccs: status tool');
  ctx.effect(() => ctx.tools.register(AUDIT_TOOL), 'ccs: audit tool');

  // ── Pre-execute waterfall ─────────────────────────────────────────────
  // Signature: async (exec, next). Only a confirmed dangerous call
  // short-circuits; every other path (including internal errors) continues
  // the chain via next(exec).
  ctx.on('tools/pre-execute', async (exec, next) => {
    stats.toolCallsChecked++;

    try {
      const args = (exec.arguments && typeof exec.arguments === 'object') ? exec.arguments : {};
      let decision;

      if (exec.name === NATIVE_BASH) {
        // Command-injection main line: audit arguments.command by tool name.
        decision = await auditBashCall(args);
      } else if (exec.name === NATIVE_WEB_FETCH) {
        // SSRF main line: audit arguments.url by tool name.
        decision = await auditWebFetchCall(args);
      } else {
        // Everything else (incl. web_search / run_code and third-party
        // tools): generic deep policy evaluation.
        decision = await evaluateToolCall(
          { name: exec.name, arguments: exec.arguments, agent: exec.agent },
          config,
        );
      }

      if (!decision.allow) {
        recordBlock(decision.reason);
        // Intercept: short-circuit is the correct waterfall behavior.
        return { kind: 'deny', reason: decision.reason };
      }

      for (const w of decision.warnings) {
        log('warn', `tool "${exec.name}": ${w}`);
      }

      // Pass-through: MUST delegate down the chain.
      return next(exec);
    } catch (err) {
      // Narrow fail-open: only for the plugin's OWN internal errors.
      // Record the error, then continue the chain — never fabricate an
      // `allow` (which would swallow every downstream listener).
      stats.internalErrors++;
      log('error', `pre-execute evaluation error: ${err?.message || err}`);
      return next(exec);
    }
  });

  // ── Post-execute waterfall ────────────────────────────────────────────
  // Signature: async (exec, result, next). Clean results continue the
  // chain; prompt-injection content is blocked; secrets are redacted and
  // returned via {kind:'accept', content}.
  ctx.on('tools/post-execute', async (exec, result, next) => {
    stats.toolResultsScanned++;

    try {
      if (!result.isError && config.scanOutput.enabled && Array.isArray(result.content)) {
        const maxScan = config.scanOutput.maxScanLength;
        const fullText = contentText(result.content);
        const scanRegion = fullText.slice(0, maxScan);

        // 1. Indirect prompt injection in fetched/tool output → block.
        if (config.promptInjection.enabled) {
          const injection = detectInjection(scanRegion, { threshold: config.promptInjection.threshold });
          if (injection.blocked) {
            stats.injectionAttempts++;
            recordBlock(`output from "${exec.name}": ${injection.reason}`);
            return {
              kind: 'block',
              feedback: [{ type: 'text', text: `[CCS] Tool output blocked: ${injection.reason}` }],
            };
          }
        }

        // 2. Secrets in output → redact per text block, accept with content.
        let redactedCount = 0;
        const redactedLabels = new Set();
        const newContent = result.content.map((block) => {
          if (block?.type !== 'text' || typeof block.text !== 'string') return block;
          const region = block.text.slice(0, maxScan);
          const result2 = redactSecretsInText(region);
          if (result2.found > 0) {
            redactedCount += result2.found;
            for (const l of result2.labels) redactedLabels.add(l);
            return { ...block, text: result2.text + block.text.slice(region.length) };
          }
          return block;
        });

        if (redactedCount > 0) {
          stats.secretsDetected += redactedCount;
          stats.outputsRedacted++;
          log('warn', `redacted ${redactedCount} secret pattern(s) in output from "${exec.name}": ${[...redactedLabels].join(', ')}`);
          // Redacted replacement via the supported accept-with-content path.
          return { kind: 'accept', content: newContent };
        }
      }

      // Clean result: MUST continue the chain.
      return next(exec, result);
    } catch (err) {
      // Narrow fail-open for plugin-internal errors only.
      stats.internalErrors++;
      log('error', `post-execute evaluation error: ${err?.message || err}`);
      return next(exec, result);
    }
  });

  // ── Subprocess spawn wrapper (DEFENSE-IN-DEPTH only) ──────────────────
  // The model's commands mainly run through the native `bash` tool, which is
  // audited in pre-execute above. This patch only covers flows that still
  // go through the subprocess service seam directly.
  const subprocess = ctx.get?.('subprocess');
  if (subprocess && typeof subprocess.spawn === 'function') {
    const originalSpawn = subprocess.spawn;
    ctx.effect(() => {
      subprocess.spawn = (spec) => {
        stats.subprocessesChecked++;

        try {
          const decision = evaluateSubprocess(spec, config);
          if (!decision.allow) {
            stats.subprocessesBlocked++;
            recordBlock(`subprocess: ${decision.reason}`);
            throw new Error(`[CCS] Subprocess blocked: ${decision.reason}`);
          }
          for (const w of decision.warnings) {
            log('warn', `subprocess: ${w}`);
          }
        } catch (err) {
          if (err.message?.startsWith('[CCS]')) throw err;
          stats.internalErrors++;
          log('error', `subprocess evaluation error: ${err?.message || err}`);
        }

        return originalSpawn(spec);
      };
      return () => { subprocess.spawn = originalSpawn; };
    }, 'ccs: subprocess guard');
  }

  // ── Fetch provider wrapper (DEFENSE-IN-DEPTH, best-effort) ────────────
  // The v1 monkey-patch of web.fetch(url, opts) is gone: the real signature
  // is fetch(request: WebFetchRequest, signal?) and patching the service
  // method was fragile. SSRF's main line is the web_fetch pre-execute audit
  // above. We additionally wrap a fetch PROVIDER only when a concrete
  // downstream provider is discoverable, so delegation semantics cannot be
  // guessed at.
  const web = ctx.get?.('web');
  installFetchProviderGuard(web, ctx);

  log('info', `CCS runtime security guard active (v${VERSION})`, {
    hooks: [
      'pre-execute',
      'post-execute',
      ...(subprocess ? ['subprocess'] : []),
      ...(web ? ['web-available'] : []),
    ],
  });
}

/**
 * Best-effort registration of an SSRF-guarded fetch provider.
 *
 * Contract uncertainties in v0.2.1-alpha.1 (exact registerFetchProvider
 * signature and provider-registry shape are not part of the extracted
 * tools source) mean this is deliberately conservative:
 *  - skipped silently if registerFetchProvider is absent;
 *  - skipped unless at least one pre-existing provider is discoverable to
 *    delegate to (we never invent routing semantics);
 *  - all registration failures are contained and logged.
 */
function installFetchProviderGuard(web, ctx) {
  if (!web || typeof web.registerFetchProvider !== 'function') return;

  let delegates;
  try {
    delegates = discoverFetchProviders(web);
  } catch (err) {
    log('warn', `fetch-provider discovery failed, skipping guard: ${err?.message || err}`);
    return;
  }
  if (!delegates || delegates.length === 0) {
    log('info', 'fetch-provider guard not installed: no downstream provider discovered (pre-execute web_fetch audit remains the SSRF main line)');
    return;
  }

  try {
    const guarded = async (request, signal) => {
      const url = request?.url;
      if (typeof url === 'string') {
        stats.fetchCallsChecked++;
        const reason = await validateFetchUrl(url, { allowPrivate: config.ssrf.allowPrivate });
        if (reason) {
          stats.fetchCallsBlocked++;
          recordBlock(`fetch ${url}: ${reason}`);
          const err = new Error(`[CCS] Fetch blocked: ${reason}`);
          err.code = 'CCS_FETCH_BLOCKED';
          throw err;
        }
      }
      return delegates[0](request, signal);
    };

    let disposer;
    // Try plausible registration shapes; the first that doesn't throw wins.
    try {
      disposer = web.registerFetchProvider({ name: 'ccs-ssrf-guard', fetch: guarded });
    } catch {
      disposer = web.registerFetchProvider('ccs-ssrf-guard', { fetch: guarded });
    }
    if (typeof disposer === 'function') {
      ctx.effect(() => disposer, 'ccs: fetch provider guard');
    }
    log('info', 'fetch-provider SSRF guard installed (defense-in-depth)');
  } catch (err) {
    stats.internalErrors++;
    log('error', `registerFetchProvider guard failed: ${err?.message || err}`);
  }
}

/**
 * Discover pre-registered fetch providers across plausible registry shapes.
 * Returns normalized functions (request, signal) => result, possibly empty.
 */
function discoverFetchProviders(web) {
  const out = [];
  const pushAll = (entries) => {
    for (const entry of entries) {
      if (!entry) continue;
      if (typeof entry === 'function') { out.push(entry); continue; }
      if (typeof entry.fetch === 'function') out.push(entry.fetch.bind(entry));
      else if (typeof entry.provide === 'function') out.push(entry.provide.bind(entry));
    }
  };
  for (const key of ['providers', '_providers', 'fetchProviders', '_fetchProviders']) {
    const container = web[key];
    if (Array.isArray(container)) pushAll(container);
    else if (container instanceof Map) pushAll([...container.values()]);
  }
  return out;
}

// ── Helpers ──────────────────────────────────────────────────────────────

function deepMerge(target, source) {
  const out = Array.isArray(target) ? [...target] : { ...target };
  for (const [k, v] of Object.entries(source)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && k in out && typeof out[k] === 'object') {
      out[k] = deepMerge(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export { apply, inject, name, DEFAULT_POLICY };
export { evaluateToolCall } from './policy.js';
export { evaluateSubprocess } from './policy.js';
export { evaluateToolResult } from './policy.js';
export { validateFetchUrl } from './ssrf.js';
export { scanForSecrets, isCredentialPath, redactSecretsInText } from './credentials.js';
export { detectInjection } from './injection.js';
export { inspectSpawn, detectCommandInjection } from './cmdi.js';
