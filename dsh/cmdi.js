/**
 * @file Command injection detection — inspects subprocess argv and shell strings.
 *
 * Detects:
 *  - Shell metacharacter injection (;, |, &&, ||, backticks, $())
 *  - Reverse shell patterns
 *  - Download-and-execute chains (curl|wget | sh, pip install from URL)
 *  - Obfuscated commands (base64 -d | sh, hex encoding)
 *  - Fileless execution (/dev/tcp, /dev/shm)
 */

const DANGEROUS_PATTERNS = [
  // Shell chaining / injection
  { pattern: /[;&|`$]\s*(?:\$\(|`|sh\b|bash\b|zsh\b|dash\b|python\b|perl\b|ruby\b|node\b)/i, weight: 5, label: 'shell metachar + interpreter' },
  { pattern: /\|\s*(?:sh|bash|zsh|dash|python|perl|ruby|node)\b/i, weight: 6, label: 'pipe to interpreter' },
  { pattern: /`[^`]{2,}`/, weight: 4, label: 'backtick command substitution' },
  { pattern: /\$\([^)]{2,}\)/, weight: 4, label: '$() command substitution' },
  { pattern: /;\s*(?:rm|mv|cp|chmod|chown|curl|wget|nc|bash|sh|python|cat|echo)\b/i, weight: 4, label: 'chained dangerous command' },

  // Reverse shells
  { pattern: /(?:bash|sh|zsh)\s+-i\s*>&?\s*\/dev\/(?:tcp|udp)\//i, weight: 7, label: 'reverse shell (/dev/tcp)' },
  { pattern: /nc\b.{0,40}-e\s+(?:sh|bash|bin\/sh)/i, weight: 7, label: 'netcat reverse shell' },
  { pattern: /ncat\b.{0,40}-e\s+(?:sh|bash)/i, weight: 7, label: 'ncat reverse shell' },
  { pattern: /python.{0,60}socket.{0,40}(?:connect|send|recv)/i, weight: 6, label: 'python reverse shell' },

  // Download-and-execute
  { pattern: /(?:curl|wget)\b[^|;]{0,100}\|\s*(?:sh|bash|zsh|python|perl)/i, weight: 6, label: 'download-and-execute' },
  { pattern: /(?:curl|wget)\b[^|;]{0,200}(?:-o|--output)[^|;]{0,60}(?:\/tmp|\/dev\/shm|\/var\/tmp)/i, weight: 4, label: 'download to temp (possible staging)' },

  // Fileless / memory-only
  { pattern: /\/dev\/(?:tcp|udp)\//i, weight: 5, label: '/dev/tcp or /dev/udp (network socket)' },
  { pattern: /\/dev\/shm\//i, weight: 2, label: '/dev/shm (tmpfs, no disk trace)' },

  // Obfuscation
  { pattern: /base64\s+(?:-d|--decode)\s*\|?\s*(?:sh|bash|python|perl|eval)/i, weight: 6, label: 'base64 decode + execute' },
  { pattern: /xxd\s+-p?\s*-r?\s*\|?\s*(?:sh|bash)/i, weight: 5, label: 'hex decode + execute' },
  { pattern: /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/, weight: 3, label: 'hex-encoded characters' },
  { pattern: /\$\{IFS\}/, weight: 4, label: '${IFS} obfuscation' },
  { pattern: /\$\{PATH:[\d:]+}/, weight: 4, label: 'PATH substring obfuscation' },

  // Destructive
  { pattern: /\brm\s+-[rf]+\s+(?:\/|~|\*|\.\.|\/\*|~\/\*)/i, weight: 7, label: 'destructive rm (root/home/glob)' },
  { pattern: /\bmkfs\b/, weight: 7, label: 'mkfs (filesystem format)' },
  { pattern: /\bdd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\//i, weight: 7, label: 'dd to device' },
  { pattern: /:\(\)\s*{\s*:\s*\|\s*:\s*&\s*};/, weight: 7, label: 'fork bomb' },

  // Persistence
  { pattern: /(?:>>|>)\s*(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile)/i, weight: 5, label: 'shell profile modification (persistence)' },
  { pattern: /(?:chmod|chown)\s+[0-7]*777/, weight: 2, label: 'chmod 777 (overly permissive)' },

  // Credential theft
  { pattern: /cat\s+(?:~\/)?\.ssh\/id_rsa/, weight: 7, label: 'SSH private key read' },
  { pattern: /cat\s+(?:~\/)?\.aws\/credentials/, weight: 7, label: 'AWS credentials read' },
  { pattern: /(?:env|printenv)\s*\|/, weight: 3, label: 'environment dump piped' },
];

/**
 * Scan a command string for injection patterns.
 * @param {string} command
 * @param {number} [threshold=8]
 * @returns {{ score: number, hits: Array<{label: string, weight: number}>, blocked: boolean, reason?: string }}
 */
export function detectCommandInjection(command, threshold = 6) {
  if (!command || typeof command !== 'string') return { score: 0, hits: [], blocked: false };

  let score = 0;
  const hits = [];

  for (const { pattern, weight, label } of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(command)) {
      score += weight;
      hits.push({ label, weight });
    }
  }

  const blocked = score >= threshold;
  return {
    score,
    hits,
    blocked,
    reason: blocked ? `command injection detected (score ${score} ≥ ${threshold}): ${hits.map(h => h.label).join(', ')}` : undefined,
  };
}

/**
 * Inspect a subprocess spawn spec for dangerous commands.
 * @param {object} spec - spawn spec with argv and/or command.
 * @param {number} [threshold]
 * @returns {{ score: number, hits: Array<{label: string, weight: number}>, blocked: boolean, reason?: string }}
 */
export function inspectSpawn(spec, threshold = 6) {
  const argv = Array.isArray(spec?.argv) ? spec.argv : [];
  const command = typeof spec?.command === 'string' ? spec.command : '';
  // Join argv into a string for pattern matching
  const combined = command || argv.join(' ');
  return detectCommandInjection(combined, threshold);
}
