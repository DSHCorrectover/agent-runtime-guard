/**
 * @file Prompt injection detection — identifies injection attempts in tool inputs.
 *
 * Detects patterns commonly used in indirect prompt injection:
 *  - "ignore previous instructions" / "disregard" / "forget"
 *  - Role override ("you are now", "system:")
 *  - Instruction leakage ("reveal your system prompt")
 *  - Markup/comment-based injection in fetched content
 *  - Encoded/obfuscated injection attempts
 */

const INJECTION_PATTERNS = [
  // Direct instruction override
  { pattern: /\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|above|all)\b.{0,20}\b(?:instruction|prompt|rule|system|context)/i, weight: 5, label: 'instruction override' },
  { pattern: /\b(?:ignore|disregard|forget)\b.{0,20}\b(?:all|previous|prior|above)/i, weight: 4, label: 'instruction override attempt' },

  // Role/system override
  { pattern: /\b(?:you are now|you're now|new (?:persona|role|identity)|act as|pretend (?:to be|you are))\b/i, weight: 4, label: 'role override attempt' },
  { pattern: /\b(?:system|assistant|developer)\s*:\s*(?:you|ignore|new|override|do not)/i, weight: 4, label: 'fake role marker' },
  { pattern: /\[(?:SYSTEM|ADMIN|OVERRIDE|INSTRUCTION)\]/i, weight: 5, label: 'fake system/override tag' },

  // Prompt exfiltration
  { pattern: /\b(?:reveal|show|print|leak|expose|dump|output|repeat)\b.{0,30}\b(?:system|initial|original|developer|hidden)\b.{0,20}\b(?:prompt|instruction|message|rule)/i, weight: 5, label: 'prompt exfiltration attempt' },
  { pattern: /\b(?:what are|what were|tell me)\b.{0,20}\b(?:your|the)\b.{0,20}\b(?:instruction|rule|system prompt|developer message)/i, weight: 3, label: 'prompt probing' },

  // HTML/XML comment injection (in fetched web content)
  { pattern: /<!--[\s\S]{0,200}(?:ignore|system|instruction|assistant|secret|password|token|key)/i, weight: 3, label: 'hidden comment injection' },
  { pattern: /<(?:script|meta|template)[^>]*>[\s\S]{0,200}(?:ignore|instruction|system|assistant)/i, weight: 3, label: 'markup-based injection' },

  // Markdown image-based exfiltration
  { pattern: /!\[[^\]]{0,100}\]\s*\(\s*https?:\/\/[^\s)]{10,}/i, weight: 2, label: 'markdown image (potential data exfil via URL)' },

  // Unicode/bidi tricks
  { pattern: /[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/, weight: 2, label: 'invisible/override Unicode character' },

  // Base64-encoded instructions
  { pattern: /(?:decode|base64|atob|btoa)\s*\(?['"`][A-Za-z0-9+/=]{20,}/i, weight: 3, label: 'encoded payload reference' },

  // Social engineering urgency
  { pattern: /\b(?:urgent|emergency|critical|immediately)\b.{0,30}\b(?:must|need to|have to|do it now|no questions)/i, weight: 1, label: 'urgency/social engineering' },
];

/**
 * Scan text for prompt injection patterns.
 * @param {string} text - the text to scan.
 * @param {object} [opts]
 * @param {number} [opts.threshold=6] - total weight to trigger block.
 * @returns {{ score: number, hits: Array<{label: string, weight: number, snippet: string}>, blocked: boolean, reason?: string }}
 */
export function detectInjection(text, opts = {}) {
  if (!text || typeof text !== 'string') return { score: 0, hits: [], blocked: false };

  const threshold = opts.threshold ?? 6;
  const hits = [];
  let score = 0;

  for (const { pattern, weight, label } of INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    if (match) {
      score += weight;
      const start = Math.max(0, match.index - 20);
      const end = Math.min(text.length, match.index + match[0].length + 20);
      hits.push({ label, weight, snippet: text.slice(start, end).trim() });
    }
  }

  const blocked = score >= threshold;
  return {
    score,
    hits,
    blocked,
    reason: blocked ? `prompt injection detected (score ${score} ≥ ${threshold}): ${hits.map(h => h.label).join(', ')}` : undefined,
  };
}
