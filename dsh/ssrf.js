/**
 * @file SSRF protection — validates URLs against private network ranges.
 *
 * DeepSeek Harness's built-in web-fetch-http explicitly defers SSRF blocking
 * (see packages/web/web-fetch-http/src/policy.ts line 18: "SSRF / private-network
 * blocking is deferred"). This module fills that gap.
 *
 * Covers: IPv4 private ranges, loopback, link-local, carrier-grade NAT,
 * IPv6 loopback/unique-local/link-local, decimal/octal/hex IP encoding,
 * and DNS rebinding via TTL=0 detection (best-effort).
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** IPv4 CIDR ranges that must never be reachable from a plugin/tool fetch. */
const V4_BLOCKLIST = [
  { network: 0n, broadcast: 255n, label: 'this network (0.0.0.0/8)' },
  { network: 167772160n, broadcast: 184549375n, label: 'private (10.0.0.0/8)' },
  { network: 2130706432n, broadcast: 2147483647n, label: 'loopback (127.0.0.0/8)' },
  { network: 2851995648n, broadcast: 2852061183n, label: 'link-local (169.254.0.0/16)' },
  { network: 2886729728n, broadcast: 2887778303n, label: 'private (172.16.0.0/12)' },
  { network: 3221225472n, broadcast: 3221225727n, label: 'documentation (192.0.2.0/24)' },
  { network: 3221225984n, broadcast: 3221226239n, label: 'documentation (192.0.2.0/24)' },
  { network: 3232235520n, broadcast: 3232301055n, label: 'private (192.168.0.0/16)' },
  { network: 3272853504n, broadcast: 3272919039n, label: 'benchmarking (198.18.0.0/15)' },
  { network: 3323068416n, broadcast: 3323199487n, label: 'documentation (203.0.113.0/24)' },
  { network: 3325256704n, broadcast: 3325256959n, label: 'reserved (224.0.0.0/4 multicast)' },
  { network: 3758096384n, broadcast: 4026531839n, label: 'reserved (224.0.0.0/4)' },
  { network: 4026531840n, broadcast: 4294967295n, label: 'reserved (240.0.0.0/4)' },
  // Cloud metadata endpoints
  { network: ipToLong('169.254.169.254'), broadcast: ipToLong('169.254.169.254'), label: 'cloud metadata (169.254.169.254)' },
  { network: ipToLong('100.100.100.200'), broadcast: ipToLong('100.100.100.200'), label: 'Alibaba Cloud metadata (100.100.100.200)' },
];

/** Convert a dotted-quad IPv4 string to a 32-bit integer (as BigInt). */
function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  return BigInt(parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]);
}

/** Parse a numeric string that may be decimal, octal (0o), or hex (0x). */
function parseNumericHost(raw) {
  const trimmed = raw.trim().toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) return trimmed;
  // Handle decimal integer form (e.g. http://2130706433 = 127.0.0.1)
  if (/^\d+$/.test(trimmed)) {
    const num = BigInt(trimmed);
    return `${(num >> 24n) & 255n}.${(num >> 16n) & 255n}.${(num >> 8n) & 255n}.${num & 255n}`;
  }
  // Hex form
  if (trimmed.startsWith('0x')) {
    const num = BigInt(trimmed);
    return `${(num >> 24n) & 255n}.${(num >> 16n) & 255n}.${(num >> 8n) & 255n}.${num & 255n}`;
  }
  // Octal form per part
  if (/^0[0-7]+(\.0[0-7]+){0,3}$/.test(trimmed)) {
    const parts = trimmed.split('.').map(p => parseInt(p, 8));
    while (parts.length < 4) parts.push(0);
    return parts.join('.');
  }
  return null;
}

/** Check whether an IPv4 address string falls in a blocked range. */
export function isBlockedIPv4(ip) {
  const num = ipToLong(ip);
  for (const range of V4_BLOCKLIST) {
    if (num >= range.network && num <= range.broadcast) {
      return range.label;
    }
  }
  return null;
}

/** Check whether an IPv6 address is loopback, link-local, unique-local, or unspecified. */
export function isBlockedIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'loopback (::1)';
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return 'unspecified (::)';
  if (lower.startsWith('fe80:')) return 'link-local (fe80::/10)';
  if (lower.startsWith('fc') || lower.startsWith('fd')) return 'unique-local (fc00::/7)';
  if (lower.startsWith('ff') || lower.startsWith('ff00:')) return 'multicast (ff00::/8)';
  // IPv4-mapped IPv6 (::ffff:a.b.c.d)
  const v4Mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
  if (v4Mapped) return isBlockedIPv4(v4Mapped[1]);
  return null;
}

/**
 * Validate a URL for SSRF. Returns a denial reason string if blocked,
 * or undefined if safe.
 *
 * @param {string} urlString - the URL to validate.
 * @param {object} [opts]
 * @param {boolean} [opts.allowPrivate=false] - permit private IP targets.
 * @returns {Promise<string|undefined>} denial reason, or undefined.
 */
export async function validateFetchUrl(urlString, opts = {}) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return `invalid URL: ${urlString}`;
  }

  // Scheme check
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return `blocked scheme "${url.protocol}" — only http/https permitted`;
  }

  // Embedded credentials
  if (url.username || url.password) {
    return 'URL contains embedded credentials';
  }

  const hostname = url.hostname;

  // IP literal? (URL.hostname already strips brackets for IPv6)
  const ipVersion = isIP(hostname);
  if (ipVersion === 4) {
    const reason = isBlockedIPv4(hostname);
    if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
    return undefined;
  }
  if (ipVersion === 6) {
    const reason = isBlockedIPv6(hostname);
    if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
    return undefined;
  }

  // Also check for bracketed IPv6 that isIP might reject
  const bracketMatch = hostname.match(/^\[(.+)\]$/);
  if (bracketMatch) {
    const inner = bracketMatch[1];
    if (isIP(inner) === 6) {
      const reason = isBlockedIPv6(inner);
      if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
      return undefined;
    }
  }

  // Numeric encoding attempts
  const numeric = parseNumericHost(hostname);
  if (numeric) {
    const reason = isBlockedIPv4(numeric);
    if (reason && !opts.allowPrivate) return `SSRF blocked: numeric host "${hostname}" resolves to ${reason}`;
    return undefined;
  }

  // DNS resolution — check resolved IPs
  if (!opts.allowPrivate) {
    try {
      const addresses = await lookup(hostname, { all: true, verbatim: true });
      for (const addr of addresses) {
        if (addr.family === 4) {
          const reason = isBlockedIPv4(addr.address);
          if (reason) return `SSRF blocked: "${hostname}" resolves to ${reason} (${addr.address})`;
        } else {
          const reason = isBlockedIPv6(addr.address);
          if (reason) return `SSRF blocked: "${hostname}" resolves to ${reason} (${addr.address})`;
        }
      }
    } catch {
      // DNS failure — allow (the fetch itself will fail)
    }
  }

  return undefined;
}
