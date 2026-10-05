"use strict";
/**
 * CCS 字段级篡改定位 —— locate_tampering
 *
 * 为什么需要这个（它不是 verify_receipt 的替代品）:
 *   verify_receipt 回一个布尔：签名对不对。审计人员拿到 false 之后
 *   仍然不知道**哪里被改了**。要把话说清楚、要能举证，需要一份差异清单。
 *
 *   本模块产出 RFC 6901 JSON-Pointer 形式的字段变更清单，
 *   每条带变化类型、原值、新值、严重度与整改建议。
 *
 * 与 Python 侧 correctover-ccs-mcp 的 ccs_locate_tampering 输出结构对齐，
 * 使两个渠道（npm 运行时 / PyPI 取证）给出同一份证据格式。
 *
 * 零依赖：仅 crypto 用于可选的内容摘要。
 *
 * License: Elastic-2.0 (c) Correctover
 */

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// RFC 6901 JSON-Pointer 转义
// ---------------------------------------------------------------------------

function pointerEscape(token) {
  // 顺序不可颠倒：必须先转义 ~，否则会把 / 转出来的 ~1 再转一次
  return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

function joinPointer(base, token) {
  return base + "/" + pointerEscape(token);
}

// ---------------------------------------------------------------------------
// 严重度：按字段语义分级，不是按"改了多少字节"
//
// 设计取舍：改一个字符的 verdict 比改一百个字符的 latency 严重得多。
// 分级的依据是**这个字段决定谁的结论**，不是差异大小。
// ---------------------------------------------------------------------------

const CRITICAL_EXACT = [
  "/verdict", "/signature", "/signer_public_key", "/signature_alg",
  "/evidence_hash", "/content_hash", "/receipt_id", "/instruction_digest",
];
const CRITICAL_PREFIX = ["/checks/", "/policy/", "/decision"];
const HIGH_EXACT = [
  "/reason", "/allowed", "/action", "/tool", "/principal", "/subject",
  "/policy_mode", "/delegation",
];
const MEDIUM_PREFIX = ["/latency", "/cost", "/model", "/provider", "/intent"];

function classifySeverity(pointer) {
  if (CRITICAL_EXACT.includes(pointer)) return "critical";
  if (CRITICAL_PREFIX.some((p) => pointer.startsWith(p))) return "critical";
  if (HIGH_EXACT.includes(pointer)) return "high";
  if (MEDIUM_PREFIX.some((p) => pointer.startsWith(p))) return "medium";
  return "low";
}

const REMEDIATION = {
  critical:
    "A verdict-bearing field changed. Treat the artifact as untrusted: do not act on it, " +
    "re-derive the conclusion from the original source, and re-issue the receipt.",
  high:
    "A context field changed. Confirm with the counterparty which version is authoritative " +
    "before relying on either.",
  medium:
    "An operational field changed. Usually affects interpretation rather than the verdict; " +
    "verify if it feeds a downstream decision.",
  low:
    "A non-decisional field changed. Low impact; record for completeness.",
};

// ---------------------------------------------------------------------------
// 深度差异
// ---------------------------------------------------------------------------

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * 返回字段级变更清单。
 * 数组按**下标**逐项比较，不用集合语义——收据里的数组是有序的，
 * 把 [a,b] 与 [b,a] 判为"相同"会漏掉真实的顺序篡改。
 */
function deepDiff(original, suspect, base = "") {
  const changes = [];

  const bothObjects = isPlainObject(original) && isPlainObject(suspect);
  const bothArrays = Array.isArray(original) && Array.isArray(suspect);

  if (bothObjects) {
    const keys = new Set([...Object.keys(original), ...Object.keys(suspect)]);
    for (const k of Array.from(keys).sort()) {
      const ptr = joinPointer(base, k);
      const hasO = Object.prototype.hasOwnProperty.call(original, k);
      const hasS = Object.prototype.hasOwnProperty.call(suspect, k);
      if (hasO && !hasS) {
        changes.push(mk(ptr, "removed", original[k], undefined));
      } else if (!hasO && hasS) {
        changes.push(mk(ptr, "added", undefined, suspect[k]));
      } else {
        changes.push(...deepDiff(original[k], suspect[k], ptr));
      }
    }
    return changes;
  }

  if (bothArrays) {
    const n = Math.max(original.length, suspect.length);
    for (let i = 0; i < n; i++) {
      const ptr = joinPointer(base, i);
      if (i >= original.length) {
        changes.push(mk(ptr, "added", undefined, suspect[i]));
      } else if (i >= suspect.length) {
        changes.push(mk(ptr, "removed", original[i], undefined));
      } else {
        changes.push(...deepDiff(original[i], suspect[i], ptr));
      }
    }
    return changes;
  }

  if (!sameScalar(original, suspect)) {
    changes.push(mk(base || "/", "modified", original, suspect));
  }
  return changes;
}

function sameScalar(a, b) {
  if (a === b) return true;
  if (typeof a === "number" && typeof b === "number" && Number.isNaN(a) && Number.isNaN(b)) {
    return true;
  }
  if (isPlainObject(a) || isPlainObject(b) || Array.isArray(a) || Array.isArray(b)) {
    // 类型不一致（对象 vs 标量）：交给 JSON 比较判等
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return false;
}

function preview(v) {
  if (v === undefined) return null;
  if (typeof v === "string") return v.length > 200 ? v.slice(0, 200) + "…" : v;
  try {
    const s = JSON.stringify(v);
    return s && s.length > 200 ? s.slice(0, 200) + "…" : v;
  } catch {
    return String(v);
  }
}

function mk(pointer, change, original, suspect) {
  const severity = classifySeverity(pointer);
  return {
    path: pointer,
    path_format: "rfc6901",
    change,
    original: preview(original),
    suspect: preview(suspect),
    severity,
    remediation: REMEDIATION[severity],
    // 兼容既有消费方（Python 侧曾输出点号路径）
    path_dotted: pointer.replace(/^\//, "").replace(/\//g, "."),
  };
}

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

function digestOf(obj) {
  try {
    return "sha256:" + crypto
      .createHash("sha256")
      .update(JSON.stringify(sortDeep(obj)))
      .digest("hex");
  } catch {
    return null;
  }
}

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (isPlainObject(v)) {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

function buildReport(original, suspect) {
  const changes = deepDiff(original, suspect);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const c of changes) counts[c.severity]++;

  const originalDigest = digestOf(original);
  const suspectDigest = digestOf(suspect);

  let conclusion;
  if (changes.length === 0) {
    conclusion =
      "No field-level differences found between the two artifacts. " +
      "Note: this compares content only; it does not by itself prove either artifact is authentic.";
  } else if (counts.critical > 0) {
    conclusion =
      `${changes.length} field(s) differ, including ${counts.critical} verdict-bearing field(s). ` +
      "At least one change affects the conclusion itself, so the two artifacts are not interchangeable.";
  } else {
    conclusion =
      `${changes.length} field(s) differ. None are verdict-bearing; differences are likely ` +
      "operational or contextual rather than decisional.";
  }

  return {
    schema: "correctover.tamper-localization.v1",
    tampered: changes.length > 0,
    counts,
    changes,
    digests: { original: originalDigest, suspect: suspectDigest },
    conclusion,
    limitations: [
      "This compares two artifacts you supplied. It does not prove which one is authentic.",
      "It reports content differences only; it does not verify any cryptographic signature.",
      "Pair it with verify_receipt to establish authenticity, then use this to localize the change.",
    ],
  };
}

module.exports = {
  deepDiff,
  buildReport,
  classifySeverity,
  pointerEscape,
  joinPointer,
  digestOf,
};
