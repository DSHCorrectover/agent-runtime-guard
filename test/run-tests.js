"use strict";
/**
 * locate_tampering 测试套件
 *
 * 关键断言不是"函数能跑"，而是三件事：
 *   1) 字段级定位真的指向**正确的指针**（RFC 6901 转义正确）
 *   2) 严重度按**字段语义**分级，不按差异大小
 *   3) 数组顺序变更必须被检出（不能退化成集合比较）
 *
 * 运行： node test/run-tests.js
 */

const assert = require("assert");
const t = require("../src/locate_tampering");

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  PASS  ${name}`);
  } catch (e) {
    failed++;
    failures.push({ name, msg: e.message });
    console.log(`  FAIL  ${name}\n        ${e.message}`);
  }
}

console.log("locate_tampering 测试套件\n");

// ---------------------------------------------------------------------------
console.log("1. JSON-Pointer 转义（RFC 6901）");
// ---------------------------------------------------------------------------

test("普通 token 不变", () => {
  assert.strictEqual(t.pointerEscape("checks"), "checks");
});

test("~ 转义为 ~0", () => {
  assert.strictEqual(t.pointerEscape("a~b"), "a~0b");
});

test("/ 转义为 ~1", () => {
  assert.strictEqual(t.pointerEscape("a/b"), "a~1b");
});

test("~ 先于 / 转义（顺序敏感）", () => {
  // "~/" 必须变成 "~0~1"，
  // 若先转 / 会得到 "~~1" 再转 ~ 成 "~0~1"……不，先转 / 会错成 "~~01"
  assert.strictEqual(t.pointerEscape("~/"), "~0~1");
});

test("含 / 的 key 仍产生合法单段指针", () => {
  const ptr = t.joinPointer("", "a/b");
  assert.strictEqual(ptr, "/a~1b");
  // 指针段数必须是 1（因为 / 被转义了）
  assert.strictEqual(ptr.split("/").length - 1, 1);
});

// ---------------------------------------------------------------------------
console.log("\n2. 差异检出");
// ---------------------------------------------------------------------------

test("无差异返回空清单", () => {
  const a = { x: 1, y: { z: "ok" } };
  assert.strictEqual(t.deepDiff(a, JSON.parse(JSON.stringify(a))).length, 0);
});

test("标量修改被检出且指针正确", () => {
  const d = t.deepDiff({ verdict: "valid" }, { verdict: "invalid" });
  assert.strictEqual(d.length, 1);
  assert.strictEqual(d[0].path, "/verdict");
  assert.strictEqual(d[0].change, "modified");
  assert.strictEqual(d[0].original, "valid");
  assert.strictEqual(d[0].suspect, "invalid");
});

test("嵌套字段指针用 / 分隔", () => {
  const d = t.deepDiff(
    { checks: { security: { status: "pass" } } },
    { checks: { security: { status: "fail" } } }
  );
  assert.strictEqual(d[0].path, "/checks/security/status");
});

test("新增字段标 added 且 original 为 null", () => {
  const d = t.deepDiff({ a: 1 }, { a: 1, b: 2 });
  assert.strictEqual(d.length, 1);
  assert.strictEqual(d[0].change, "added");
  assert.strictEqual(d[0].path, "/b");
  assert.strictEqual(d[0].original, null);
});

test("删除字段标 removed", () => {
  const d = t.deepDiff({ a: 1, b: 2 }, { a: 1 });
  assert.strictEqual(d[0].change, "removed");
  assert.strictEqual(d[0].path, "/b");
});

test("数组按下标比较，顺序变更被检出", () => {
  // 关键：不能用集合语义，否则 ["a","b"] vs ["b","a"] 会被判为相同
  const d = t.deepDiff({ list: ["a", "b"] }, { list: ["b", "a"] });
  assert.ok(d.length > 0, "顺序变更必须被检出");
  const paths = d.map((c) => c.path).sort();
  assert.deepStrictEqual(paths, ["/list/0", "/list/1"]);
});

test("数组长度变化：新增项标 added", () => {
  const d = t.deepDiff({ l: [1] }, { l: [1, 2] });
  assert.strictEqual(d.length, 1);
  assert.strictEqual(d[0].path, "/l/1");
  assert.strictEqual(d[0].change, "added");
});

test("类型变更（对象→标量）被检出", () => {
  const d = t.deepDiff({ a: { b: 1 } }, { a: "flat" });
  assert.strictEqual(d.length, 1);
  assert.strictEqual(d[0].path, "/a");
});

test("深层多处修改全部报出", () => {
  const o = { v: "valid", lat: 12, c: { s: { st: "pass", d: "ok" } } };
  const s = { v: "invalid", lat: 71, c: { s: { st: "fail", d: "ok" } } };
  const d = t.deepDiff(o, s);
  const paths = d.map((c) => c.path).sort();
  assert.deepStrictEqual(paths, ["/c/s/st", "/lat", "/v"]);
});

// ---------------------------------------------------------------------------
console.log("\n3. 严重度按字段语义（不是按差异大小）");
// ---------------------------------------------------------------------------

test("verdict 为 critical", () => {
  assert.strictEqual(t.classifySeverity("/verdict"), "critical");
});

test("checks 下任意深度均为 critical", () => {
  assert.strictEqual(t.classifySeverity("/checks/security/status"), "critical");
  assert.strictEqual(t.classifySeverity("/checks/a/b/c/d"), "critical");
});

test("reason 为 high", () => {
  assert.strictEqual(t.classifySeverity("/reason"), "high");
});

test("latency 为 medium", () => {
  assert.strictEqual(t.classifySeverity("/latency_ms"), "medium");
});

test("未知字段为 low", () => {
  assert.strictEqual(t.classifySeverity("/some_unknown_field"), "low");
});

test("改一个字符的 verdict 比改大对象的 latency 更严重", () => {
  const d = t.deepDiff(
    { verdict: "valid", latency_ms: 1 },
    { verdict: "invali", latency_ms: 99999 }
  );
  const byPath = Object.fromEntries(d.map((c) => [c.path, c.severity]));
  assert.strictEqual(byPath["/verdict"], "critical");
  assert.strictEqual(byPath["/latency_ms"], "medium");
  const rank = { critical: 3, high: 2, medium: 1, low: 0 };
  assert.ok(rank[byPath["/verdict"]] > rank[byPath["/latency_ms"]]);
});

// ---------------------------------------------------------------------------
console.log("\n4. 报告结构");
// ---------------------------------------------------------------------------

test("报告带 schema 标识", () => {
  const r = t.buildReport({ a: 1 }, { a: 2 });
  assert.strictEqual(r.schema, "correctover.tamper-localization.v1");
});

test("tampered 在有差异时为 true", () => {
  assert.strictEqual(t.buildReport({ a: 1 }, { a: 2 }).tampered, true);
});

test("tampered 在无差异时为 false", () => {
  assert.strictEqual(t.buildReport({ a: 1 }, { a: 1 }).tampered, false);
});

test("counts 按严重度汇总", () => {
  const r = t.buildReport(
    { verdict: "valid", reason: "x", latency_ms: 1 },
    { verdict: "invalid", reason: "y", latency_ms: 2 }
  );
  assert.strictEqual(r.counts.critical, 1);
  assert.strictEqual(r.counts.high, 1);
  assert.strictEqual(r.counts.medium, 1);
});

test("结论在存在 critical 时明确说明不可互换", () => {
  const r = t.buildReport({ verdict: "valid" }, { verdict: "invalid" });
  assert.ok(/not interchangeable/i.test(r.conclusion), r.conclusion);
});

test("结论在无 critical 时不夸大", () => {
  const r = t.buildReport({ latency_ms: 1 }, { latency_ms: 2 });
  assert.ok(/likely operational|None are verdict-bearing/i.test(r.conclusion), r.conclusion);
});

test("无差异时结论不声称真实性", () => {
  const r = t.buildReport({ a: 1 }, { a: 1 });
  assert.ok(/does not by itself prove/i.test(r.conclusion), r.conclusion);
});

test("limitations 明确不做真实性判断", () => {
  const r = t.buildReport({ a: 1 }, { a: 2 });
  assert.ok(r.limitations.some((l) => /does not prove which one is authentic/i.test(l)));
  assert.ok(r.limitations.some((l) => /does not verify any cryptographic signature/i.test(l)));
});

test("每条变更都带整改建议", () => {
  const r = t.buildReport({ verdict: "a" }, { verdict: "b" });
  assert.ok(r.changes.every((c) => typeof c.remediation === "string" && c.remediation.length > 10));
});

test("digests 对相同内容稳定", () => {
  const a = t.buildReport({ x: 1, y: 2 }, { x: 1, y: 2 });
  const b = t.buildReport({ y: 2, x: 1 }, { y: 2, x: 1 });
  assert.strictEqual(a.digests.original, b.digests.original,
    "键顺序不同不应导致摘要不同");
});

// ---------------------------------------------------------------------------
console.log("\n5. 与 Python 侧输出对齐");
// ---------------------------------------------------------------------------

test("path_dotted 兼容字段存在且格式正确", () => {
  const d = t.deepDiff(
    { checks: { security: { status: "pass" } } },
    { checks: { security: { status: "fail" } } }
  );
  assert.strictEqual(d[0].path_dotted, "checks.security.status");
});

test("path_format 声明为 rfc6901", () => {
  const d = t.deepDiff({ a: 1 }, { a: 2 });
  assert.strictEqual(d[0].path_format, "rfc6901");
});

test("指针与点号路径同时可查（既有消费方不被破坏）", () => {
  const d = t.deepDiff({ a: { b: 1 } }, { a: { b: 2 } })[0];
  assert.strictEqual(d.path, "/a/b");
  assert.strictEqual(d.path_dotted, "a.b");
});

// ---------------------------------------------------------------------------
console.log(`\n${"=".repeat(52)}`);
console.log(`  ${passed}/${passed + failed} PASS`);
console.log(`${"=".repeat(52)}`);
if (failures.length) {
  console.log("\n失败明细：");
  for (const f of failures) console.log(`  - ${f.name}\n    ${f.msg}`);
}
process.exit(failed ? 1 : 0);
