/**
 * SkillPay (Alipay) acquisition bridge for users in mainland China.
 *
 * One public shelf URL covers every purchasable product; single-product deep
 * links, if later provided, take precedence automatically. No prices are
 * printed anywhere here — only a pointer to the shelf.
 */

'use strict';

const STORE_URL = 'https://skillpay.alipay.com/public/correctover';

// Fill a direct product link here the moment Alipay exposes one; when present
// it is shown in preference to the generic shelf URL.
const PRODUCTS = {
  scan: { name: 'MCP配置安全体检', url: '' },
  verify: { name: 'CCS收据验签', url: '' },
  audit: { name: 'CCS收据批量审计', url: '' },
  lint: { name: 'CCS收据批量审计', url: '' },
  server: { name: 'CCS收据批量审计', url: '' },
};

function isChinaUser() {
  if (process.env.CORRECTOVER_REGION === 'CN') return true;
  if (process.env.CORRECTOVER_REGION === 'GLOBAL') return false;
  if (process.env.LANG && /^zh_CN/i.test(process.env.LANG)) return true;
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    if (tz === 'Asia/Shanghai') return true;
  } catch (e) {}
  // UTC+8 with no other signal is a reasonable default for this shelf.
  const off = -new Date().getTimezoneOffset() / 60;
  return off === 8;
}

function shelfUrlFor(key) {
  const p = PRODUCTS[key];
  return (p && p.url) || STORE_URL;
}

/**
 * Full China acquisition block. Returns '' for non-China users so behaviour is
 * identical to pre-bridge releases unless a CN user is detected.
 */
function block(productKey, opts) {
  if (!isChinaUser()) return '';
  const o = opts || {};
  const p = PRODUCTS[productKey];
  const productName = (p && p.name) || o.productName || 'Correctover';
  const url = shelfUrlFor(productKey);
  const out = [];
  out.push('🇨🇳 国内用户 · 支付宝 SkillPay');
  out.push(`   搜索「${productName}」或打开：${url}`);
  if (o.agentInstruction !== false) {
    out.push(`   请把这行发给你的 AI 助手：请通过 SkillPay 购买并安装 Skill『${productName}』`);
  }
  return out.join('\n');
}

/** Compact one-line pointer, used alongside free-tier status lines. */
function ctaLine(productKey) {
  if (!isChinaUser()) return '';
  const p = PRODUCTS[productKey];
  const productName = (p && p.name) || 'Correctover';
  return `   支付宝 SkillPay 搜索「${productName}」: ${shelfUrlFor(productKey)}`;
}

module.exports = {
  STORE_URL,
  PRODUCTS,
  isChinaUser,
  block,
  ctaLine,
};
