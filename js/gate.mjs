// input-gate / js — gate.py 的 JS 移植，纯函数，不依赖任何宿主 API。
// 用法（宿主里）:
//   import { gate, loadPolicy } from "./js/gate.mjs";
//   const r = gate(rawText, "https://example.com/x", policy);
//   r.text   -> 加了 UNTRUSTED 横幅和围栏的正文
//   r.flags  -> 命中项，形如 "INJECTION_PATTERN:OVERRIDE_ZH:忽略之前的指令"
// 只做标记和封顶，不做权限控制；它不是安全边界。

const UNTRUSTED_BANNER =
  "UNTRUSTED SOURCE: {url} | fetched {ts} | flags: {flags}";
const FENCE_OPEN = "<<<UNTRUSTED_TEXT";
const FENCE_CLOSE = "UNTRUSTED_TEXT>>>";

// 命中只标记，不删除。
const INJECTION_PATTERNS = [
  ["OVERRIDE_ZH", /(忽略|无视|跳过)(之前|以上|前面|先前)(的)?(所有)?(指令|要求|设定|提示)/i],
  ["OVERRIDE_EN", /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i],
  ["OVERRIDE_EN2", /disregard\s+(the\s+)?(system|developer|previous)/i],
  ["ROLE_SWAP", /(你现在是|从现在起你是|你的新(身份|角色|指令)是)/i],
  ["SYSTEM_TAG", /<\/?\s*(system|assistant|developer|tool)\s*>/i],
  ["PROMPT_LEAK", /(system\s*prompt|开发者指令|developer\s+message|重复你的(指令|提示词))/i],
  ["SECRET_EXFIL", /(密码|口令|token|密钥|api[_\s-]?key|私钥)[^\n]{0,24}(发给|写到|上传|交给|post|send)/i],
  ["SHELL_PIPE", /(curl|wget)[^\n|]{0,80}\|\s*(ba)?sh/i],
  ["RM_ROOT", /rm\s+-rf\s+\/(\s|$)/i],
  ["EVAL_BLOB", /eval\s*\(\s*(base64|exec|__import__)/i],
];

const INVISIBLE_RANGES = [
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0xfeff, 0xfeff],
];

const BASE64_BLOB = /[A-Za-z0-9+/]{200,}={0,2}/g;
const URL_IN_TEXT = /https?:\/\/[^\s<>"')\]]+/g;

export const DEFAULT_ALLOW_DOMAINS = [
  "github.com",
  "raw.githubusercontent.com",
  "docs.python.org",
  "pypi.org",
];

export const DEFAULT_POLICY = {
  maxChars: 8000,
  allowDomains: DEFAULT_ALLOW_DOMAINS,
  stripInvisible: true,
  flagInjection: true,
  maxBase64Run: 200,
  fenceUntrusted: true,
};

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function domainOk(url, allow) {
  const host = hostOf(url);
  if (!host) return false;
  return allow.some((d) => host === d || host.endsWith("." + d));
}

function countInvisible(text) {
  let n = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi)) n++;
  }
  return n;
}

function stripInvisible(text) {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (!INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi)) out += ch;
  }
  return out;
}

export function scan(text, policy = DEFAULT_POLICY) {
  const flags = [];
  if (policy.flagInjection) {
    for (const [name, pat] of INJECTION_PATTERNS) {
      const m = pat.exec(text);
      if (m) flags.push(`INJECTION_PATTERN:${name}:${m[0].slice(0, 40)}`);
    }
  }
  const inv = countInvisible(text);
  if (inv) flags.push(`INVISIBLE_CHARS:${inv}`);
  for (const blob of text.match(BASE64_BLOB) || []) {
    if (blob.length >= policy.maxBase64Run) {
      flags.push(`LONG_BASE64:${blob.length}`);
      break;
    }
  }
  const urls = (text.match(URL_IN_TEXT) || []).slice(0, 20);
  for (const u of urls) {
    if (!domainOk(u, policy.allowDomains)) {
      flags.push(`OFF_WHITELIST_URL:${hostOf(u)}`);
      break;
    }
  }
  return flags;
}

export function gate(text, source = "", policy = DEFAULT_POLICY) {
  const originalLen = [...text].length;
  let cleaned = policy.stripInvisible ? stripInvisible(text) : text;

  const flags = scan(cleaned, policy);

  let truncated = false;
  let dropped = 0;
  const chars = [...cleaned];
  if (chars.length > policy.maxChars) {
    truncated = true;
    dropped = chars.length - policy.maxChars;
    cleaned = chars.slice(0, policy.maxChars).join("");
    flags.push(`TRUNCATED:${dropped}`);
  }

  let body = cleaned;
  if (policy.fenceUntrusted) {
    const banner = UNTRUSTED_BANNER.replace("{url}", source || "(unknown)")
      .replace("{ts}", new Date().toISOString().replace(/\.\d+Z$/, "Z"))
      .replace("{flags}", flags.map((f) => f.split(":")[0]).join(",") || "none");
    body = `[${banner}]\n${FENCE_OPEN}\n${cleaned}\n${FENCE_CLOSE}`;
  }

  return {
    text: body,
    url: source,
    trusted: false,
    flags,
    truncated,
    droppedChars:
      dropped || (policy.stripInvisible ? originalLen - (policy.stripInvisible ? [...cleaned].length : 0) : 0),
  };
}

// 宿主可以把自己的策略对象直接喂进来；未给的字段用默认值兜底。
export function loadPolicy(raw = {}) {
  return {
    ...DEFAULT_POLICY,
    ...raw,
    allowDomains: raw.allowDomains || raw.allow_domains || DEFAULT_ALLOW_DOMAINS,
  };
}
