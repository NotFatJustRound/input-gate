"""input-gate: 给 agent 的外部输入套一道闸。

三道闸: 来源标记 / 长度封顶 / 可疑模式与白名单。
只依赖标准库。
"""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

UNTRUSTED_BANNER = "UNTRUSTED SOURCE: {url} | fetched {ts} | flags: {flags}"
FENCE_OPEN = "<<<UNTRUSTED_TEXT"
FENCE_CLOSE = "UNTRUSTED_TEXT>>>"

# 可疑指令: 命中只标记，不删除。
INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("OVERRIDE_ZH", r"(忽略|无视|跳过)(之前|以上|前面|先前)(的)?(所有)?(指令|要求|设定|提示)"),
    ("OVERRIDE_EN", r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)"),
    ("OVERRIDE_EN2", r"disregard\s+(the\s+)?(system|developer|previous)"),
    ("ROLE_SWAP", r"(你现在是|从现在起你是|你的新(身份|角色|指令)是)"),
    ("SYSTEM_TAG", r"</?\s*(system|assistant|developer|tool)\s*>"),
    ("PROMPT_LEAK", r"(system\s*prompt|开发者指令|developer\s+message|重复你的(指令|提示词))"),
    ("SECRET_EXFIL", r"(密码|口令|token|密钥|api[_\s-]?key|私钥)[^\n]{0,24}(发给|写到|上传|交给|post|send)"),
    ("SHELL_PIPE", r"(curl|wget)[^\n|]{0,80}\|\s*(ba)?sh"),
    ("RM_ROOT", r"rm\s+-rf\s+/(\s|$)"),
    ("EVAL_BLOB", r"eval\s*\(\s*(base64|exec|__import__)"),
)

INVISIBLE_RANGES = (
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0xFEFF, 0xFEFF),
)

BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+")

DEFAULT_ALLOW_DOMAINS = frozenset(
    {"github.com", "raw.githubusercontent.com", "docs.python.org", "pypi.org"}
)


@dataclass
class Policy:
    max_chars: int = 8000
    allow_domains: frozenset[str] = DEFAULT_ALLOW_DOMAINS
    strip_invisible: bool = True
    flag_injection: bool = True
    max_base64_run: int = 200
    fence_untrusted: bool = True


@dataclass
class GateResult:
    text: str
    url: str
    trusted: bool = False
    flags: list[str] = field(default_factory=list)
    truncated: bool = False
    dropped_chars: int = 0


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _domain_ok(url: str, allow: Iterable[str]) -> bool:
    host = _host(url)
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in allow)


def _find_invisible(text: str) -> int:
    n = 0
    for ch in text:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in INVISIBLE_RANGES):
            n += 1
    return n


def _strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text if not any(lo <= ord(ch) <= hi for lo, hi in INVISIBLE_RANGES)
    )


def scan(text: str, policy: Policy) -> list[str]:
    """返回命中列表，形如 INJECTION_PATTERN:OVERRIDE_ZH:忽略之前的指令"""
    flags: list[str] = []
    if policy.flag_injection:
        for name, pat in INJECTION_PATTERNS:
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                flags.append(f"INJECTION_PATTERN:{name}:{m.group(0)[:40]}")
    inv = _find_invisible(text)
    if inv:
        flags.append(f"INVISIBLE_CHARS:{inv}")
    for blob in BASE64_BLOB.findall(text):
        if len(blob) >= policy.max_base64_run:
            flags.append(f"LONG_BASE64:{len(blob)}")
            break
    for u in URL_IN_TEXT.findall(text)[:20]:
        if not _domain_ok(u, policy.allow_domains):
            flags.append(f"OFF_WHITELIST_URL:{_host(u)}")
            break
    return flags


def gate(text: str, source: str, policy: Policy | None = None) -> GateResult:
    policy = policy or Policy()
    original_len = len(text)

    if policy.strip_invisible:
        cleaned = _strip_invisible(text)
    else:
        cleaned = text

    flags = scan(cleaned, policy)

    truncated = len(cleaned) > policy.max_chars
    if truncated:
        dropped = len(cleaned) - policy.max_chars
        cleaned = cleaned[: policy.max_chars]
        flags.append(f"TRUNCATED:{dropped}")
    else:
        dropped = 0

    if policy.fence_untrusted:
        banner = UNTRUSTED_BANNER.format(
            url=source or "(unknown)",
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            flags=",".join(f.split(":")[0] for f in flags) or "none",
        )
        body = f"[{banner}]\n{FENCE_OPEN}\n{cleaned}\n{FENCE_CLOSE}"
    else:
        body = cleaned

    return GateResult(
        text=body,
        url=source,
        trusted=False,
        flags=flags,
        truncated=truncated,
        dropped_chars=dropped or (original_len - len(cleaned) if policy.strip_invisible else 0),
    )


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    raw["allow_domains"] = frozenset(raw.get("allow_domains", DEFAULT_ALLOW_DOMAINS))
    return Policy(**raw)


def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python gate.py <url-or-file> [policy.json]", file=sys.stderr)
        return 2
    target = argv[1]
    policy = load_policy(argv[2]) if len(argv) > 2 else Policy()

    if target.startswith(("http://", "https://")):
        # 这里不内置抓取器: 交给上游（如 web-forager）抓完把正文传进来。
        print("这是一个纯函数门: 请把抓取后的正文通过 gate() 传入。", file=sys.stderr)
        return 1

    with open(target, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    r = gate(text, source=f"file://{target}", policy=policy)
    print(r.text)
    print(f"\nflags: {r.flags}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
