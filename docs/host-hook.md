# 把闸挂到抓取路径：宿主侧接入约定

状态：**提案，未在真实宿主上验证**。插件这边能做的是提供稳定接口，接入点在宿主，不在本仓库。

## 为什么

现在 `input-gate` 是"自愿调用的工具"：模型不调，它就不存在。线上装了之后调用次数是 0，说明这条路不通——你不能指望一个正在被注入的模型，还记得先调一次闸。

真正的做法是让它成为工具返回值的必经环节：抓取类工具（`web_fetch` / `web_search` 正文、文件解析结果、剪贴板）在把正文交给模型之前先过一遍 `gate()`。

## 调用约定

```js
// 宿主侧，工具 output/render 阶段
const gated = gate(rawText, sourceUrl, {
  mode: 'balanced',        // strict | balanced | lenient
  maxChars: 50000,
  timestamp: callId,       // 可选：传入则 nonce 由 source+timestamp 派生，输出可复现
});

// 无论 verdict 是什么，交给模型的都是 gated.text
// reject 时 gated.text 是 [REJECTED BY input-gate: ...] + codes，正文不交付
return gated.text;
```

失败语义（必须 fail-closed）：

| 情况 | 行为 |
| --- | --- |
| `gate()` 抛异常 | 返回 `[input-gate unavailable: <reason>]`，**不要**回退成原文 |
| `source` 缺失 | 正常过闸，横幅标 `source: unknown`，裁决上升一档 |
| 正文超长 | 先扫全文再截断（已是现状），不要先截断再扫 |

## 宿主需要提供的三样东西

1. **调用点识别**：哪些工具输出算"外部内容"。抓取、搜索正文、文件解析、剪贴板算；模型自己写的代码、宿主自己的提示词不算。
2. **source 归一化**：统一成 URL 或 `file://` 形式，作为横幅和策略匹配的键。
3. **时间戳注入（可选）**：只在需要复现的测试路径传，线上别传——传了 nonce 就退化成可预测的。

## 已知代价

- 所有外部内容都会多一层 `[UNTRUSTED SOURCE: ...]` 横幅，模型侧的提示词要知道这个横幅是什么意思，否则只是加噪音。
- 代码块内的硬规则命中会降成 `quarantine`，正文照给——这是为了不误伤文档，但也给了攻击者"把载荷包进代码块换降级"的路子。取舍写在 README 的已知局限里。
- 每个抓取多一次全文扫描。1MB / 90ms 量级，正常页面无感，批量抓取时要留意。

## 怎么算挂上了

上线后统计 `gate()` 调用次数：从 0 变成非零，说明接进去了。再用 issue #1 里那三条 payload 真跑一次抓取，看是不是 `reject · FENCE_FORGERY` / `reject · TAG_SMUGGLING` / `quarantine`，而不是原文直通。
