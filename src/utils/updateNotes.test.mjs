import test from "node:test";
import assert from "node:assert/strict";
import {
  formatUpdateVersion,
  parseUpdateNotes,
} from "./updateNotes.ts";

test("compact Chinese updater notes become scannable highlights", () => {
  const parsed = parseUpdateNotes(
    "核心更新：统一授权边界；证据驱动的验证闭环；可复查的 Repeater 工作流。",
  );

  assert.equal(parsed.title, "核心更新");
  assert.deepEqual(parsed.highlights, [
    "统一授权边界",
    "证据驱动的验证闭环",
    "可复查的 Repeater 工作流",
  ]);
  assert.equal(parsed.fallback, "");
});

test("Markdown release notes retain the core section and remove markup", () => {
  const parsed = parseUpdateNotes(`
## 核心更新

- **统一授权边界**：Scope 外请求在发送前拒绝。
- **证据报告**：查看 [完整说明](https://example.test/release)。

## 下载与升级

- Windows x64 安装包
`);

  assert.equal(parsed.title, "核心更新");
  assert.deepEqual(parsed.highlights, [
    "统一授权边界：Scope 外请求在发送前拒绝",
    "证据报告：查看 完整说明",
  ]);
});

test("plain legacy notes remain readable instead of disappearing", () => {
  const parsed = parseUpdateNotes(
    "Security and reliability improvements for this release.",
  );

  assert.equal(parsed.title, "更新说明");
  assert.deepEqual(parsed.highlights, [
    "Security and reliability improvements for this release",
  ]);
});

test("missing notes provide an explicit fallback", () => {
  const parsed = parseUpdateNotes("   ");

  assert.deepEqual(parsed.highlights, []);
  assert.match(parsed.fallback, /暂未提供详细说明/);
});

test("version labels contain exactly one v prefix", () => {
  assert.equal(formatUpdateVersion("0.1.1"), "v0.1.1");
  assert.equal(formatUpdateVersion("v0.1.1"), "v0.1.1");
  assert.equal(formatUpdateVersion(""), "—");
});
