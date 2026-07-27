/**
 * 前端只负责去掉条目两侧空白和去重。
 *
 * URL/IDN/IPv4/IPv6/端口/通配符的规范化与合法性判定全部由后端
 * ScopePolicy 完成，避免前后端两套解析器产生不同安全结论。
 */

export function normalizeScopeEntry(raw: string): string {
  return raw.trim();
}

/** 批量去空 + 去重；安全规范化留给后端。 */
export function normalizeScopeList(entries: string[]): string[] {
  const out = entries.map(normalizeScopeEntry).filter(Boolean);
  return [...new Set(out)];
}
