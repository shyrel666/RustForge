/** Scope 输入清洗：与后端 normalize_scope_pattern 同规则，保存前把库存干净 */

/** 单条归一化：去空白/小写 → 去 scheme → 去路径 → 去端口 → 去结尾点号 */
export function normalizeScopeEntry(raw: string): string {
  let s = raw.trim().toLowerCase();
  const scheme = s.indexOf("://");
  if (scheme >= 0) s = s.slice(scheme + 3);
  const slash = s.indexOf("/");
  if (slash >= 0) s = s.slice(0, slash);
  if (!s.includes("]")) {
    const colon = s.lastIndexOf(":");
    if (colon >= 0) s = s.slice(0, colon);
  }
  return s.replace(/\.+$/, "");
}

/** 批量归一化 + 去空 + 去重 */
export function normalizeScopeList(entries: string[]): string[] {
  const out = entries.map(normalizeScopeEntry).filter(Boolean);
  return [...new Set(out)];
}
