/**
 * 将远端持久值合并进本地草稿：只有仍等于上一次持久值的未编辑草稿才自动同步。
 */
export function reconcileDraftValue<T>(
  draft: T,
  previousPersisted: T,
  nextPersisted: T
): T {
  return Object.is(draft, previousPersisted) ? nextPersisted : draft;
}
