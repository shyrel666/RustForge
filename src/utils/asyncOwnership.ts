/**
 * 异步请求的项目/代际身份。调用方必须在启动请求时捕获二者，并在提交
 * 结果前重新校验，避免旧项目的 Promise 回写当前工作区。
 */
export function isCurrentProjectGeneration(
  activeProjectId: number | null,
  currentGeneration: number,
  requestProjectId: number,
  requestGeneration: number
): boolean {
  return (
    activeProjectId === requestProjectId &&
    currentGeneration === requestGeneration
  );
}

/**
 * 在任何 await 之前为有副作用的操作取得唯一令牌。active=true 时拒绝
 * 重入；完成方只能在令牌仍为当前值时释放 UI 状态。
 */
export function claimExclusiveOperation(
  active: boolean,
  currentOperationId: number
): number | null {
  return active ? null : currentOperationId + 1;
}
