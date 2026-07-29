-- 供应商提示词缓存命中量是输入 Token 的子集。
-- 历史运行无法追溯供应商已丢弃的 usage 明细，因此安全回填为 0。
ALTER TABLE analysis_runs
ADD COLUMN cached_tokens INTEGER NOT NULL DEFAULT 0
    CHECK(cached_tokens >= 0 AND cached_tokens <= prompt_tokens);
