//! LLM 输出的通用 JSON 提取：剥 Markdown 围栏、截取首个 JSON 片段。
//! analyzer（单请求分析）和 planner（任务树规划）共用。

use serde::de::DeserializeOwned;

/// 从模型输出提取 JSON（对象或数组）并反序列化
pub fn parse_llm_json<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    let trimmed = raw.trim();
    let no_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    let no_fence = no_fence.strip_suffix("```").unwrap_or(no_fence).trim();

    // 找第一个 JSON 起点（对象或数组），与对应的最后一个闭包符
    let obj_start = no_fence.find('{');
    let arr_start = no_fence.find('[');
    let (start, open, close) = match (obj_start, arr_start) {
        (Some(o), Some(a)) if a < o => (a, '[', ']'),
        (Some(o), _) => (o, '{', '}'),
        (None, Some(a)) => (a, '[', ']'),
        (None, None) => return Err("输出中没有 JSON 内容".into()),
    };
    let _ = open;
    let end = no_fence.rfind(close).ok_or("JSON 片段不完整")?;
    if end <= start {
        return Err("JSON 片段不完整".into());
    }
    serde_json::from_str(&no_fence[start..=end]).map_err(|e| format!("JSON 解析失败: {e}"))
}
