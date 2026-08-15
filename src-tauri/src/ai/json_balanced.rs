//! LLM 输出的通用 JSON 提取：剥 Markdown 围栏、按括号平衡扫描并尝试
//! 每一个 JSON 起点，避免“首个开符 + 最后闭符”把尾注中的 `}` 或散文中的
//! `[...]` 误当成 JSON 的一部分。
//! analyzer（单请求分析）和 planner（测试计划规划）共用。

use serde::de::DeserializeOwned;

fn strip_code_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    let no_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    no_fence.strip_suffix("```").unwrap_or(no_fence).trim()
}

/// 从 `start` 处开始做括号平衡扫描，返回第一个完整 JSON 片段的结束位置。
/// 扫描会跳过字符串字面量与转义字符；遇到括号不匹配或超过最大嵌套深度时
/// 返回 `None`，由调用方尝试下一个候选起点。
fn balanced_json_end(input: &str, start: usize) -> Option<usize> {
    const MAX_JSON_DEPTH: usize = 64;

    let bytes = input.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().copied().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                stack.push(byte);
                if stack.len() > MAX_JSON_DEPTH {
                    return None;
                }
            }
            b'}' | b']' => {
                let expected_open = if byte == b'}' { b'{' } else { b'[' };
                if stack.pop() != Some(expected_open) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn json_candidate_starts(input: &str) -> Vec<usize> {
    let bytes = input.as_bytes();
    let mut starts = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => starts.push(index),
            _ => {}
        }
    }
    starts
}

/// 从模型输出提取 JSON（对象或数组）并反序列化。
///
/// 解析器按出现顺序尝试每个 `{` / `[` 起点；只有括号平衡且能被目标类型
/// 成功反序列化的片段才会返回。这样 `{"a":1} 尾注还有 }` 或
/// `前置说明 [不是一个 JSON] {"a":1}` 都不会再把合法响应误拒。
pub fn parse_llm_json<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    let prepared = strip_code_fence(raw);

    let starts = json_candidate_starts(prepared);
    if starts.is_empty() {
        return Err("输出中没有 JSON 内容".into());
    }

    let mut last_error = String::from("JSON 片段不完整");
    for start in starts {
        let Some(end) = balanced_json_end(prepared, start) else {
            continue;
        };
        match serde_json::from_str(&prepared[start..end]) {
            Ok(value) => return Ok(value),
            Err(error) => last_error = format!("JSON 解析失败: {error}"),
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn parses_plain_json_object_and_array() {
        assert_eq!(parse_llm_json::<Value>(r#"{"a":1}"#).unwrap()["a"], 1);
        assert_eq!(parse_llm_json::<Vec<Value>>(r#"[1,2]"#).unwrap().len(), 2);
    }

    #[test]
    fn trailing_prose_with_braces_does_not_break_the_first_complete_object() {
        let parsed =
            parse_llm_json::<Value>("```json\n{\"a\":1}\n尾注里还有一个 } 和另一个 { 符号")
                .unwrap();
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn invalid_prose_before_json_is_skipped_to_the_next_candidate() {
        let parsed = parse_llm_json::<Value>("前置说明 [这不是完整 JSON 的起点 {\"a\":1}").unwrap();
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn escaped_braces_inside_strings_are_ignored() {
        let parsed = parse_llm_json::<Value>(r#"{"note":"} still text {","a":1}"#).unwrap();
        assert_eq!(parsed["a"], 1);
    }

    #[test]
    fn incomplete_json_still_fails_closed() {
        assert!(parse_llm_json::<Value>("{\"a\":1").is_err());
        assert!(parse_llm_json::<Value>("no json here").is_err());
    }

    #[test]
    fn parser_still_rejects_wrong_shape_even_when_json_is_balanced() {
        let value = json!({"a": 1});
        assert!(parse_llm_json::<Vec<Value>>(&value.to_string()).is_err());
    }
}
