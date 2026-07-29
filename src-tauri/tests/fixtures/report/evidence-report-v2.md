# 证据化安全测试报告：&lt;script&gt;alert(1)&lt;/script&gt; 演示/项目

- 报告格式：Evidence Report Schema v2
- 报告生成时间：`2026-07-28T12:00:00+08:00`
- 内容分级：默认脱敏

> **授权与复核声明**：本报告仅适用于项目中明确记录的授权范围。AI 与被动规则只产生待验证假设；confirmed 结论来自人工接受的真实 Evidence，但仍需专业人员复核。禁止将本报告用于未授权目标。

## 1. 授权范围、排除范围和测试限制

- 项目 ID：`7`
- 目标主机：demo.test
- 项目创建时间：`2026-07-24 09:00:00`
- 授权范围：
  - demo.test
  - api.demo.test
- 排除范围：
  - 当前项目模型未单独记录排除项；所有未列入授权范围的目标均视为排除范围。
- 测试限制：
  - 1 条流量存在请求或响应截断；相关正文不能视为完整内容。
  - 1 条 Finding 尚未人工确认，仅列入待验证附录，不作为报告结论。
  - 1 个测试计划节点尚未完成。
  - 1 个测试计划节点受阻；阻塞原因见测试计划章节。

## 2. 时间线、方法与工具版本

### 时间线

- `2026-07-24 09:00:00` · project\_created · `project:7`：项目及授权边界记录已创建。
- `2026-07-24 09:10:00` · traffic\_capture\_started · `traffic-count:1`：开始记录授权范围内流量；本报告共统计 1 条。
- `2026-07-24 09:13:00` · finding\_created · `finding:31`：创建待确认 Finding：登录存在 SQL 注入 \# 标题。
- `2026-07-24 09:14:00` · finding\_created · `finding:32`：创建待确认 Finding：待确认的会话问题。
- `2026-07-24 09:16:00` · test\_plan\_revision · `test-plan-revision:1`：初始测试计划
- `2026-07-24 09:18:00.000` · evidence\_created · `evidence:1`：为 Finding \#31 创建 traffic Evidence 快照。
- `2026-07-24 09:19:00.000` · evidence\_accepted · `evidence:1`：Evidence \#1 经人工接受。
- `2026-07-24 09:20:00.000` · finding\_confirmed · `finding:31`：Finding 状态由「待验证」变为「已确认」。

### 使用的方法

- **有界流量采集**（`bounded_traffic_capture`）：在授权 Scope 内保存带捕获、截断和解码状态的 HTTP 流量。
- **AI 辅助假设**（`ai_hypothesis`）：模型输出经过结构校验并保留模型、提示词版本和输入哈希；不自动确认漏洞。
- **人工 Evidence 复核**（`human_evidence_review`）：只有已接受且具备确认资格的 Evidence 才能支撑 confirmed 结论。
- **证据驱动测试计划**（`evidence_driven_test_plan`）：计划节点、未完成项和阻塞项按当前持久化 revision 汇总。

### 工具版本

- RustForge：`0.1.2`
- SQLite：`3.46.0`
- Evidence Report Schema：`2`

## 3. 执行摘要与风险分布

- 已记录流量：1 条
- 已确认 Finding：1 条
- 待验证附录：1 条
- 默认省略 rejected Finding：1 条
- 已接受且可支撑确认的 Evidence：1 项
- 测试计划覆盖：1/3 个节点已终结
- confirmed 风险分布：critical 0，high 1，medium 0，low 0，info 0

## 4. 已确认 Findings

### 1. [high] 登录存在 SQL 注入 \# 标题

#### 身份、目标与风险

- Finding ID：`31`
- 稳定身份：`finding:31`
- 状态：已确认
- 类型：SQL 注入
- 风险：`high`　置信度：87　累计出现：1
- 来源：AI 分析（需人工复核）
- 标准引用：A03:2021、CWE-89 (v4.20)
- 受影响目标：
  - `POST` `https://demo.test/login?api_key=%5BREDACTED%3Aquery_value%5D`

#### 假设依据（不等同于实际复现）

AI 假设：参数 username 可能触发报错，不是已执行结果。

#### 建议验证步骤（计划性内容）

1\. 在授权环境输入单引号
2\. 对比响应

#### 已执行复现与实际 Evidence

##### Evidence `1` · `traffic` `11`

- 实际观察：人工观察到 500 与 SQL 错误片段；Authorization: \[REDACTED:sensitive\_field\]
- 人工接受：是　可用于确认：是　来源仍可用：是
- 快照 SHA-256：`403b7b32136b42136fe9e753f03caa618e89ebb29cf17b0ecfe69a2700a33680`（校验通过）
- 创建者：`test:analyst`　创建时间：`2026-07-24 09:18:00.000`
- 接受说明：响应差异可重复

**不可变脱敏请求/响应快照（默认报告内容）**

```json
{
  "redaction_manifest": {
    "body_decisions": [],
    "disclosures": [],
    "notes": [],
    "omissions": [],
    "redactions": [
      {
        "count": 1,
        "kind": "query_value",
        "location": "request.url.query.api_key"
      },
      {
        "count": 1,
        "kind": "sensitive_header",
        "location": "request.headers.authorization"
      },
      {
        "count": 1,
        "kind": "sensitive_header",
        "location": "request.headers.cookie"
      },
      {
        "count": 1,
        "kind": "sensitive_header",
        "location": "response.headers.set-cookie"
      },
      {
        "count": 1,
        "kind": "sensitive_field",
        "location": "request.body.api_key"
      }
    ],
    "total_input_bytes": 0
  },
  "request": {
    "body": "{\n  \"api_key\": \"[REDACTED:sensitive_field]\",\n  \"username\": \"admin\"\n}",
    "capture_status": "identity_text",
    "captured_size": 20000,
    "headers": "{\n  \"Authorization\": \"[REDACTED:sensitive_header]\",\n  \"Content-Type\": \"application/json\",\n  \"Cookie\": \"[REDACTED:sensitive_header]\"\n}",
    "method": "POST",
    "truncated": false,
    "url": "https://demo.test/login?api_key=%5BREDACTED%3Aquery_value%5D",
    "wire_size": 20000
  },
  "response": {
    "body": "{\n  \"error\": \"SQL syntax near username\",\n  \"padding\": \"captured prefix\"\n}",
    "capture_status": "identity_text",
    "captured_size": 8192,
    "headers": "{\n  \"Content-Type\": \"application/json\",\n  \"Set-Cookie\": \"[REDACTED:sensitive_header]\"\n}",
    "status": 500,
    "truncated": true,
    "wire_size": 24000
  },
  "schema_version": 1,
  "source": {
    "id": 11,
    "type": "traffic"
  },
  "source_created_at": "2026-07-24 09:10:00"
}
```

> 本结论由 1 项已接受且具备确认资格的 Evidence 支撑。

#### 修复建议与复测状态

- 修复建议：（A03:2021）优先使用参数化接口和安全 API，对输入做语义白名单校验，并按最终解释上下文编码输出。 （CWE-89 (v4.20)）使用参数化查询；动态标识符采用严格映射；数据库账号遵循最小权限。
- 复测状态：`not_recorded`（当前数据模型未记录独立的修复后复测结论；测试计划完成状态不等同于复测通过。）
- 人工备注：由分析员复核。

#### 来源审计

- AI：AnalysisRun `21` · provider `test-provider` · model `model-v2` · prompt `traffic_analysis` v3 · validation `valid`

## 5. 测试计划覆盖、未完成项与阻塞项

- 当前 revision：1
- 待更新：是（新 Evidence 到达）
- 覆盖率：33%（1/3 个节点已终结）
- 状态分布：todo 1，in_progress 0，done 1，blocked 1，skipped 0，not_applicable 0

### 未完成项

- `test:session` · 待做 · 验证会话轮换 · priority 20 · Evidence 0

### 阻塞项

- `test:admin` · 受阻 · 验证管理员路径 · priority 30 · Evidence 0 · 原因：缺少授权账号

### 已跳过 / 不适用项

> 暂无已跳过或不适用项。

## 6. 来源版本与人工复核说明

> AI 与被动规则只产生待验证假设。报告中的 confirmed 状态来自人工接受 Evidence 后的显式状态变更；仍需由具备授权和专业能力的人员复核。

### 标准版本

- cwe `4.20` · MITRE CWE 4.20（RustForge 精选知识卡） · 发布 `2026-04-30` · [标准来源](<https://cwe.mitre.org/data/index.html>)
- owasp-top10 `2021` · OWASP Top 10:2021 · 发布 `2021` · [标准来源](<https://owasp.org/Top10/2021/>)

### AI 模型与提示词版本

- AnalysisRun `21` · provider `test-provider` · model `model-v2` · prompt `traffic_analysis` v3 · input hash `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

### 规则版本

> 本报告没有规则来源 Finding。

## 附录 A. 待验证 Findings（不作为已确认结论）

### 1. [medium] 待确认的会话问题

#### 身份、目标与风险

- Finding ID：`32`
- 稳定身份：`finding:32`
- 状态：待验证
- 类型：会话管理
- 风险：`medium`　置信度：55　累计出现：1
- 来源：AI 分析（需人工复核）
- 标准引用：—
- 受影响目标：
  - `POST` `https://demo.test/login?api_key=%5BREDACTED%3Aquery_value%5D`

#### 假设依据（不等同于实际复现）

仅为待验证假设。

#### 建议验证步骤（计划性内容）

检查会话轮换。

#### 已执行复现与实际 Evidence

> 尚未关联实际 Evidence；该条目只能保留为待验证假设。

#### 修复建议与复测状态

- 修复建议：—
- 复测状态：`not_recorded`（当前数据模型未记录独立的修复后复测结论；测试计划完成状态不等同于复测通过。）

#### 来源审计

- AI：AnalysisRun `21` · provider `test-provider` · model `model-v2` · prompt `traffic_analysis` v3 · validation `valid`
