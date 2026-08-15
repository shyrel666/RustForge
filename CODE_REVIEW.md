# RustForge 代码审查报告

审查日期：2026-08-04
审查范围：src-tauri（Rust 后端全模块）、src（Vue3/TS 前端核心层），约 6.4 万行
方法：7 个模块域逐行审查 + 交叉依赖核验 + 高危项人工二次验证

严重度分级：高 = 安全边界被绕过 / 数据丢失或错显 / 功能实际失效；中 = 竞态、误报、一致性缺口；低 = 边界健壮性与可维护性问题。

---

## 一、高严重度问题（均已对照源码二次验证）

### H1. Mission 流程硬编码 `written_authorization_confirmed = true`，绕过书面授权强制门

`src-tauri/src/assessment/mission.rs:2679`（`contract_input_from_mission`）：

```rust
Ok(super::model::AssessmentContractInput {
    ...
    written_authorization_confirmed: true,   // 硬编码
})
```

书面授权校验只存在于 `service::create_run`（`service.rs:610-612`）：

```rust
if !preview.written_authorization_confirmed {
    return Err("[AUTHORIZATION_REQUIRED] 必须确认已获得目标的书面授权".into());
}
```

Mission v2 流程中 `confirm_context` 会经由 `contract_input_from_mission` 重建契约，该字段被无条件置 true，且 `CreateAssessmentMissionInput.written_authorization_confirmed` 是 `#[serde(default)]`（`model.rs:187-188`，默认 false），`create_mission` 本身不强制。结果：mission 路径下 `[AUTHORIZATION_REQUIRED]` 检查永远不会触发。对安全测试工具而言，这是自声明合规门的自我绕过。

修复：`create_mission` 即要求该标志为 true 并持久化到 mission 行；`contract_input_from_mission` 使用持久化值。

### H2. `redact_url` 不处理 URL userinfo，`user:password@host` 凭据原样发给外部 LLM

`src-tauri/src/ai/redaction.rs:254-298`：函数只剥离 fragment、改写 query，从不调用 `parsed.username()`/`set_password()`；`parsed.to_string()` 原样保留 userinfo。调用方包括 `ai/context.rs:466-471`（AI 分析上下文）和 `evidence/service.rs:653,792`（证据快照）。凡 `https://user:token@host` 形式的请求，凭据明文进入 LLM 请求并写入证据快照。

修复：解析成功后检测 userinfo 并替换为 `[REDACTED:url_credentials]@`，记入 manifest。

### H3. 结构化脱敏只做"整串"检测，JSON/form/header 值内嵌的秘密全部漏检

`redaction.rs:236-252`（`redact_or_disclose_value`）：`secret_value_kind` 的所有模式（`sk-` 前缀、JWT 三段式、`bearer `、高熵字符集）都锚定在整个值上。但同文件 `redact_fallback_text`（603-689 行）明明实现了子串级正则扫描（JWT、AKIA、`access_token=` 等），结构化路径（content-type 为 JSON/form/headers，即绝大多数流量）从不调用它。

典型泄漏样例：`{"message":"令牌 eyJhbGci... 已失效"}`、`{"callback":"https://x.test/cb?access_token=..."}`、非敏感 header 里内嵌的带凭据 URL。错误回显 token 是业务接口最常见的响应形态，命中概率高。

修复：对结构化解析后的每个字符串叶子节点，在整串检测失败后追加子串扫描。

### H4. URL path 段中的 token 完全不扫描

`redact_url` 对 path 原样保留，调用方在其输出上不再做任何秘密扫描。REST 风格把凭据放 path 很常见：Slack webhook（`/services/T0000/B0000/XXXX...`）、`/sessions/{token}/profile`、OAuth 回调路径带 code 等，均直接发送给外部 LLM。

修复：对 `parsed.path_segments()` 逐段做与 fallback 同强度的候选扫描。

### H5. 自动更新下载完成后从不调用 `relaunch()`，更新实际不生效

`src/services/appUpdater.ts:24-27`、`src/services/appUpdaterCore.ts:139-156`：`downloadAndInstall()` 完成后仅把 status 置为 `"installing"`。全仓库检索确认 `relaunch`、`@tauri-apps/plugin-process` 均不存在。Tauri v2 updater 官方流程要求下载完成后调用 `relaunch()` 才能应用更新。后果：UI 永久停在"正在安装"（busy 恒 true、按钮禁用），用户以为更新成功实际仍运行旧版本。`appUpdaterCore.test.mjs:40-55` 断言 `status === "installing"` 需同步修正。

---

## 二、中严重度问题

### 代理与证书（proxy/）

**M-P1. 代理热路径在 tokio 工作线程上做阻塞式 r2d2/SQLite I/O，并静默丢流量、fail-open。**
`proxy/interceptor.rs:109-114`：`authorize_host` 在 async 的 `handle_request`/`should_intercept_connect` 中直接调用阻塞的 `self.db.get()`（池仅 8 连接、默认 30s 超时）。`store_and_emit`（136 行）用 `let Ok(db) = self.db.get() else { return };`——池超时后这条流量**不落库、无日志**；`authorize_host` 的存储错误还被当作"Scope 外"直接放行，把存储故障与白名单拒绝混为一谈。建议 scope 判定改内存缓存或 `spawn_blocking`，落库失败至少记录。

**M-P2. CA 证书与私钥从不校验配对。**
`proxy/ca.rs:401-411`：rcgen 0.14 的 `Issuer::from_ca_cert_pem` 不校验私钥是否对应证书公钥（已核对 rcgen 源码）。一旦磁盘上 `rustforge-ca.cer` 与 `.key` 错配（手工改动、部分损坏或下述竞态），`build_authority` 成功返回，但之后所有站点证书用错私钥 → MITM 握手对全部站点静默失败，程序层无任何报错。另外 `ensure_ca` 无跨调用锁，key/cert 分两次原子 rename，首次并发生成可产出"keyB + certA"错配对（`ca.rs:357,390-391`）。建议加配对自校验 + `ensure_ca` 进程内互斥。

### 规则引擎（rules/）

**M-R1. `missing` 条件把"二进制/解码失败正文"当作"字段确定不存在"的完整证据。**
`rules/engine.rs:128-131,641-645,734-739`：`body_text` 只对 `empty|identity_text|decoded_text` 三种 decode_status 返回正文，其余 9 种（`identity_binary`、`decode_failed` 等）候选为空且 `truncated=false`，`missing` 以满置信度命中。作者专门处理了截断正文（限置信度 + 回归测试），却漏掉非文本这一整类。对图片/二进制响应，任何 body 上的 missing 规则都会误报成 Finding。

**M-R2. worker 线程无 panic 防护：panic 后永久静默罢工，`worker_running` 恒报 true。**
`rules/worker.rs:286-295`：`run` 循环无 `catch_unwind`，`process` panic 则线程退出且 `running.store(false)` 不执行；队列中未消费任务丢失、`queue_depth` 虚高，诊断接口报告一切正常。被动初筛功能静默死亡而流量照常落库。建议 `catch_unwind` + RAII guard 保证任何退出路径清状态。

**M-R3. 规则包加载缺字段长度校验，运行期写库才撞 DB CHECK，整次求值静默丢失且不重试。**
`rules/loader.rs:287-333` 只查非空，而 `v1.sql:860-879` 对 pack_id/rule_id/field_path 等有 200/120/1000 长度 CHECK。超长 rule_id 或超长 json_path 的包能通过加载，写 `finding_rule_hits` 时事务整体回滚，只记一次 failed 计数（`worker.rs:299-306`），该流量初筛审计永久缺失。

**M-R4. 条件树只限深度（16）不限宽度。**
`loader.rs:390-426`：深度 2、含 10 万个 regex 条件的规则能通过全部闸门；每正则编译产物上限 1MiB，加载期 CPU/内存无上界。不受信规则包可加载时 OOM。建议加每规则/每包条件节点总数与正则总数上限。

**M-R5. `jwt_metadata` 提取器无 target 校验；method/url/status/content_type 上任何提取器/name 被静默忽略。**
`loader.rs:484`、`engine.rs:404-416,549-572`：`{"target":"status","extractor":{"kind":"jwt_metadata",...}}` 能通过加载，运行期却变成对状态码字符串比较——规则声明 A 行为、实际执行 B 行为，无诊断。

### 评估流程（assessment/）

**M-A1. 用户排除路径可被百分号编码绕过。**
`policy.rs:158-164,245-251`：`path_matches_prefix` 用 `authorized.url.path()`（保持百分号编码）与明文排除项比较，`/%61dmin/archive` 不命中 `/admin/archive`。同文件的破坏性路径检查专门做了 `percent_decode_repeatedly`（3 轮解码），两处防护标准不一致。`discovery.rs:1524-1530` 的 `path_matches_claim`（资源归属判定）同病。

**M-A2. run 状态先提交、mission 同步后执行：revision 竞态可把 mission 永久卡在活动状态。**
`service.rs:711-713`：`transition_run` 提交 run 状态后才调 `mission::sync_from_run`；后者在事务外读 revision（`mission.rs:1034-1047`），等待 IMMEDIATE 锁期间若其他写者（如 `send_message`）bump revision，UPDATE 失配返回 `[REVISION_CONFLICT]`，但 run 已提交为终态，runner 的 `finalize_error` 见 run 非活动态什么也不做。mission 卡在 executing 且无任何恢复路径（重启恢复逻辑只处理活动 run）。建议同一事务内完成两者，或 sync 失败时强制转入可恢复状态。

**M-A3. `link_run` 不检查 UPDATE 影响行数；失败时无清理，遗留永久阻塞的僵尸 run。**
`mission.rs:796-809`：revision 事务外读取，UPDATE 影响 0 行被忽略并照常提交 → `active_run_id` 恒 NULL → 无法 stop、人工配方选择报错、mission 计数永远为 0。`commands.rs:4052-4053` 中 `create_run` 成功而 `link_run` 失败时无任何清理：新 run 以 queued 活动态靠唯一索引阻塞之后所有评估（报 `[ASSESSMENT_BUSY]`），直到应用重启。

**M-A4. "目标不稳定"停止条件漏计连接失败。**
`executor.rs:447-465`：只有 status≥500 和 `TIMEOUT` 计入 `consecutive_target_failures`；目标宕机（`CONNECT_FAILED`）每次重置计数器，`TargetUnstable` 永不触发，会以 2 RPS 敲打不可达目标直到 300 次预算耗尽。

### 存储与迁移（storage/）

**M-S1. v0（未定版）数据库升级前不创建备份。**
`storage/db.rs:70-74`：`from_version > 0` 把 user_version=0 的库排除在 `VACUUM INTO` 快照之外，但 v0 是"未版本化的开发 schema"且可能含真实数据（测试明确要求 v0 升级保数据）。v0→v4 是破坏性最强的路径（v4 重建两张父表），却恰好没有恢复点。

**M-S2. v4 迁移把 v3 运行中的非终态 status 原样灌入 legacy mission。**
`v4.sql:467-512`：升级时正在运行的 run（executing 等）被复制进 legacy mission，永久占用全局唯一部分索引 `idx_assessment_missions_one_network_active` 的槽位——新 mission 无法进入活动状态，迁移正确性依赖迁移之外的启动恢复代码必然成功。建议 backfill 时把非终态收敛为 `interrupted`。

**M-S3. v4 表重建用 `INSERT ... SELECT *` 按位置复制。**
`v4.sql:49-50,69-70`：当前列序已核对一致、今天没有错，但未来任何列序调整都会导致静默数据错位（同为 TEXT 的列互换连 CHECK 都不拦）。应显式列名。

**M-S4. `json_contains_sensitive_field` 的非法 JSON 兜底只匹配 apikey/authorization。**
`secrets.rs:155-166`：畸形但含 `"password":"..."` 的设置可逃过"旧版明文秘密拒绝启动"基线。兜底子串集应与 `is_sensitive_setting_key` 保持一致。

### 报告与命令层（report.rs / commands.rs）

**M-C1. 报告生成是同步 command，阻塞 IPC 线程，且 markdown 预览也构建全量 JSON。**
`commands.rs:4120-4128`、`report.rs:1219-1237`：大项目生成报告时 UI 冻结数秒至数十秒；同时渲染 markdown + pretty JSON 再丢弃 JSON，双倍内存。代码库自己的注释承认同步 command 会阻塞 WebView 消息循环（CA 命令因此改成 async+spawn_blocking），报告命令没跟上。

**M-C2. 全部时间戳存无时区标记的本地时间。**
`v1.sql:67-68`：`strftime(...,'now','localtime')`。跨时区/夏令时切换后时间不再单调，报告时间线字符串排序、MIN/MAX 时间范围、按日趋势分桶全部失真；且报告头 `generated_at` 带时区偏移而正文时间无标记。作为证据链的报告时间不可靠。建议统一存 UTC。

**M-C3. 共享 Evidence 导致报告重复计数。**
`report.rs:2689-2702,1429-1433`：schema 明确允许一条 Evidence 关联多个 Finding，但时间线按 finding 展开（完全重复的条目）、`accepted_supporting_evidence` 用 flat_map 重复计数、快照整块重复渲染。应按 `evidence.id` 去重。

**M-C4. `delete_finding` 物理删除且无审计、无事件。**
`commands.rs:2336-2341`：裸 `DELETE FROM findings`，FK 级联连同全部审计事件与证据链接一起删除，confirmed 结论也能无痕删除——对以"不可变审计"为卖点的工具是自我否定的后门；且不 emit 事件导致前端状态不一致。其余所有 Finding 变更路径均走事务+审计事件。

**M-C5. `start_proxy` 绕过端口校验 + 启动 TOCTOU。**
`commands.rs:1186-1194`：设置层要求代理端口 ≥1024（`set_setting` 校验），但 `start_proxy` 是独立 IPC 入口，可传任意 u16（含 80/443）。`proxy/mod.rs:72-106` 检查与置位之间锁被释放，两次并发启动都通过检查、都成功 bind，第二个 shutdown 句柄覆盖第一个 → 第一个代理实例永远无法停止、端口永久占用。

### AI 与证据（ai/ evidence/）

**M-E1. 用户文本长度校验发生在脱敏之前，脱敏标记膨胀后撞 DB CHECK。**
`evidence/service.rs:963-977`：先校验 ≤4000 字符再脱敏，而 `redact_fallback_text` 把 1~3 字符的值替换成 26 字符的 `[REDACTED:sensitive_field]`，一段 3900 字符的 observation 脱敏后可远超 4000，合法操作以晦涩的 SQLite 约束错误失败。

**M-E2. `parse_llm_json` 用"第一个开符 + 最后一个闭符"截取。**
`ai/json.rs:16-29`：JSON 后带含 `}` 的尾注、或 JSON 前散文含 `[...]` 时，合法响应被误拒，浪费重试计费甚至整次分析作废（方向是错误拒绝而非错误接受，有 deny_unknown_fields 兜底）。建议括号平衡扫描。

**M-E3. digest 中 `stable_key`/`locks`/`prerequisites` 未脱敏直接回灌规划提示词。**
`ai/digest.rs:535-557`：只有 title 被脱敏。stable_key 可来自模型输出（`planner.rs` 的 sanitize 只查长度），一旦被写入秘密，每轮 digest 都绕过脱敏发回 LLM——二次泄漏通道。建议 stable_key 施加字符集白名单 + 脱敏。

### 前端状态层（Vue/Pinia）

**M-F1. traffic store 无过期响应守卫。**
`stores/traffic.ts:45-62,83-91`：`load()` 无 generation 守卫（findings store 有、repeater store 有，traffic 没有），快速切换项目时旧响应覆盖新数据，显示错误项目的流量与错误 total；`openDetail()` 同理，且错误 detail 会被下游 `sendToRepeater`/AI 分析使用——对安全工具是典型的跨项目数据错显。

**M-F2. assessmentMission store 变更操作不推进 `_generation`。**
`stores/assessmentMission.ts:434-439,302-320`：事件触发的 100ms 延迟 `loadSelected` 在途时，用户批准动作写入新 detail，随后旧快照到达并通过所有守卫，把批准前的旧状态覆盖回来——已批准动作在界面上回退。多个 action 的 `previewAssessmentMissionContext` await 后也未复查工作区。

**M-F3. project store `select()` 未串行化。**
`stores/project.ts:26-29`：快速切换时后端持久化的当前项目可能与前端不一致并影响下次启动恢复。repeater store 专门为同类问题做了串行化队列（注释明确），project store 没有。

**M-F4. 自动更新检查的"一次性配额"在失败时也被消耗。**
`services/appUpdaterCore.ts:84-92`：`automaticChecked` 在发起检查前置 true，开机自启时网络未就绪导致首次检查失败后，整个会话不再有任何自动检查——用户永远收不到更新提示。失败应允许重试；在途检查的早退也应返回 promise 而非瞬时快照。

---

## 三、低严重度问题（摘要）

| 位置 | 问题 |
|---|---|
| replay/service.rs:1858 | 用户提供的 `Host` 头被静默丢弃，Host 注入/虚拟主机类测试无法在 Repeater 构造 |
| replay/service.rs:980 | 手动重放无响应体读取上限且全量哈希（Assessment 路径有界，两处策略不一致） |
| replay/service.rs:539 | `cancel.changed()` 丢弃 Result，"发送端被 drop"误判为用户主动取消 |
| proxy/ca.rs:431 | `is_trusted()` 对 certutil 全量输出做子串匹配，脆弱 |
| engine.rs:784 | `Not` 的证据文本恒为"字段不存在"，值不满足场景误导人工复核 |
| engine.rs:797 | 嵌套 `for_each` 忽略外层实例作用域，与 schema 注释承诺矛盾 |
| loader.rs:494 | 空正则被接受，语义恒真（`contains` 拒绝空值，regex 无对应检查） |
| worker.rs:521 | 双 worker 并发时 Finding 唯一索引竞态，碰撞方事务回滚且不重试 |
| fingerprint.rs:14 | 指纹去端口，同 host 不同端口服务被合并去重（设计风险） |
| mission.rs:650,845 | `decide_action`/`request_stop` UPDATE 未校验影响行数，审计 revision 可不一致 |
| mission.rs:939 | mission 停止后仍可 link handoff 结果，复活已取消动作 |
| executor.rs:273 | 丢弃授权结果的已解析 Url、把原始字符串重新传给传输层，违反 scope.rs 明示契约（TOCTOU 隐患） |
| scope.rs:264 | URL 授权路径不拒绝含 `*` 的主机，与代理路径不一致（不可利用） |
| verifier.rs:393 | JWT 验证只认 401/403，重定向式认证的签名绕过会假阴性 |
| verifier.rs:114 | `HttpOnly=true` 等带值属性被判为缺失，产生假阳性 |
| secrets.rs:193 | 日志脱敏不覆盖 Cookie 头与查询串凭据 |
| migrations.rs:1157 | 每次启动（含最新版）全量 quick_check + foreign_key_check，启动成本随数据量线性增长 |
| tree/service.rs:1565 | archive 递归 CTE 用 UNION ALL，若存在环（触发器不防多节点环）会挂死；应用层已兜底 |
| redaction.rs:542 | 非 CRLF multipart 解析中止后回退全量文本扫描，违反"文件内容默认不发送"策略 |
| validation.rs:216 | 重复的 evidence_refs 被误判 ungrounded，置信度错误压至 ≤25 |
| client.rs:185 | LLM 响应体无大小上限；total_tokens 缺失时记 0 |
| report.rs:1312 | `is_suspected` 只判 producer，与注释定义不符；limitations 引用的 pending 数在正文不存在 |
| commands.rs:2004,1135 | `.ok()`/`.or(Ok(None))` 吞掉真实 DB 错误（同文件 get_setting 有正确范式） |
| commands.rs:1407 | `list_traffic` 的 limit 无上限（同类接口有 500/200 上限） |
| commands.rs:3717 | `confirm_assessment_mission_context` 漏查 `ai_enabled` 全局开关（兄弟命令都查） |
| stores 四个 bindEvents | 并发绑定竞态可致监听器泄漏、事件重复处理 |
| findings.ts:79 | 状态更新失败时 generation 已推进，丢弃在途 refresh 结果致列表过期 |
| repeaterDraft.ts:60 | 头部 JSON 解析失败静默丢弃全部头部（含鉴权头）且无警告 |
| router/index.ts | 无 catch-all 路由；meta.title 死配置；stores/assessment.ts 整体为死代码 |

---

## 四、核查后确认无问题的部分（避免误报）

以下方向经逐项核验为正确实现，值得肯定：

- SQL 注入：全部 `format!` 构造 SQL 的表名均来自编译期常量，其余查询全部参数化。
- 迁移原子性：每步迁移在单个 IMMEDIATE 事务内完成 DDL + 校验 + user_version，失败整体回滚。
- ReDoS 防护真实有效：regex crate 线性时间 + 加载期四道闸门（512B 源码、1MiB size_limit、nest_limit=24）+ 运行期 50ms 协作式预算。
- 范围匹配核心逻辑：通配符正确拒绝 `evilexample.com`；IDN/punycode、IPv4 整数形式（`2130706433`）、userinfo、反斜杠等绕过向量均有处理；空 scope fail-closed。
- 传输层校验时机：`execute_assessment_request` 先双重授权后发包，禁止重定向、30s 超时、1MiB 响应上限。
- body_capture 截断逻辑无 off-by-one；解压炸弹有 decoded 上限。
- AI 输出校验不可绕过：`deny_unknown_fields`、无 default、confidence 为 u8、后端字段无法由模型注入。
- API key 不入日志：SecretString Debug 遮盖，所有错误经 redact_sensitive。
- 未发现持锁跨 await、未发现 command 中可触发的 panic、未发现路径穿越面。
- 前端 semver 比较不存在自研逻辑（由 updater 插件内部判定），无 1.10<1.9 类错误。

---

## 五、修复优先级建议

1. H1 授权门绕过（一行硬编码，合规边界）
2. H2-H4 脱敏三连（数据发往外部 LLM 前的最后防线）
3. H5 更新流程闭环（装 plugin-process + relaunch）
4. M-A2/M-A3 状态机竞态（不可恢复的卡死与僵尸 run）
5. M-R2 worker panic 防护（完全静默的功能死亡）
6. M-A1 排除路径解码、M-P1 代理热路径、M-C4 delete_finding 审计
7. 其余中危按模块批量修复；低危项可在常规迭代中消化

总体评价：代码工程质量整体较高——不可变审计触发器、乐观 revision、fail-closed 校验、ReDoS 多层闸门、授权范围的多向量防护都设计得相当严谨。问题集中在三类：跨流程复制粘贴导致的行为不一致（授权门、端口校验、ai_enabled 检查、脱敏黑名单宽窄）、"证据缺失"与"缺失证据"的语义混淆（missing 条件、长度校验时机）、以及并发窗口内的写后读 TOCTOU（revision、link_run、start_proxy）。建议为这三类模式建立项目级 lint/评审检查点。
