<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  createFindingEvidence,
  listFindingEvidence,
  listFindingEvents,
  setFindingEvidenceAccepted,
  updateFindingReview,
  updateFindingStatus,
  type Evidence,
  type EvidenceSourceType,
  type Finding,
  type FindingEvent,
  type FindingTrafficRef,
} from "../api/tauri";
import { reconcileDraftValue } from "../utils/reviewDraft";

const props = defineProps<{
  finding: Finding;
  traffic: FindingTrafficRef[];
}>();

const emit = defineEmits<{
  "finding-updated": [finding: Finding];
}>();

interface SourceCandidate {
  key: string;
  type: EvidenceSourceType;
  id: number;
  label: string;
}

const loading = ref(false);
const savingEvidence = ref(false);
const savingReview = ref(false);
const evidence = ref<Evidence[]>([]);
const events = ref<FindingEvent[]>([]);
const selectedSource = ref("");
const observation = ref("");
const conclusionReason = ref("");
const reviewReason = ref("");
const severity = ref(props.finding.severity);
const analystNotes = ref(props.finding.analyst_notes);
let loadGeneration = 0;

const sourceCandidates = computed<SourceCandidate[]>(() => {
  const result: SourceCandidate[] = [];
  const seen = new Set<string>();
  const add = (
    type: EvidenceSourceType,
    id: number | null,
    label: string
  ) => {
    if (id === null || id <= 0) return;
    const key = `${type}:${id}`;
    if (seen.has(key)) return;
    seen.add(key);
    result.push({ key, type, id, label });
  };

  add(
    "traffic",
    props.finding.traffic_id,
    `首次关联流量 #${props.finding.traffic_id}`
  );
  for (const item of props.traffic) {
    add("traffic", item.traffic_id, `流量 #${item.traffic_id} · ${item.method} ${item.url}`);
  }
  add(
    "analysis_run",
    props.finding.analysis_run_id,
    `AI 分析运行 #${props.finding.analysis_run_id}`
  );
  return result;
});

const chosenSource = computed(
  () =>
    sourceCandidates.value.find(
      (candidate) => candidate.key === selectedSource.value
    ) ?? null
);

async function loadPanel() {
  const findingId = props.finding.id;
  const generation = ++loadGeneration;
  loading.value = true;
  try {
    const [nextEvidence, nextEvents] = await Promise.all([
      listFindingEvidence(findingId),
      listFindingEvents(findingId),
    ]);
    if (generation !== loadGeneration || findingId !== props.finding.id) return;
    evidence.value = nextEvidence;
    events.value = nextEvents;
  } catch (error) {
    if (generation === loadGeneration) ElMessage.error(String(error));
  } finally {
    if (generation === loadGeneration) loading.value = false;
  }
}

function isDismissed(error: unknown) {
  return error === "cancel" || error === "close";
}

async function addEvidence() {
  const source = chosenSource.value;
  if (!source) {
    ElMessage.warning("请选择仍可读取的证据来源");
    return;
  }
  if (!observation.value.trim()) {
    ElMessage.warning("请填写本次人工观察结果");
    return;
  }
  savingEvidence.value = true;
  try {
    await createFindingEvidence(
      props.finding.id,
      source.type,
      source.id,
      observation.value
    );
    observation.value = "";
    await loadPanel();
    ElMessage.success("已保存独立脱敏 Evidence 快照");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    savingEvidence.value = false;
  }
}

async function toggleAccepted(item: Evidence) {
  const next = !item.accepted;
  try {
    const { value } = await ElMessageBox.prompt(
      next ? "说明为什么接受这条证据" : "说明为什么撤销这条证据",
      next ? "人工接受 Evidence" : "撤销 Evidence",
      {
        confirmButtonText: next ? "接受" : "撤销",
        cancelButtonText: "取消",
        inputType: "textarea",
        inputPlaceholder: "必填；内容会在本地做保守脱敏",
        inputValidator: (input) => Boolean(input.trim()) || "请填写审计原因",
      }
    );
    await setFindingEvidenceAccepted(
      props.finding.id,
      item.id,
      next,
      value
    );
    await loadPanel();
    ElMessage.success(next ? "Evidence 已被人工接受" : "Evidence 已撤销接受");
  } catch (error) {
    if (!isDismissed(error)) ElMessage.error(String(error));
  }
}

async function changeStatus(status: Finding["status"]) {
  try {
    const updated = await updateFindingStatus(
      props.finding.id,
      status,
      conclusionReason.value
    );
    emit("finding-updated", updated);
    conclusionReason.value = "";
    await loadPanel();
    ElMessage.success("人工结论已更新");
  } catch (error) {
    ElMessage.error(String(error));
  }
}

async function saveReview() {
  savingReview.value = true;
  try {
    const updated = await updateFindingReview(
      props.finding.id,
      severity.value,
      analystNotes.value,
      reviewReason.value
    );
    severity.value = updated.severity;
    analystNotes.value = updated.analyst_notes;
    emit("finding-updated", updated);
    reviewReason.value = "";
    await loadPanel();
    ElMessage.success("复核信息已保存");
  } catch (error) {
    ElMessage.error(String(error));
  } finally {
    savingReview.value = false;
  }
}

function sourceLabel(item: Evidence) {
  const labels: Record<EvidenceSourceType, string> = {
    traffic: "流量",
    analysis_run: "AI 分析运行",
    replay_run: "重放运行",
  };
  return `${labels[item.source_type]} #${item.source_id}`;
}

function eventLabel(event: FindingEvent) {
  const labels: Record<FindingEvent["event_type"], string> = {
    created: "创建待验证假设",
    status_changed: "状态变更",
    severity_changed: "严重度变更",
    notes_changed: "人工备注变更",
    evidence_accepted: "接受 Evidence",
    evidence_revoked: "撤销 Evidence",
  };
  return labels[event.event_type];
}

function eventChange(event: FindingEvent) {
  if (event.event_type === "created") return event.new_value ?? "pending";
  if (event.old_value === null && event.new_value === null) return "";
  return `${event.old_value || "（空）"} → ${event.new_value || "（空）"}`;
}

function prettySnapshot(item: Evidence) {
  return JSON.stringify(item.redacted_snapshot, null, 2);
}

watch(
  sourceCandidates,
  (candidates) => {
    if (!candidates.some((candidate) => candidate.key === selectedSource.value)) {
      selectedSource.value = candidates[0]?.key ?? "";
    }
  },
  { immediate: true }
);

watch(
  () => props.finding.severity,
  (next, previous) => {
    // 只有未编辑的字段跟随外部更新；本地草稿与旧持久值不同时必须保留。
    severity.value = reconcileDraftValue(severity.value, previous, next);
  }
);

watch(
  () => props.finding.analyst_notes,
  (next, previous) => {
    analystNotes.value = reconcileDraftValue(
      analystNotes.value,
      previous,
      next
    );
  }
);

watch(
  () => props.finding,
  (next, previous) => {
    if (!previous || next.id !== previous.id) {
      severity.value = next.severity;
      analystNotes.value = next.analyst_notes;
      conclusionReason.value = "";
      reviewReason.value = "";
    }
    void loadPanel();
  },
  { immediate: true }
);
</script>

<template>
  <div v-loading="loading" class="evidence-panel">
    <section class="evidence-region">
      <div class="region-heading">
        <div>
          <div class="region-kicker">01 · Hypothesis</div>
          <h4>假设来源</h4>
        </div>
        <el-tag type="warning" effect="plain">尚需人工验证</el-tag>
      </div>
      <div class="fact-grid">
        <div>
          <span>生成器</span>
          <strong>{{ finding.source === "ai" ? "AI 分析" : "被动规则" }}</strong>
        </div>
        <div>
          <span>模型置信度</span>
          <strong>{{ finding.confidence }} / 100</strong>
        </div>
        <div>
          <span>首次流量</span>
          <strong>{{ finding.traffic_id ? `#${finding.traffic_id}` : "来源已删除" }}</strong>
        </div>
        <div>
          <span>分析运行</span>
          <strong>{{
            finding.analysis_run_id ? `#${finding.analysis_run_id}` : "不适用"
          }}</strong>
        </div>
      </div>
      <div class="hypothesis-copy">
        <strong>命中说明</strong>
        <p>{{ finding.reasoning || "（无）" }}</p>
        <strong>建议验证步骤</strong>
        <p>{{ finding.verify_steps || "（无）" }}</p>
      </div>
      <code v-if="finding.fingerprint" class="hash">
        fingerprint · {{ finding.fingerprint }}
      </code>
    </section>

    <section class="evidence-region">
      <div class="region-heading">
        <div>
          <div class="region-kicker">02 · Evidence</div>
          <h4>实际证据</h4>
        </div>
        <el-tag
          :type="
            evidence.some(
              (item) => item.accepted && item.qualifies_for_confirmation
            )
              ? 'success'
              : 'info'
          "
          effect="plain"
        >
          {{
            evidence.filter(
              (item) => item.accepted && item.qualifies_for_confirmation
            ).length
          }}
          条可用于确认且已接受
        </el-tag>
      </div>

      <div class="evidence-form">
        <el-select
          v-model="selectedSource"
          placeholder="选择来源"
          :disabled="!sourceCandidates.length"
        >
          <el-option
            v-for="candidate in sourceCandidates"
            :key="candidate.key"
            :label="candidate.label"
            :value="candidate.key"
          />
        </el-select>
        <el-input
          v-model="observation"
          type="textarea"
          :rows="3"
          maxlength="4000"
          show-word-limit
          placeholder="记录实际观察到的现象。URL、Header、正文和此说明都会在本地脱敏后保存。"
        />
        <div class="form-actions">
          <span class="muted">快照上限 64 KiB，不复制原始大正文。</span>
          <el-button
            type="primary"
            :loading="savingEvidence"
            :disabled="!sourceCandidates.length"
            @click="addEvidence"
          >
            保存 Evidence
          </el-button>
        </div>
      </div>

      <div v-if="evidence.length" class="evidence-list">
        <article v-for="item in evidence" :key="item.id" class="evidence-card">
          <div class="evidence-card__top">
            <div>
              <strong>Evidence #{{ item.id }} · {{ sourceLabel(item) }}</strong>
              <div class="meta">
                {{ item.created_at }} · {{ item.created_by }}
              </div>
            </div>
            <div class="evidence-tags">
              <el-tag
                size="small"
                :type="item.source_available ? 'info' : 'warning'"
                effect="plain"
              >
                {{ item.source_available ? "来源可用" : "来源已删除 · 快照保留" }}
              </el-tag>
              <el-tag
                size="small"
                :type="item.accepted ? 'success' : 'info'"
                effect="dark"
              >
                {{ item.accepted ? "人工已接受" : "未接受" }}
              </el-tag>
              <el-tag
                v-if="!item.qualifies_for_confirmation"
                size="small"
                type="warning"
                effect="plain"
              >
                仅审计 · 不可单独确认
              </el-tag>
            </div>
          </div>
          <p class="observation">{{ item.observation }}</p>
          <code class="hash">sha256 · {{ item.content_hash }}</code>
          <p v-if="item.acceptance_note" class="acceptance-note">
            接受/撤销说明：{{ item.acceptance_note }}
          </p>
          <div class="evidence-card__actions">
            <el-button
              size="small"
              :type="item.accepted ? 'warning' : 'success'"
              plain
              @click="toggleAccepted(item)"
            >
              {{
                item.accepted
                  ? "撤销接受"
                  : item.qualifies_for_confirmation
                    ? "接受为验证证据"
                    : "接受为审计记录"
              }}
            </el-button>
          </div>
          <el-collapse>
            <el-collapse-item title="查看脱敏快照" :name="item.id">
              <pre>{{ prettySnapshot(item) }}</pre>
            </el-collapse-item>
          </el-collapse>
        </article>
      </div>
      <el-empty v-else :image-size="54" description="尚未保存实际 Evidence" />
    </section>

    <section class="evidence-region">
      <div class="region-heading">
        <div>
          <div class="region-kicker">03 · Analyst decision</div>
          <h4>人工结论</h4>
        </div>
        <el-tag
          :type="
            finding.status === 'confirmed'
              ? 'success'
              : finding.status === 'rejected'
                ? 'info'
                : 'warning'
          "
        >
          {{
            finding.status === "confirmed"
              ? "已确认"
              : finding.status === "rejected"
                ? "误报"
                : "待验证"
          }}
        </el-tag>
      </div>

      <el-input
        v-model="conclusionReason"
        type="textarea"
        :rows="2"
        maxlength="4000"
        show-word-limit
        placeholder="本次状态变更原因（标记误报时必填）"
      />
      <div class="decision-actions">
        <el-button
          type="success"
          :disabled="finding.status === 'confirmed'"
          @click="changeStatus('confirmed')"
        >
          确认 Finding
        </el-button>
        <el-button
          type="info"
          :disabled="finding.status === 'rejected'"
          @click="changeStatus('rejected')"
        >
          标记误报
        </el-button>
        <el-button
          type="warning"
          plain
          :disabled="finding.status === 'pending'"
          @click="changeStatus('pending')"
        >
          重置待验证
        </el-button>
      </div>
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="严重度表示风险，置信度表示假设可信程度；二者不会互相覆盖。"
      />

      <div class="review-form">
        <label>
          <span>人工严重度</span>
          <el-select v-model="severity">
            <el-option
              v-for="item in ['critical', 'high', 'medium', 'low', 'info']"
              :key="item"
              :label="item"
              :value="item"
            />
          </el-select>
        </label>
        <label class="review-notes">
          <span>分析员备注</span>
          <el-input
            v-model="analystNotes"
            type="textarea"
            :rows="3"
            maxlength="4000"
            show-word-limit
          />
        </label>
        <label class="review-notes">
          <span>本次修改说明（可选）</span>
          <el-input v-model="reviewReason" maxlength="4000" />
        </label>
        <div class="form-actions">
          <span class="muted">备注会保守脱敏，变更前后值写入不可变历史。</span>
          <el-button type="primary" :loading="savingReview" @click="saveReview">
            保存复核信息
          </el-button>
        </div>
      </div>

      <div class="history">
        <h5>Finding 历史</h5>
        <el-timeline v-if="events.length">
          <el-timeline-item
            v-for="event in events"
            :key="event.id"
            :timestamp="event.created_at"
            placement="top"
          >
            <strong>{{ eventLabel(event) }}</strong>
            <div v-if="eventChange(event)" class="event-change">
              {{ eventChange(event) }}
            </div>
            <div v-if="event.reason" class="event-reason">{{ event.reason }}</div>
            <div class="meta">{{ event.actor }} · event #{{ event.id }}</div>
          </el-timeline-item>
        </el-timeline>
        <span v-else class="muted">暂无历史。</span>
      </div>
    </section>
  </div>
</template>

<style scoped>
.evidence-panel {
  display: grid;
  gap: 14px;
  margin-top: 16px;
}
.evidence-region {
  padding: 14px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-raised);
}
.region-heading,
.evidence-card__top,
.form-actions,
.evidence-card__actions,
.decision-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.region-heading {
  margin-bottom: 12px;
}
.region-heading h4,
.history h5 {
  margin: 2px 0 0;
  color: var(--rf-text-primary);
}
.region-kicker {
  color: var(--rf-text-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.fact-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}
.fact-grid > div {
  display: grid;
  gap: 3px;
  padding: 9px;
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-base);
}
.fact-grid span,
.review-form label > span {
  color: var(--rf-text-muted);
  font-size: 11px;
}
.hypothesis-copy {
  margin-top: 12px;
}
.hypothesis-copy p,
.observation,
.acceptance-note,
.event-reason {
  white-space: pre-wrap;
  word-break: break-word;
}
.hypothesis-copy p {
  margin: 4px 0 10px;
  color: var(--rf-text-secondary);
}
.evidence-form,
.review-form {
  display: grid;
  gap: 10px;
}
.evidence-list {
  display: grid;
  gap: 10px;
  margin-top: 12px;
}
.evidence-card {
  padding: 12px;
  border: 1px solid var(--rf-border);
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-base);
}
.evidence-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  justify-content: flex-end;
}
.meta,
.muted {
  color: var(--rf-text-muted);
  font-size: 11px;
}
.hash {
  display: block;
  margin-top: 8px;
  color: var(--rf-text-secondary);
  font-size: 11px;
  overflow-wrap: anywhere;
}
.acceptance-note,
.event-reason {
  color: var(--rf-text-secondary);
  font-size: 12px;
}
.evidence-card__actions,
.decision-actions {
  justify-content: flex-start;
  margin: 10px 0;
}
pre {
  max-height: 360px;
  margin: 0;
  padding: 10px;
  overflow: auto;
  border-radius: var(--rf-radius-control);
  background: var(--rf-bg-base);
  color: var(--rf-text-secondary);
  font-size: 11px;
  white-space: pre-wrap;
  word-break: break-word;
}
.review-form {
  margin-top: 12px;
}
.review-form label {
  display: grid;
  gap: 5px;
}
.review-notes {
  grid-column: 1 / -1;
}
.history {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid var(--rf-border);
}
.event-change {
  margin-top: 3px;
  color: var(--rf-text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
}
@media (max-width: 900px) {
  .fact-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .form-actions,
  .region-heading,
  .evidence-card__top {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
