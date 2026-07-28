import test from "node:test";
import assert from "node:assert/strict";
import {
  cloneReplayDraftState,
  draftStateFromRun,
  draftStateFromTraffic,
  replayWarningIsConfirmed,
  shouldApplyReplayResult,
} from "./repeaterDraft.ts";

function replayRun(overrides = {}) {
  return {
    id: 11,
    attempt_id: 7,
    session_id: 3,
    project_id: 2,
    method: "POST",
    url: "https://example.test/upload",
    request_headers: [
      { name: "Content-Type", value: "text/plain" },
      { name: "Content-Encoding", value: "gzip" },
    ],
    request_wire_body_text: null,
    request_wire_body_base64: "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA==",
    req_wire_captured_size: 28,
    req_wire_truncated: false,
    request_input: {
      encoding: "base64",
      text: null,
      base64: "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA==",
      original_size: 40,
      captured_size: 40,
      truncated: false,
      content_hash: "a".repeat(64),
    },
    request_body_text: "hello",
    request_body_base64: null,
    req_wire_size: 28,
    req_captured_size: 5,
    req_truncated: false,
    req_decode_status: "decoded_text",
    tls_policy: "strict",
    scope_decision: {
      allowed: true,
      normalized_host: "example.test",
      matched_scope: "example.test",
      match_kind: "exact",
      reason_code: null,
      reason: null,
    },
    outcome: "completed",
    error_code: null,
    error_message: null,
    status: 200,
    status_text: "OK",
    response_headers: [],
    response_body_text: "ok",
    response_body_base64: null,
    resp_wire_size: 2,
    resp_captured_size: 2,
    resp_truncated: false,
    resp_decode_status: "identity_text",
    duration_ms: 4,
    request_hash: "b".repeat(64),
    req_body_hash: "c".repeat(64),
    response_hash: "d".repeat(64),
    resp_body_hash: "e".repeat(64),
    created_at: "2026-07-28 12:00:00",
    ...overrides,
  };
}

test("restoring a compressed run uses exact wire bytes and retains Content-Encoding", () => {
  const state = draftStateFromRun(replayRun());

  assert.equal(state.draft.bodyEncoding, "base64");
  assert.equal(
    state.draft.body,
    "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA=="
  );
  assert.match(state.draft.headersRaw, /Content-Encoding: gzip/);
  assert.notEqual(state.draft.body, "hello");
  assert.equal(state.replayWarning, "");
});

test("invalid Base64 failures restore the original input instead of an empty body", () => {
  const state = draftStateFromRun(
    replayRun({
      outcome: "request_failed",
      status: null,
      request_wire_body_base64: null,
      request_body_text: null,
      req_wire_size: 0,
      req_wire_captured_size: 0,
      req_decode_status: "not_received",
      request_input: {
        encoding: "base64",
        text: null,
        base64: "%%%invalid%%%",
        original_size: 13,
        captured_size: 13,
        truncated: false,
        content_hash: "f".repeat(64),
      },
    })
  );

  assert.equal(state.draft.bodyEncoding, "base64");
  assert.equal(state.draft.body, "%%%invalid%%%");
});

test("per-session draft envelopes retain truncation confirmation metadata", () => {
  const original = draftStateFromRun(
    replayRun({
      req_wire_truncated: true,
      request_input: {
        encoding: "base64",
        text: null,
        base64: "AAEC",
        original_size: 2_000_000,
        captured_size: 4,
        truncated: true,
        content_hash: "f".repeat(64),
      },
    })
  );
  const saved = cloneReplayDraftState(original);
  original.draft.body = "changed elsewhere";
  original.replayWarning = "";

  assert.equal(saved.draft.body, "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA==");
  assert.equal(saved.bodyTruncated, true);
  assert.match(saved.replayWarning, /wire 前缀/);
});

test("a truncation confirmation is bound to one project, session, and warning", () => {
  const confirmation = {
    projectId: 2,
    sessionId: 3,
    warning: "wire body truncated",
  };

  assert.equal(
    replayWarningIsConfirmed(
      "wire body truncated",
      2,
      3,
      confirmation
    ),
    true
  );
  assert.equal(
    replayWarningIsConfirmed(
      "wire body truncated",
      2,
      4,
      confirmation
    ),
    false
  );
  assert.equal(
    replayWarningIsConfirmed("different warning", 2, 3, confirmation),
    false
  );
  assert.equal(replayWarningIsConfirmed("", 99, 99, null), true);
});

test("decode-truncated traffic retains encoding headers and requires confirmation", () => {
  const state = draftStateFromTraffic({
    id: 9,
    project_id: 2,
    method: "POST",
    url: "https://example.test/",
    host: "example.test",
    path: "/",
    status: 200,
    duration_ms: 1,
    req_wire_size: 100,
    req_captured_size: 100,
    req_truncated: true,
    req_decode_status: "decode_truncated",
    resp_wire_size: 0,
    resp_captured_size: 0,
    resp_truncated: false,
    resp_decode_status: "empty",
    rule_tags: [],
    created_at: "",
    req_headers: JSON.stringify({
      "Content-Encoding": "gzip, br",
      "Content-Type": "text/plain",
    }),
    req_body_text: "partial intermediate bytes",
    req_body_base64: null,
    resp_headers: null,
    resp_body_text: null,
    resp_body_base64: null,
  });

  assert.match(state.draft.headersRaw, /Content-Encoding: gzip, br/);
  assert.match(state.replayWarning, /不能精确还原/);
});

test("slow replay results are applied only to their original project and session", () => {
  assert.equal(shouldApplyReplayResult(2, 3, 2, 3), true);
  assert.equal(shouldApplyReplayResult(2, 4, 2, 3), false);
  assert.equal(shouldApplyReplayResult(5, 3, 2, 3), false);
  assert.equal(shouldApplyReplayResult(null, null, 2, 3), false);
});
