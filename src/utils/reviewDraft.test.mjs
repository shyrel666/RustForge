import test from "node:test";
import assert from "node:assert/strict";
import { reconcileDraftValue } from "./reviewDraft.ts";

test("reconcileDraftValue synchronizes an untouched draft", () => {
  assert.equal(reconcileDraftValue("medium", "medium", "high"), "high");
});

test("reconcileDraftValue preserves a locally edited draft", () => {
  assert.equal(reconcileDraftValue("critical", "medium", "high"), "critical");
});

test("reconcileDraftValue ignores unrelated external Finding updates", () => {
  assert.equal(reconcileDraftValue("local note", "", ""), "local note");
});
