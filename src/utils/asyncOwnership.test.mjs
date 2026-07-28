import test from "node:test";
import assert from "node:assert/strict";
import {
  claimExclusiveOperation,
  isCurrentProjectGeneration,
} from "./asyncOwnership.ts";

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test("a delayed result cannot commit after the active project changes", async () => {
  let activeProjectId = 1;
  let generation = 7;
  let rendered = "";
  const requestProjectId = activeProjectId;
  const requestGeneration = generation;
  const response = deferred();
  const consumer = response.promise.then((value) => {
    if (
      isCurrentProjectGeneration(
        activeProjectId,
        generation,
        requestProjectId,
        requestGeneration
      )
    ) {
      rendered = value;
    }
  });

  activeProjectId = 2;
  generation += 1;
  response.resolve("old-project-result");
  await consumer;

  assert.equal(rendered, "");
});

test("an exclusive operation is claimed synchronously before any await", () => {
  let active = false;
  let operationId = 0;

  const first = claimExclusiveOperation(active, operationId);
  assert.equal(first, 1);
  operationId = first;
  active = true;

  assert.equal(claimExclusiveOperation(active, operationId), null);

  active = false;
  assert.equal(claimExclusiveOperation(active, operationId), 2);
});
