import test from "node:test";
import assert from "node:assert/strict";
import { runDiagnosticJobs } from "./runtimeDiagnostics.ts";

test("diagnostic jobs publish successful values independently", async () => {
  const values = [];
  let releaseSlow;
  const slow = new Promise((resolve) => {
    releaseSlow = resolve;
  });

  const run = runDiagnosticJobs(
    [
      {
        label: "慢速项目",
        run: async () => {
          await slow;
          values.push("slow");
        },
      },
      {
        label: "快速项目",
        run: async () => {
          values.push("fast");
        },
      },
    ],
    100,
  );

  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(values, ["fast"]);

  releaseSlow();
  const result = await run;
  assert.deepEqual(values, ["fast", "slow"]);
  assert.deepEqual(result.failures, []);
});

test("one failed diagnostic does not discard successful diagnostics", async () => {
  let completed = false;
  const result = await runDiagnosticJobs([
    {
      label: "系统",
      run: async () => {
        completed = true;
      },
    },
    {
      label: "CA 证书",
      run: async () => {
        throw new Error("证书存储不可用");
      },
    },
  ]);

  assert.equal(completed, true);
  assert.deepEqual(result.failures, ["CA 证书：证书存储不可用"]);
});

test("a stalled diagnostic returns a bounded timeout failure", async () => {
  const result = await runDiagnosticJobs(
    [
      {
        label: "CA 证书",
        run: () => new Promise(() => {}),
      },
    ],
    5,
  );

  assert.deepEqual(result.failures, ["CA 证书：读取超过 1 秒"]);
});
