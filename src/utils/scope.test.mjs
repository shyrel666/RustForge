import test from "node:test";
import assert from "node:assert/strict";
import { normalizeScopeEntry, normalizeScopeList } from "./scope.ts";

test("frontend scope cleanup does not duplicate backend URL parsing", () => {
  assert.equal(
    normalizeScopeEntry(" HTTPS://Example.COM:8443/path "),
    "HTTPS://Example.COM:8443/path",
  );
  assert.deepEqual(
    normalizeScopeList([" 例子.测试 ", "例子.测试", " [::1]:8080 "]),
    ["例子.测试", "[::1]:8080"],
  );
});
