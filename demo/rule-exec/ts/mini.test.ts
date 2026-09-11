// TS mirror tests for the mini-language (browser runtime).
// Mirrors register/demo/rule-exec Go tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  Budget, BudgetError,
  evalCondition, runFlow, checkStaticBounds,
  type Condition, type Flow, type Step, type FlowContext,
} from "./mini.ts";

function ctxWith(vars: Record<string, unknown>, req: Record<string, unknown>): FlowContext {
  return {
    vars: vars ?? {},
    request: req ?? {},
    handler: (op) => ({ rowCount: op === "db:select" ? 3 : undefined }),
  };
}

function wantBudgetKind(fn: () => void, kind: string): void {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof BudgetError, `expected BudgetError, got ${String(err)}`);
  assert.equal((err as BudgetError).kind, kind);
}





test("TS: if/seq nesting allowed, excessive nesting rejected", () => {
  const ok: Flow = { steps: [{ kind: "if", condition: { op: "eq", path: "flag", value: false },
    then: [{ kind: "seq", steps: [{ kind: "op", op: "noop" }] }] }] };
  checkStaticBounds(ok, new Budget());
  let deep: Step[] = [{ kind: "op", op: "noop" }];
  for (let i = 0; i < 100; i++) deep = [{ kind: "seq", steps: deep }];
  assert.throws(() => checkStaticBounds({ steps: deep }, new Budget()), /nesting depth/);
});

test("TS: condition evaluation", () => {
  const ctx = {
    request: {
      tenant_id: "org-a",
      time: "2026-08-23T10:00:00Z",
      params: { amount: 500 },
    },
  };
  const cases: [Condition, boolean][] = [
    [{ op: "eq", path: "request.tenant_id", value: "org-a" }, true],
    [{ op: "eq", path: "request.tenant_id", value: "org-b" }, false],
    [{ op: "and", items: [
      { op: "eq", path: "request.tenant_id", value: "org-a" },
      { op: "lte", path: "request.params.amount", value: 1000 },
    ] }, true],
    [{ op: "between", path: "request.params.amount", window: ["1", "1000"] }, true],
    [{ op: "in", path: "request.tenant_id", value: ["org-a", "org-b"] }, true],
  ];
  for (const [cond, want] of cases) {
    assert.equal(evalCondition(cond, ctx, new Budget(), 0), want, JSON.stringify(cond));
  }
  assert.throws(() => evalCondition({ op: "bogus" }, ctx, new Budget(), 0), /unknown condition op/);
});

test("condition vectors (shared truth table with Go)", () => {
  const path = new URL("../../../ruleexec/testdata/condition-vectors.json", import.meta.url);
  const file = JSON.parse(readFileSync(path, "utf8")) as {
    cases: {
      id: string; ctx: Record<string, unknown>; condition: Condition;
      derivation: string; expect: { result?: boolean; error?: boolean };
    }[];
  };
  assert.ok(file.cases.length > 0, "no condition vectors");
  for (const c of file.cases) {
    let got: boolean | undefined;
    let err: unknown;
    try {
      got = evalCondition(c.condition, c.ctx, new Budget(), 0);
    } catch (e) {
      err = e;
    }
    if (c.expect.error) {
      assert.ok(err !== undefined, `${c.id}: expected an error (${c.derivation})`);
      continue;
    }
    assert.equal(err, undefined, `${c.id}: unexpected error ${String(err)}`);
    assert.equal(got, c.expect.result, `${c.id}: ${c.derivation}`);
  }
});
