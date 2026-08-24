// TS mirror tests for the mini-language (browser runtime).
// Mirrors register/demo/rule-exec Go tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Budget, BudgetError, DefaultMaxIterations,
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

test("TS: infinite while stopped by iteration budget", () => {
  const flow: Flow = {
    steps: [{ kind: "while", condition: { op: "eq", path: "flag", value: true }, do: [{ kind: "op", op: "noop" }] }],
  };
  const b = new Budget();
  wantBudgetKind(() => runFlow(flow, ctxWith({ flag: true }, {}), b), "iterations");
  assert.equal(b.iterations, DefaultMaxIterations + 1);
});

test("TS: nested loops rejected statically", () => {
  const inner: Step[] = [{ kind: "for", from: 0, to: 10, do: [{ kind: "op", op: "noop" }] }];
  const flow: Flow = { steps: [{ kind: "for", from: 0, to: 10, do: inner }] };
  assert.throws(() => checkStaticBounds(flow, new Budget()), /nested loop/);
  // while -> if -> while is also a nested loop
  const flow2: Flow = {
    steps: [{ kind: "while", condition: { op: "eq", path: "flag", value: true },
      do: [{ kind: "if", condition: { op: "eq", path: "flag", value: true },
        then: [{ kind: "while", condition: { op: "eq", path: "flag", value: true }, do: [{ kind: "op", op: "noop" }] }] }] }],
  };
  assert.throws(() => checkStaticBounds(flow2, new Budget()), /nested loop/);
});

test("TS: if<->while nesting allowed", () => {
  const wif: Flow = { steps: [{ kind: "while", condition: { op: "eq", path: "flag", value: true }, do: [{ kind: "if", condition: { op: "eq", path: "flag", value: false }, then: [{ kind: "op", op: "noop" }] }] }] };
  const fw: Flow = { steps: [{ kind: "if", condition: { op: "eq", path: "flag", value: false }, then: [{ kind: "while", condition: { op: "eq", path: "flag", value: true }, do: [{ kind: "op", op: "noop" }] }] }] };
  checkStaticBounds(wif, new Budget());
  checkStaticBounds(fw, new Budget());
});

test("TS: static huge loop rejected", () => {
  const flow: Flow = { steps: [{ kind: "for", from: 0, to: 1_000_000_000, do: [{ kind: "op", op: "noop" }] }] };
  assert.throws(() => checkStaticBounds(flow, new Budget()), /static bound/);
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
    [{ op: "time-in", path: "request.time", window: ["08:00", "22:00"] }, true],
    [{ op: "time-in", path: "request.time", window: ["11:00", "09:00"] }, false],
    [{ op: "between", path: "request.params.amount", window: ["1", "1000"] }, true],
    [{ op: "in", path: "request.tenant_id", value: ["org-a", "org-b"] }, true],
  ];
  for (const [cond, want] of cases) {
    assert.equal(evalCondition(cond, ctx, new Budget(), 0), want, JSON.stringify(cond));
  }
  assert.throws(() => evalCondition({ op: "bogus" }, ctx, new Budget(), 0), /unknown condition op/);
});

test("TS: flow break and retry", () => {
  const flow: Flow = {
    steps: [{ kind: "for", var: "i", from: 0, to: 10,
      do: [{ kind: "if", condition: { op: "eq", path: "i", value: 3 }, then: [{ kind: "break" }] }] }],
  };
  const fc = ctxWith({}, {});
  const b = new Budget();
  runFlow(flow, fc, b);
  assert.equal(fc.vars.i, 3);
  assert.equal(b.iterations, 4);

  let attempts = 0;
  const flaky: Flow = { steps: [{ name: "f", kind: "retry", maxRetries: 2, steps: [{ kind: "op", op: "db:flaky" }] }] };
  const fc2: FlowContext = {
    vars: {},
    request: {},
    handler: (op, vars) => {
      if (op !== "db:flaky") throw new Error("unknown op");
      attempts++;
      if (attempts < 3) throw new Error("transient");
      vars.done = true;
      return {};
    },
  };
  runFlow(flaky, fc2, new Budget());
  assert.equal(attempts, 3);
  assert.equal(fc2.vars.done, true);
});
