// Mini-language runtime (browser port) for AIC rule-exec.
// Mirrors the Go implementation in register/demo/rule-exec; the two
// share the same semantics and test scenarios. Browser-safe: no Node
// or WebCrypto APIs.

export const DefaultMaxSteps = 10000;
export const DefaultMaxIterations = 1000;
export const DefaultMaxDepth = 64;
export const DefaultMaxNesting = 64;

const KNOWN_CONDITION_OPS = new Set([
  "and", "or", "not", "eq", "neq", "lt", "lte", "gt", "gte",
  "in", "contains", "between", "time-in", "is-null",
]);

export class BudgetError extends Error {
  kind: string;
  used: number;
  max: number;

  constructor(kind: string, used: number, max: number) {
    super(`budget exceeded: ${kind} ${used} > ${max}`);
    this.name = "BudgetError";
    this.kind = kind;
    this.used = used;
    this.max = max;
  }
}

export class Budget {
  steps = 0;
  iterations = 0;
  nesting = 0;
  maxSteps: number;
  maxIterations: number;
  maxDepth: number;
  maxNesting: number;
  deadline?: number;

  constructor(
    maxSteps: number = DefaultMaxSteps,
    maxIterations: number = DefaultMaxIterations,
    maxDepth: number = DefaultMaxDepth,
    maxNesting: number = DefaultMaxNesting,
    deadline?: number,
  ) {
    this.maxSteps = maxSteps;
    this.maxIterations = maxIterations;
    this.maxDepth = maxDepth;
    this.maxNesting = maxNesting;
    this.deadline = deadline;
  }

  step(): void {
    this.steps++;
    if (this.steps > this.maxSteps) {
      throw new BudgetError("steps", this.steps, this.maxSteps);
    }
    if (this.deadline !== undefined && Date.now() > this.deadline) {
      throw new BudgetError("timeout", 0, 0);
    }
  }

  iteration(): void {
    this.iterations++;
    if (this.iterations > this.maxIterations) {
      throw new BudgetError("iterations", this.iterations, this.maxIterations);
    }
  }

  enter(depth: number): void {
    if (depth > this.maxDepth) {
      throw new BudgetError("depth", depth, this.maxDepth);
    }
    this.nesting++;
    if (this.nesting > this.maxNesting) {
      throw new BudgetError("nesting", this.nesting, this.maxNesting);
    }
  }

  exit(): void {
    if (this.nesting > 0) this.nesting--;
  }

  stats(): { steps: number; iterations: number } {
    return { steps: this.steps, iterations: this.iterations };
  }
}

export interface Condition {
  op: string;
  path?: string;
  value?: unknown;
  window?: string[];
  items?: Condition[];
}

export interface Step {
  name?: string;
  kind: string;
  op?: string;
  condition?: Condition;
  then?: Step[];
  else?: Step[];
  var?: string;
  from?: number;
  to?: number;
  maxRetries?: number;
  steps?: Step[];
  do?: Step[];
}

export interface Flow {
  steps: Step[];
}

export type OpHandler = (
  op: string,
  vars: Record<string, unknown>,
  req: Record<string, unknown>,
) => Record<string, unknown>;

export interface FlowContext {
  vars: Record<string, unknown>;
  request: Record<string, unknown>;
  handler: OpHandler;
}

function resolvePath(ctx: Record<string, unknown>, path: string): { v: unknown; ok: boolean } {
  if (!path) return { v: undefined, ok: false };
  const parts = path.split(".");
  let cur: unknown = ctx;
  for (const p of parts) {
    if (typeof cur !== "object" || cur === null) return { v: undefined, ok: false };
    const m = cur as Record<string, unknown>;
    if (!(p in m)) return { v: undefined, ok: false };
    cur = m[p];
  }
  return { v: cur, ok: true };
}

function toNum(v: unknown): number | null {
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const n = Number(v);
    return Number.isNaN(n) ? null : n;
  }
  return null;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a === "object" && a !== null && typeof b === "object" && b !== null) {
    const ka = Object.keys(a as object).sort();
    const kb = Object.keys(b as object).sort();
    if (ka.length !== kb.length) return false;
    return ka.every((k, i) => k === kb[i] && deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

function parseHHMM(s: string): number | null {
  const m = /^(\d{2}):(\d{2})$/.exec(s);
  if (!m) return null;
  const h = Number(m[1]);
  const mi = Number(m[2]);
  if (h > 23 || mi > 59) return null;
  return h * 60 + mi;
}

function evalLeaf(op: string, got: unknown, want: unknown, window?: string[]): boolean {
  switch (op) {
    case "eq": return deepEqual(got, want);
    case "neq": return !deepEqual(got, want);
    case "lt": case "lte": case "gt": case "gte": {
      const g = toNum(got);
      const w = toNum(want);
      if (g === null || w === null) throw new Error(`op ${op} requires numeric operands`);
      switch (op) {
        case "lt": return g < w;
        case "lte": return g <= w;
        case "gt": return g > w;
        default: return g >= w;
      }
    }
    case "in": {
      if (!Array.isArray(want)) throw new Error("op in requires a list value");
      return want.some((x) => deepEqual(got, x));
    }
    case "contains": {
      if (typeof got !== "string" || typeof want !== "string") throw new Error("op contains requires strings");
      return got.includes(want);
    }
    case "between": {
      if (!window || window.length !== 2) throw new Error("op between requires window [lo, hi]");
      const g = toNum(got);
      const lo = toNum(window[0]);
      const hi = toNum(window[1]);
      if (g === null || lo === null || hi === null) throw new Error("op between requires numeric operands");
      return g >= lo && g <= hi;
    }
    case "time-in": {
      if (!window || window.length !== 2) throw new Error("op time-in requires window [start, end]");
      if (typeof got !== "string") throw new Error("op time-in requires an RFC3339 time string");
      const t = new Date(got);
      if (Number.isNaN(t.getTime())) throw new Error("op time-in: bad time");
      const cur = t.getUTCHours() * 60 + t.getUTCMinutes();
      const start = parseHHMM(window[0]);
      const end = parseHHMM(window[1]);
      if (start === null || end === null) throw new Error("op time-in: invalid window");
      if (start <= end) return cur >= start && cur <= end;
      return cur >= start || cur <= end;
    }
    case "is-null":
      return got === null || got === undefined;
    default:
      throw new Error(`unknown condition op ${op}`);
  }
}

export function evalCondition(c: Condition, ctx: Record<string, unknown>, b: Budget, depth: number): boolean {
  b.step();
  b.enter(depth);
  try {
    switch (c.op) {
      case "and":
        for (const it of c.items ?? []) {
          if (!evalCondition(it, ctx, b, depth + 1)) return false;
        }
        return true;
      case "or":
        for (const it of c.items ?? []) {
          if (evalCondition(it, ctx, b, depth + 1)) return true;
        }
        return false;
      case "not": {
        if (!c.items || c.items.length !== 1) throw new Error("op not requires exactly 1 item");
        return !evalCondition(c.items[0], ctx, b, depth + 1);
      }
      case "is-null": {
        const r = resolvePath(ctx, c.path ?? "");
        return !r.ok || r.v === null || r.v === undefined;
      }
      default: {
        if (!KNOWN_CONDITION_OPS.has(c.op)) {
          throw new Error(`unknown condition op ${c.op}`);
        }
        const r = resolvePath(ctx, c.path ?? "");
        if (!r.ok) throw new Error(`condition path ${JSON.stringify(c.path)} not found`);
        return evalLeaf(c.op, r.v, c.value, c.window);
      }
    }
  } finally {
    b.exit();
  }
}

class FlowSignal extends Error {
  kind: "break" | "continue";

  constructor(kind: "break" | "continue") {
    super(`flow: ${kind}`);
    this.name = "FlowSignal";
    this.kind = kind;
  }
}

function evalContext(fc: FlowContext): Record<string, unknown> {
  const m: Record<string, unknown> = { ...fc.vars };
  m.request = fc.request;
  return m;
}

function runSteps(steps: Step[], fc: FlowContext, b: Budget, depth: number): void {
  b.enter(depth);
  try {
    for (const st of steps) {
      b.step();
      switch (st.kind) {
        case "op": {
          const out = fc.handler(st.op ?? "", fc.vars, fc.request);
          Object.assign(fc.vars, out);
          break;
        }
        case "if": {
          const ok = evalCondition(st.condition!, evalContext(fc), b, depth + 1);
          if (ok) runSteps(st.then ?? [], fc, b, depth + 1);
          else runSteps(st.else ?? [], fc, b, depth + 1);
          break;
        }
        case "while": {
          while (true) {
            b.iteration();
            const ok = evalCondition(st.condition!, evalContext(fc), b, depth + 1);
            if (!ok) break;
            try {
              runSteps(st.do ?? [], fc, b, depth + 1);
            } catch (e) {
              if (e instanceof FlowSignal) {
                if (e.kind === "break") break;
                continue;
              }
              throw e;
            }
          }
          break;
        }
        case "for": {
          for (let i = st.from ?? 0; i < (st.to ?? 0); i++) {
            b.iteration();
            if (st.var) fc.vars[st.var] = i;
            try {
              runSteps(st.do ?? [], fc, b, depth + 1);
            } catch (e) {
              if (e instanceof FlowSignal) {
                if (e.kind === "break") break;
                continue;
              }
              throw e;
            }
          }
          break;
        }
        case "retry": {
          let last: unknown;
          for (let attempt = 0; attempt <= (st.maxRetries ?? 0); attempt++) {
            b.iteration();
            try {
              runSteps(st.steps ?? [], fc, b, depth + 1);
              last = undefined;
              break;
            } catch (e) {
              if (e instanceof FlowSignal) throw e;
              last = e;
            }
          }
          if (last !== undefined) throw new Error(`retry ${st.name ?? ""} exhausted after ${(st.maxRetries ?? 0) + 1} attempts: ${String(last)}`);
          break;
        }
        case "seq":
          runSteps(st.steps ?? [], fc, b, depth + 1);
          break;
        case "break":
          throw new FlowSignal("break");
        case "continue":
          throw new FlowSignal("continue");
        default:
          throw new Error(`unknown step kind ${st.kind}`);
      }
    }
  } finally {
    b.exit();
  }
}

export function runFlow(f: Flow, fc: FlowContext, b: Budget): void {
  runSteps(f.steps, fc, b, 0);
}

export function checkStaticBounds(f: Flow, b: Budget): void {
  walkBounds(f.steps, b, 0);
}

function walkBounds(steps: Step[], b: Budget, loopDepth: number): void {
  for (const st of steps) {
    switch (st.kind) {
      case "for":
      case "while":
        if (loopDepth >= 1) throw new Error(`static bound check: nested loop ${st.name ?? ""} (loop nesting is forbidden)`);
        if (st.kind === "for") {
          const n = (st.to ?? 0) - (st.from ?? 0);
          if (n > b.maxIterations) {
            throw new Error(`static bound check: for loop ${st.name ?? ""} iterates ${n} times > budget ${b.maxIterations}`);
          }
        }
        walkBounds(st.do ?? [], b, loopDepth + 1);
        break;
      case "if":
        walkBounds(st.then ?? [], b, loopDepth);
        walkBounds(st.else ?? [], b, loopDepth);
        break;
      case "retry":
        if ((st.maxRetries ?? 0) + 1 > b.maxIterations) {
          throw new Error(`static bound check: retry ${st.name ?? ""} allows ${(st.maxRetries ?? 0) + 1} attempts > budget ${b.maxIterations}`);
        }
        walkBounds(st.steps ?? [], b, loopDepth);
        break;
      case "seq":
        walkBounds(st.steps ?? [], b, loopDepth);
        break;
    }
  }
}
