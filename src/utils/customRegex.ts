import type { CustomRuleScope } from "./sanitizeEngine.js";

export interface RegexRuleInput {
  id: string;
  pattern: string;
  flags: string;
  replacement: string;
  scope?: CustomRuleScope;
  label?: string;
}

type RegexMatch = { start: number; end: number };

type RegexWorkerSuccess =
  | { ok: true; output: string; count: number; matches?: undefined }
  | { ok: true; output?: undefined; count: number; matches: RegexMatch[] };

type RegexFailureCode = "budget" | "timeout" | "syntax-error" | "worker-error" | "cancelled";

type RegexWorkerFailure = {
  ok: false;
  code: RegexFailureCode;
  message: string;
  limit?: string;
};

type RegexWorkerResult = RegexWorkerSuccess | RegexWorkerFailure;

type RegexWorkerTask = {
  taskId: string;
  id: string;
  operation: "validate" | "replace" | "match";
  input: string;
  pattern: string;
  flags: string;
  replacement: string;
  maxMatches: number;
};

type RawRegexWorkerResponse =
  | { taskId: string; id: string; ok: true; output?: string; count: number; matches?: RegexMatch[] }
  | { taskId: string; id: string; ok: false; code: string; message: string; limit?: string };

type RegexWorkerMessage = { type: "ready" } | RawRegexWorkerResponse;

interface RegexRunOptions {
  signal?: AbortSignal;
}

interface CustomRegexApplySuccess {
  ok: true;
  output: string;
  report: string[];
}

interface CustomRegexApplyFailure {
  ok: false;
  output: string;
  report: string[];
  error: RegexWorkerFailure;
  failedRule: RegexRuleInput;
}

type CustomRegexApplyResult = CustomRegexApplySuccess | CustomRegexApplyFailure;

interface RegexWorkerPort {
  postMessage(value: RegexWorkerTask): void;
  terminate(): Promise<void>;
  setMessageHandler(handler: (value: RegexWorkerMessage) => void): void;
  setErrorHandler(handler: (error: Error) => void): void;
}

export interface CustomRegexWorkerHarnessPort {
  postMessage(value: unknown): void;
  terminate(): Promise<void>;
  setMessageHandler(handler: (value: unknown) => void): void;
  setErrorHandler(handler: (error: Error) => void): void;
}

type CreateRegexWorker = () => RegexWorkerPort | Promise<RegexWorkerPort>;

interface RegexServiceOptions {
  maxConcurrency: number;
  maxQueue: number;
  startupTimeoutMs: number;
  executionTimeoutMs: number;
  createWorker: CreateRegexWorker;
}

const CUSTOM_REGEX_BUDGETS = {
  maxPatternChars: 240,
  maxFlagsChars: 8,
  maxReplacementChars: 2_000,
  maxInputChars: 1_000_000,
  maxMatches: 10_000,
  timeoutMs: 500,
  startupTimeoutMs: 2_000,
  maxConcurrency: 4,
  maxQueue: 128,
} as const;

let nextTaskId = 1;

export function isCustomRegexWithinStaticBudgets(rule: Pick<RegexRuleInput, "pattern" | "flags" | "replacement">) {
  return (
    rule.pattern.length > 0
    && rule.pattern.length <= CUSTOM_REGEX_BUDGETS.maxPatternChars
    && rule.flags.length <= CUSTOM_REGEX_BUDGETS.maxFlagsChars
    && /^[dgimsuvy]*$/u.test(rule.flags)
    && new Set(rule.flags.split("")).size === rule.flags.length
    && rule.replacement.length <= CUSTOM_REGEX_BUDGETS.maxReplacementChars
  );
}

export async function validateCustomRegexRule(
  rule: Pick<RegexRuleInput, "pattern" | "flags" | "replacement">,
  options: RegexRunOptions = {},
): Promise<RegexWorkerResult> {
  const budget = validateRuleBudget("", rule);
  if (budget) return budget;
  return runRegexWorker({
    taskId: allocateTaskId(),
    id: "validate",
    operation: "validate",
    input: "",
    pattern: rule.pattern,
    flags: rule.flags,
    replacement: rule.replacement,
    maxMatches: 1,
  }, options);
}

export async function applyCustomRegexRules(
  input: string,
  rules: RegexRuleInput[],
  scope: CustomRuleScope,
  options: RegexRunOptions = {},
): Promise<CustomRegexApplyResult> {
  let output = input;
  const report: string[] = [];
  for (const rule of rules) {
    if (rule.scope && rule.scope !== "both" && rule.scope !== scope) continue;
    const result = await replaceWithCustomRegex(output, rule, options);
    if (!result.ok) {
      return {
        ok: false,
        output: input,
        report: [...report, formatCustomRegexFailure(rule, result)],
        error: result,
        failedRule: rule,
      };
    }
    if (typeof result.output === "string" && result.count > 0) {
      output = result.output;
      report.push(`Custom /${rule.pattern}/${rule.flags}: ${result.count}`);
    }
  }
  return { ok: true, output, report };
}

export async function findCustomRegexMatches(input: string, rules: RegexRuleInput[], options: RegexRunOptions = {}) {
  const matches: Array<{ rule: RegexRuleInput; matches: RegexMatch[]; error?: RegexWorkerFailure }> = [];
  for (const rule of rules) {
    const result = await matchWithCustomRegex(input, rule, options);
    if (!result.ok) {
      matches.push({ rule, matches: [], error: result });
      continue;
    }
    if (Array.isArray(result.matches)) {
      matches.push({ rule, matches: result.matches });
    }
  }
  return matches;
}

export function createCustomRegexServiceForTesting(options: {
  maxConcurrency?: number;
  maxQueue?: number;
  startupTimeoutMs?: number;
  executionTimeoutMs?: number;
  createWorker: () => CustomRegexWorkerHarnessPort | Promise<CustomRegexWorkerHarnessPort>;
}) {
  const service = createRegexExecutionService({
    maxConcurrency: options.maxConcurrency ?? 1,
    maxQueue: options.maxQueue ?? 1,
    startupTimeoutMs: options.startupTimeoutMs ?? 25,
    executionTimeoutMs: options.executionTimeoutMs ?? 25,
    createWorker: options.createWorker as CreateRegexWorker,
  });
  return {
    replace(input: string, rule: RegexRuleInput, runOptions: RegexRunOptions = {}) {
      const budget = validateRuleBudget(input, rule);
      if (budget) return Promise.resolve(budget);
      return service.run({
        taskId: allocateTaskId(),
        id: rule.id,
        operation: "replace",
        input,
        pattern: rule.pattern,
        flags: rule.flags,
        replacement: rule.replacement,
        maxMatches: CUSTOM_REGEX_BUDGETS.maxMatches,
      }, runOptions);
    },
  };
}

async function replaceWithCustomRegex(input: string, rule: RegexRuleInput, options: RegexRunOptions): Promise<RegexWorkerResult> {
  const budget = validateRuleBudget(input, rule);
  if (budget) return budget;
  return runRegexWorker({
    taskId: allocateTaskId(),
    id: rule.id,
    operation: "replace",
    input,
    pattern: rule.pattern,
    flags: rule.flags,
    replacement: rule.replacement,
    maxMatches: CUSTOM_REGEX_BUDGETS.maxMatches,
  }, options);
}

async function matchWithCustomRegex(input: string, rule: RegexRuleInput, options: RegexRunOptions): Promise<RegexWorkerResult> {
  const budget = validateRuleBudget(input, rule);
  if (budget) return budget;
  return runRegexWorker({
    taskId: allocateTaskId(),
    id: rule.id,
    operation: "match",
    input,
    pattern: rule.pattern,
    flags: rule.flags,
    replacement: "",
    maxMatches: CUSTOM_REGEX_BUDGETS.maxMatches,
  }, options);
}

function validateRuleBudget(input: string, rule: Pick<RegexRuleInput, "pattern" | "flags" | "replacement">): RegexWorkerFailure | null {
  if (input.length > CUSTOM_REGEX_BUDGETS.maxInputChars) {
    return budgetFailure("input", "Custom regex input exceeds NullID safety budgets");
  }
  if (rule.pattern.length === 0 || rule.pattern.length > CUSTOM_REGEX_BUDGETS.maxPatternChars) {
    return budgetFailure("pattern", "Custom regex pattern exceeds NullID safety budgets");
  }
  if (rule.flags.length > CUSTOM_REGEX_BUDGETS.maxFlagsChars || !/^[dgimsuvy]*$/u.test(rule.flags) || new Set(rule.flags.split("")).size !== rule.flags.length) {
    return budgetFailure("flags", "Custom regex flags exceed NullID safety budgets");
  }
  if (rule.replacement.length > CUSTOM_REGEX_BUDGETS.maxReplacementChars) {
    return budgetFailure("replacement", "Custom regex replacement exceeds NullID safety budgets");
  }
  return null;
}

function runRegexWorker(task: RegexWorkerTask, options: RegexRunOptions): Promise<RegexWorkerResult> {
  return getDefaultRegexService().run(task, options);
}

function getDefaultRegexService() {
  if (!defaultRegexService) {
    defaultRegexService = createRegexExecutionService({
      maxConcurrency: CUSTOM_REGEX_BUDGETS.maxConcurrency,
      maxQueue: CUSTOM_REGEX_BUDGETS.maxQueue,
      startupTimeoutMs: CUSTOM_REGEX_BUDGETS.startupTimeoutMs,
      executionTimeoutMs: CUSTOM_REGEX_BUDGETS.timeoutMs,
      createWorker: typeof Worker !== "undefined" ? createBrowserRegexWorker : createNodeRegexWorker,
    });
  }
  return defaultRegexService;
}

let defaultRegexService: ReturnType<typeof createRegexExecutionService> | null = null;

function createRegexExecutionService(options: RegexServiceOptions) {
  type QueueItem = {
    task: RegexWorkerTask;
    signal?: AbortSignal;
    resolve: (value: RegexWorkerResult) => void;
    abortQueued?: () => void;
  };

  let active = 0;
  const queue: QueueItem[] = [];

  const drain = () => {
    while (active < options.maxConcurrency && queue.length > 0) {
      const item = queue.shift()!;
      if (item.abortQueued && item.signal) {
        item.signal.removeEventListener("abort", item.abortQueued);
        item.abortQueued = undefined;
      }
      if (item.signal?.aborted) {
        item.resolve(cancelledFailure());
        continue;
      }
      active += 1;
      void runTaskInWorker(item.task, options, item.signal)
        .then(item.resolve)
        .finally(() => {
          active -= 1;
          drain();
        });
    }
  };

  return {
    run(task: RegexWorkerTask, runOptions: RegexRunOptions = {}) {
      if (runOptions.signal?.aborted) {
        return Promise.resolve(cancelledFailure());
      }
      if (active >= options.maxConcurrency && queue.length >= options.maxQueue) {
        return Promise.resolve(budgetFailure("queue", "Custom regex queue exceeds NullID safety budgets"));
      }
      return new Promise<RegexWorkerResult>((resolve) => {
        const item: QueueItem = { task, signal: runOptions.signal, resolve };
        if (runOptions.signal) {
          item.abortQueued = () => {
            const index = queue.indexOf(item);
            if (index >= 0) {
              queue.splice(index, 1);
              resolve(cancelledFailure());
            }
          };
          runOptions.signal.addEventListener("abort", item.abortQueued, { once: true });
        }
        queue.push(item);
        drain();
      });
    },
  };
}

function runTaskInWorker(task: RegexWorkerTask, options: RegexServiceOptions, signal?: AbortSignal): Promise<RegexWorkerResult> {
  return new Promise<RegexWorkerResult>((resolve) => {
    let worker: RegexWorkerPort | null = null;
    let settled = false;
    let startupTimer: ReturnType<typeof setTimeout> | null = null;
    let executionTimer: ReturnType<typeof setTimeout> | null = null;

    const clearTimers = () => {
      if (startupTimer) clearTimeout(startupTimer);
      if (executionTimer) clearTimeout(executionTimer);
      startupTimer = null;
      executionTimer = null;
    };

    const finish = (result: RegexWorkerResult) => {
      if (settled) return;
      settled = true;
      clearTimers();
      if (signal) signal.removeEventListener("abort", abortRunning);
      const activeWorker = worker;
      worker = null;
      void (activeWorker ? activeWorker.terminate() : Promise.resolve())
        .catch(() => undefined)
        .then(() => resolve(result));
    };

    const abortRunning = () => finish(cancelledFailure());

    if (signal) {
      signal.addEventListener("abort", abortRunning, { once: true });
    }

    Promise.resolve()
      .then(options.createWorker)
      .then((createdWorker) => {
        if (settled) {
          void createdWorker.terminate().catch(() => undefined);
          return;
        }
        worker = createdWorker;
        worker.setMessageHandler((message) => {
          if ("type" in message && message.type === "ready") {
            if (settled || !worker) return;
            if (startupTimer) clearTimeout(startupTimer);
            startupTimer = null;
            if (signal?.aborted) {
              finish(cancelledFailure());
              return;
            }
            executionTimer = setTimeout(() => {
              finish({ ok: false, code: "timeout", message: "Custom regex timed out" });
            }, options.executionTimeoutMs);
            try {
              worker.postMessage(task);
            } catch (error) {
              finish({
                ok: false,
                code: "worker-error",
                message: error instanceof Error ? error.message : "Custom regex worker postMessage failed",
              });
            }
            return;
          }
          if ("taskId" in message && message.taskId === task.taskId) {
            finish(normalizeWorkerResponse(message));
          }
        });
        worker.setErrorHandler((error) => {
          finish({ ok: false, code: "worker-error", message: error.message || "Custom regex worker failed" });
        });
        startupTimer = setTimeout(() => {
          finish({ ok: false, code: "worker-error", message: "Custom regex worker startup failed" });
        }, options.startupTimeoutMs);
      })
      .catch((error) => {
        finish({
          ok: false,
          code: "worker-error",
          message: error instanceof Error ? error.message : "Custom regex worker unavailable",
        });
      });
  });
}

function normalizeWorkerResponse(response: RawRegexWorkerResponse): RegexWorkerResult {
  if (response.ok) {
    if (response.matches) {
      return { ok: true, count: response.count, matches: response.matches };
    }
    return { ok: true, count: response.count, output: response.output ?? "" };
  }
  if (response.code === "syntax-error") {
    return { ok: false, code: "syntax-error", message: response.message };
  }
  if (response.code === "budget") {
    return { ok: false, code: "budget", message: response.message, limit: response.limit };
  }
  if (response.code === "cancelled") {
    return cancelledFailure();
  }
  return {
    ok: false,
    code: "worker-error",
    message: response.message || "Custom regex worker failed",
  };
}

function createBrowserRegexWorker(): RegexWorkerPort {
  const worker = new Worker(new URL("./customRegexWorker.ts", import.meta.url), { type: "module" });
  let messageHandler: ((value: RegexWorkerMessage) => void) | null = null;
  const pendingMessages: RegexWorkerMessage[] = [];
  worker.onmessage = (event: MessageEvent<RegexWorkerMessage>) => {
    if (messageHandler) {
      messageHandler(event.data);
      return;
    }
    pendingMessages.push(event.data);
  };
  return {
    postMessage(value) {
      worker.postMessage(value);
    },
    terminate() {
      worker.terminate();
      return Promise.resolve();
    },
    setMessageHandler(handler) {
      messageHandler = handler;
      while (pendingMessages.length > 0) {
        handler(pendingMessages.shift()!);
      }
    },
    setErrorHandler(handler) {
      worker.onerror = () => handler(new Error("Custom regex worker failed"));
    },
  };
}

type NodeWorkerPort = {
  postMessage(value: RegexWorkerTask): void;
  on(event: "message", listener: (value: RegexWorkerMessage) => void): NodeWorkerPort;
  on(event: "error", listener: (error: Error) => void): NodeWorkerPort;
  on(event: "exit", listener: (code: number) => void): NodeWorkerPort;
  off(event: "message", listener: (value: RegexWorkerMessage) => void): NodeWorkerPort;
  off(event: "error", listener: (error: Error) => void): NodeWorkerPort;
  off(event: "exit", listener: (code: number) => void): NodeWorkerPort;
  terminate(): Promise<number>;
};

type NodeWorkerConstructor = new (url: URL) => NodeWorkerPort;

let nodeWorkerModulePromise: Promise<{ Worker: NodeWorkerConstructor }> | null = null;

async function createNodeRegexWorker(): Promise<RegexWorkerPort> {
  if (!nodeWorkerModulePromise) {
    const dynamicImport = new Function("specifier", "return import(specifier)") as (specifier: string) => Promise<{ Worker: NodeWorkerConstructor }>;
    nodeWorkerModulePromise = dynamicImport("node:worker_threads");
  }
  const { Worker: NodeWorker } = await nodeWorkerModulePromise;
  const worker = new NodeWorker(nodeWorkerDataUrl());
  let messageHandler: ((value: RegexWorkerMessage) => void) | null = null;
  let errorHandler: (error: Error) => void = () => {};
  let terminating = false;
  const pendingMessages: RegexWorkerMessage[] = [];
  const onMessage = (value: RegexWorkerMessage) => {
    if (messageHandler) {
      messageHandler(value);
      return;
    }
    pendingMessages.push(value);
  };
  const onError = (error: Error) => errorHandler(error);
  const onExit = (code: number) => {
    if (!terminating && code !== 0) {
      errorHandler(new Error(`Custom regex worker exited with code ${code}`));
    }
  };
  worker.on("message", onMessage);
  worker.on("error", onError);
  worker.on("exit", onExit);
  return {
    postMessage(value) {
      worker.postMessage(value);
    },
    async terminate() {
      terminating = true;
      worker.off("message", onMessage);
      worker.off("error", onError);
      worker.off("exit", onExit);
      await worker.terminate();
    },
    setMessageHandler(handler) {
      messageHandler = handler;
      while (pendingMessages.length > 0) {
        handler(pendingMessages.shift()!);
      }
    },
    setErrorHandler(handler) {
      errorHandler = handler;
    },
  };
}

let cachedNodeWorkerDataUrl: URL | null = null;

function nodeWorkerDataUrl() {
  if (!cachedNodeWorkerDataUrl) {
    cachedNodeWorkerDataUrl = new URL(`data:text/javascript;charset=utf-8,${encodeURIComponent(NODE_WORKER_SOURCE)}`);
  }
  return cachedNodeWorkerDataUrl;
}

function allocateTaskId() {
  const taskId = `custom-regex-${nextTaskId}`;
  nextTaskId += 1;
  return taskId;
}

function budgetFailure(limit: string, message: string): RegexWorkerFailure {
  return { ok: false, code: "budget", limit, message };
}

function cancelledFailure(): RegexWorkerFailure {
  return { ok: false, code: "cancelled", message: "Custom regex task cancelled" };
}

function formatCustomRegexFailure(rule: RegexRuleInput, failure: RegexWorkerFailure) {
  const label = rule.label || rule.id || rule.pattern;
  return `Custom ${label}: failed (${failure.code}) ${failure.message}`;
}

const NODE_WORKER_SOURCE = `
import { parentPort } from "node:worker_threads";

parentPort.postMessage({ type: "ready" });
parentPort.on("message", (task) => {
  parentPort.postMessage(runRegexTask(task));
});

function uniqueFlags(flags) {
  return Array.from(new Set(String(flags).split(""))).join("");
}

function runRegexTask(task) {
  let regex;
  try {
    regex = new RegExp(task.pattern, task.flags);
  } catch (error) {
    return { taskId: task.taskId, id: task.id, ok: false, code: "syntax-error", message: error instanceof Error ? error.message : "Custom regex syntax is invalid" };
  }
  if (task.operation === "validate") {
    return { taskId: task.taskId, id: task.id, ok: true, count: 0 };
  }
  try {
    if (task.operation === "match") {
      const matcher = regex.global ? regex : new RegExp(task.pattern, uniqueFlags(String(task.flags) + "g"));
      const matches = [];
      let match;
      while ((match = matcher.exec(task.input)) !== null) {
        matches.push({ start: match.index, end: match.index + match[0].length });
        if (matches.length > task.maxMatches) {
          return { taskId: task.taskId, id: task.id, ok: false, code: "budget", limit: "matches", message: "Custom regex match budget exceeded" };
        }
        if (match[0].length === 0) matcher.lastIndex += 1;
        if (!matcher.global) break;
      }
      return { taskId: task.taskId, id: task.id, ok: true, count: matches.length, matches };
    }
    let count = 0;
    const output = String(task.input).replace(regex, () => {
      count += 1;
      if (count > task.maxMatches) {
        throw new Error("Custom regex match budget exceeded");
      }
      return task.replacement;
    });
    return { taskId: task.taskId, id: task.id, ok: true, output, count };
  } catch (error) {
    if (error instanceof Error && /match budget/i.test(error.message)) {
      return { taskId: task.taskId, id: task.id, ok: false, code: "budget", limit: "matches", message: error.message };
    }
    return { taskId: task.taskId, id: task.id, ok: false, code: "worker-error", message: error instanceof Error ? error.message : "Custom regex failed" };
  }
}
`;
