import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createCustomRegexServiceForTesting,
  type CustomRegexWorkerHarnessPort,
  type RegexRuleInput,
} from "../utils/customRegex.js";

type WorkerBehavior = {
  ready?: boolean;
  post?: (worker: FakeWorker, value: unknown) => void;
};

class FakeWorker implements CustomRegexWorkerHarnessPort {
  messageHandler: (value: unknown) => void = () => {};
  errorHandler: (error: Error) => void = () => {};
  postCount = 0;
  terminated = false;

  constructor(private readonly behavior: WorkerBehavior = {}) {}

  postMessage(value: unknown) {
    this.postCount += 1;
    this.behavior.post?.(this, value);
  }

  terminate() {
    this.terminated = true;
    return Promise.resolve();
  }

  setMessageHandler(handler: (value: unknown) => void) {
    this.messageHandler = handler;
    if (this.behavior.ready) {
      queueMicrotask(() => this.messageHandler({ type: "ready" }));
    }
  }

  setErrorHandler(handler: (error: Error) => void) {
    this.errorHandler = handler;
  }
}

const safeRule: RegexRuleInput = {
  id: "safe",
  pattern: "token=([a-z0-9]+)",
  flags: "g",
  replacement: "token=[redacted]",
  scope: "text",
};

describe("custom regex execution service", () => {
  it("rejects tasks beyond the bounded queue", async () => {
    const controller = new AbortController();
    const firstWorker = new FakeWorker({ ready: true });
    const service = createCustomRegexServiceForTesting({
      maxConcurrency: 1,
      maxQueue: 0,
      executionTimeoutMs: 100,
      createWorker: () => firstWorker,
    });

    const first = service.replace("token=abc", safeRule, { signal: controller.signal });
    await sleep(0);
    const second = await service.replace("token=def", safeRule);
    controller.abort();
    const firstResult = await first;

    assert.equal(second.ok, false);
    assert.equal(second.ok ? "" : second.code, "budget");
    assert.equal(second.ok ? "" : second.limit, "queue");
    assert.equal(firstResult.ok, false);
    assert.equal(firstResult.ok ? "" : firstResult.code, "cancelled");
  });

  it("removes cancelled queued tasks before they execute", async () => {
    let createdWorkers = 0;
    const firstController = new AbortController();
    const queuedController = new AbortController();
    const service = createCustomRegexServiceForTesting({
      maxConcurrency: 1,
      maxQueue: 1,
      executionTimeoutMs: 100,
      createWorker: () => {
        createdWorkers += 1;
        return new FakeWorker({ ready: true });
      },
    });

    const first = service.replace("token=abc", safeRule, { signal: firstController.signal });
    await sleep(0);
    const queued = service.replace("token=def", safeRule, { signal: queuedController.signal });
    queuedController.abort();
    const queuedResult = await queued;
    firstController.abort();
    await first;

    assert.equal(queuedResult.ok, false);
    assert.equal(queuedResult.ok ? "" : queuedResult.code, "cancelled");
    assert.equal(createdWorkers, 1);
  });

  it("normalizes worker startup failure", async () => {
    const service = createCustomRegexServiceForTesting({
      startupTimeoutMs: 5,
      createWorker: () => new FakeWorker(),
    });

    const result = await service.replace("token=abc", safeRule);

    assert.equal(result.ok, false);
    assert.equal(result.ok ? "" : result.code, "worker-error");
    assert.match(result.ok ? "" : result.message, /startup/i);
  });

  it("normalizes postMessage failures", async () => {
    const service = createCustomRegexServiceForTesting({
      createWorker: () =>
        new FakeWorker({
          ready: true,
          post: () => {
            throw new Error("post blocked");
          },
        }),
    });

    const result = await service.replace("token=abc", safeRule);

    assert.equal(result.ok, false);
    assert.equal(result.ok ? "" : result.code, "worker-error");
    assert.match(result.ok ? "" : result.message, /post blocked/i);
  });

  it("normalizes worker crashes", async () => {
    const service = createCustomRegexServiceForTesting({
      createWorker: () =>
        new FakeWorker({
          ready: true,
          post: (worker) => worker.errorHandler(new Error("worker exploded")),
        }),
    });

    const result = await service.replace("token=abc", safeRule);

    assert.equal(result.ok, false);
    assert.equal(result.ok ? "" : result.code, "worker-error");
    assert.match(result.ok ? "" : result.message, /exploded/i);
  });

  it("normalizes execution timeouts after readiness", async () => {
    const service = createCustomRegexServiceForTesting({
      executionTimeoutMs: 5,
      createWorker: () => new FakeWorker({ ready: true }),
    });

    const result = await service.replace("token=abc", safeRule);

    assert.equal(result.ok, false);
    assert.equal(result.ok ? "" : result.code, "timeout");
  });
});

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
