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

type RegexWorkerResponse =
  | { taskId: string; id: string; ok: true; output?: string; count: number; matches?: Array<{ start: number; end: number }> }
  | { taskId: string; id: string; ok: false; code: string; message: string; limit?: string };

self.postMessage({ type: "ready" });

self.onmessage = (event: MessageEvent<RegexWorkerTask>) => {
  const response = runRegexTask(event.data);
  self.postMessage(response);
};

function runRegexTask(task: RegexWorkerTask): RegexWorkerResponse {
  let regex: RegExp;
  try {
    regex = new RegExp(task.pattern, task.flags);
  } catch (error) {
    return {
      taskId: task.taskId,
      id: task.id,
      ok: false,
      code: "syntax-error",
      message: error instanceof Error ? error.message : "Custom regex syntax is invalid",
    };
  }

  if (task.operation === "validate") {
    return { taskId: task.taskId, id: task.id, ok: true, count: 0 };
  }

  try {
    if (task.operation === "match") {
      const matcher = regex.global ? regex : new RegExp(task.pattern, uniqueFlags(`${task.flags}g`));
      const matches: Array<{ start: number; end: number }> = [];
      let match: RegExpExecArray | null;
      while ((match = matcher.exec(task.input)) !== null) {
        matches.push({ start: match.index, end: match.index + match[0].length });
        if (matches.length > task.maxMatches) {
          return {
            taskId: task.taskId,
            id: task.id,
            ok: false,
            code: "budget",
            limit: "matches",
            message: "Custom regex match budget exceeded",
          };
        }
        if (match[0].length === 0) matcher.lastIndex += 1;
        if (!matcher.global) break;
      }
      return { taskId: task.taskId, id: task.id, ok: true, count: matches.length, matches };
    }

    let count = 0;
    const output = task.input.replace(regex, () => {
      count += 1;
      if (count > task.maxMatches) {
        throw new Error("Custom regex match budget exceeded");
      }
      return task.replacement;
    });
    return { taskId: task.taskId, id: task.id, ok: true, output, count };
  } catch (error) {
    if (error instanceof Error && /match budget/i.test(error.message)) {
      return {
        taskId: task.taskId,
        id: task.id,
        ok: false,
        code: "budget",
        limit: "matches",
        message: error.message,
      };
    }
    return {
      taskId: task.taskId,
      id: task.id,
      ok: false,
      code: "worker-error",
      message: error instanceof Error ? error.message : "Custom regex failed",
    };
  }
}

function uniqueFlags(flags: string) {
  return Array.from(new Set(flags.split(""))).join("");
}
