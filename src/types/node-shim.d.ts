declare module "node:test" {
  export const describe: (...args: unknown[]) => void;
  export const it: (...args: unknown[]) => void;
}

declare module "node:assert/strict" {
  const assert: {
    equal: (actual: unknown, expected: unknown) => void;
    deepEqual: (actual: unknown, expected: unknown) => void;
    match: (actual: string, expected: RegExp) => void;
    rejects: (fn: () => unknown | Promise<unknown>) => Promise<void>;
  };
  export = assert;
}

declare module "node:fs" {
  export function readFileSync(path: string, encoding: string): string;
}

declare module "node:child_process" {
  export function execFileSync(file: string, args?: string[], options?: Record<string, unknown>): string;
  export function spawnSync(
    file: string,
    args?: string[],
    options?: Record<string, unknown>,
  ): { status: number | null; stdout: string; stderr: string };
}

declare module "node:path" {
  const path: {
    resolve: (...parts: string[]) => string;
    join: (...parts: string[]) => string;
    basename: (value: string) => string;
  };
  export default path;
}

declare const Buffer: any;
declare const process: {
  cwd: () => string;
  env: Record<string, string | undefined>;
  execPath: string;
};

interface ImportMetaEnv {
  readonly PROD: boolean;
  readonly BASE_URL: string;
  readonly VITE_BUILD_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
