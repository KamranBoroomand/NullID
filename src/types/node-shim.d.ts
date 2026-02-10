declare module "node:test" {
  export const describe: (...args: unknown[]) => void;
  export const it: (...args: unknown[]) => void;
}

declare module "node:assert/strict" {
  const assert: {
    equal: (actual: unknown, expected: unknown) => void;
    rejects: (fn: () => unknown | Promise<unknown>) => Promise<void>;
  };
  export = assert;
}

declare const Buffer: any;

interface ImportMetaEnv {
  readonly PROD: boolean;
  readonly BASE_URL: string;
  readonly VITE_BUILD_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
