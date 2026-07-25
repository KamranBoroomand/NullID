import fs from "node:fs";
import path from "node:path";

const cwd = process.cwd();
const buildTestDir = path.join(cwd, "build-test");
const tsBuildInfo = path.join(cwd, "tsconfig.test.tsbuildinfo");

fs.rmSync(buildTestDir, { recursive: true, force: true });
fs.rmSync(tsBuildInfo, { force: true });
