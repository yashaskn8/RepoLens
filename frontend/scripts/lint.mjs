import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { FlatESLint } = require("eslint/use-at-your-own-risk");
const eslint = new FlatESLint();
const results = await eslint.lintFiles(["src/**/*.{js,jsx,ts,tsx}"]);
const formatter = await eslint.loadFormatter("stylish");
const output = formatter.format(results);

if (output) {
  process.stdout.write(output);
}

if (results.some((result) => result.errorCount > 0)) {
  process.exitCode = 1;
}
