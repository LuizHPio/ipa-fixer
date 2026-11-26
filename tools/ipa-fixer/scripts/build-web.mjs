import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");
const webDir = path.join(repoRoot, "web");

fs.mkdirSync(webDir, { recursive: true });

// Ensure dist/cli.js is executable if built
const cliDist = path.join(pkgRoot, "dist", "cli.js");
if (fs.existsSync(cliDist)) {
  fs.chmodSync(cliDist, 0o755);
}

// 1. Bundle standalone browser ESM library -> web/ipa-fixer.esm.js
const esmOut = path.join(webDir, "ipa-fixer.esm.js");
await esbuild.build({
  entryPoints: [path.join(pkgRoot, "src", "index.ts")],
  outfile: esmOut,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  sourcemap: false,
  minify: false,
});

// 2. Bundle Web Worker IIFE in memory and embed into web/index.html
const workerResult = await esbuild.build({
  entryPoints: [path.join(pkgRoot, "web-src", "worker.ts")],
  bundle: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: "es2022",
  sourcemap: false,
  minify: true,
});

const workerCode = workerResult.outputFiles[0]?.text;
if (!workerCode) {
  throw new Error("esbuild produced empty worker output.");
}

// Prevent accidental </script> termination inside HTML
const escapedWorkerCode = workerCode.replace(/<\/script/gi, "<\\/script");

const templatePath = path.join(pkgRoot, "web-src", "template.html");
const template = fs.readFileSync(templatePath, "utf8");
const marker = "/*__EMBEDDED_WORKER__*/";
if (!template.includes(marker)) {
  throw new Error(`Missing marker ${marker} in ${templatePath}`);
}

const finalHtml = template.replace(marker, () => escapedWorkerCode);
const htmlOut = path.join(webDir, "index.html");
fs.writeFileSync(htmlOut, finalHtml, "utf8");

console.log(`Built ${path.relative(repoRoot, esmOut)} (${fs.statSync(esmOut).size.toLocaleString("en-US")} bytes)`);
console.log(`Built ${path.relative(repoRoot, htmlOut)} (${fs.statSync(htmlOut).size.toLocaleString("en-US")} bytes)`);
