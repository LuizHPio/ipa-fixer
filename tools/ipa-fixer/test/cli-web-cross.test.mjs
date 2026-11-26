import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import * as vm from "node:vm";

import {
  getEntryDataRange,
  openEntryDecompressedStream,
  readZipCentralDirectory,
} from "../dist/index.js";
import { openFileSource } from "../dist/node.js";
import {
  createBlobSource as browserCreateBlobSource,
  fixIpaBlob as browserFixIpaBlob,
  getEntryDataRange as browserGetEntryDataRange,
  inspectIpaBlob as browserInspectIpaBlob,
  openEntryDecompressedStream as browserOpenEntryDecompressedStream,
  readZipCentralDirectory as browserReadZipCentralDirectory,
} from "../../../web/ipa-fixer.esm.js";
import {
  assertValidZipWithPython,
  buildSyntheticIpaBytes,
  readStreamAll,
  sha256,
} from "./helpers.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "..", "..");

const CLI_JS = path.join(pkgRoot, "dist", "cli.js");
const PYTHON_CLI = path.join(repoRoot, "tools", "python", "ipa_ldid_fixer.py");
const WEB_HTML = path.join(repoRoot, "web", "index.html");
const WEB_ESM = path.join(repoRoot, "web", "ipa-fixer.esm.js");

test("Node CLI: --help, error handling, NO_COLOR, ANSI color, default output path, and all flags", async () => {
  const helpRun = spawnSync("node", [CLI_JS, "--help"], { encoding: "utf8" });
  assert.equal(helpRun.status, 0);
  assert.match(helpRun.stdout, /Usage: ipa-ldid-fixer/);
  assert.match(helpRun.stdout, /--strip-extensionkit/);

  // Error cases
  for (const badArgs of [
    [],
    ["does-not-exist.ipa"],
    ["foo.ipa", "--unknown-flag"],
    ["foo.ipa", "-o"],
  ]) {
    const res = spawnSync("node", [CLI_JS, ...badArgs], { encoding: "utf8" });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /\[X\] Error:/);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-cli-"));
  const inIpa = path.join(tmpDir, "sample.ipa");
  fs.writeFileSync(inIpa, await buildSyntheticIpaBytes());

  try {
    // Dry run with NO_COLOR=1 -> zero ANSI escapes, no output file created
    const dryNoColor = spawnSync("node", [CLI_JS, inIpa, "--dry-run", "-v"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    assert.equal(dryNoColor.status, 0);
    assert.equal(dryNoColor.stdout.includes("\x1b["), false);
    assert.match(dryNoColor.stdout, /Binaries scanned:\s+4/);
    assert.match(dryNoColor.stdout, /Binaries needing repair:\s+3/);
    assert.match(dryNoColor.stdout, /Offsets with wrong value:\s+3/);
    assert.equal(fs.existsSync(path.join(tmpDir, "sample_fixed.ipa")), false);

    // Dry run with color enabled -> emits ANSI escape sequences
    const envWithColor = { ...process.env };
    delete envWithColor.NO_COLOR;
    const dryColor = spawnSync("node", [CLI_JS, inIpa, "--dry-run"], {
      encoding: "utf8",
      env: envWithColor,
    });
    assert.equal(dryColor.status, 0);
    assert.equal(dryColor.stdout.includes("\x1b["), true);

    // Default output path (<stem>_fixed.ipa) when -o omitted
    const defaultOutRun = spawnSync("node", [CLI_JS, inIpa], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    assert.equal(defaultOutRun.status, 0);
    const defaultOutPath = path.join(tmpDir, "sample_fixed.ipa");
    assert.equal(fs.existsSync(defaultOutPath), true);
    assertValidZipWithPython(defaultOutPath);

    // --strip-extensionkit + -o
    const extKitOut = path.join(tmpDir, "extkit.ipa");
    const extKitRun = spawnSync(
      "node",
      [CLI_JS, inIpa, "--strip-extensionkit", "-o", extKitOut],
      { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }
    );
    assert.equal(extKitRun.status, 0);
    assert.match(extKitRun.stdout, /ExtensionKit removed:\s+1/);
    assertValidZipWithPython(extKitOut);

    // --strip-plugins --keep-signatures --scan-all
    const comboOut = path.join(tmpDir, "combo.ipa");
    const comboRun = spawnSync(
      "node",
      [CLI_JS, inIpa, "--strip-plugins", "--keep-signatures", "--scan-all", "-o", comboOut],
      { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }
    );
    assert.equal(comboRun.status, 0);
    assert.match(comboRun.stdout, /Offsets corrected:\s+3/);
    assertValidZipWithPython(comboOut);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Web assets: zero node:* imports, valid JS syntax, and live execution of embedded Web Worker", async () => {
  const esmSrc = fs.readFileSync(WEB_ESM, "utf8");
  assert.equal(/from\s+["']node:|require\(["']node:/.test(esmSrc), false);

  const html = fs.readFileSync(WEB_HTML, "utf8");
  assert.equal(html.includes("/*__EMBEDDED_WORKER__*/"), false);
  assert.equal(/<(?:script|link)[^>]+https?:\/\//i.test(html), false);

  const workerMatch = html.match(
    /<script id="ipa-fixer-worker" type="text\/plain">([\s\S]*?)<\/script>/
  );
  assert.ok(workerMatch, "Embedded worker script tag missing");
  const workerCode = workerMatch[1].replace(/<\\\/script/gi, "</script");

  const uiMatch = html.match(/<script>\s*([\s\S]*?)<\/script>\s*<\/body>/);
  assert.ok(uiMatch, "UI script tag missing");
  const uiCode = uiMatch[1];

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-web-check-"));
  try {
    const wf = path.join(tmpDir, "worker.js");
    const uf = path.join(tmpDir, "ui.js");
    fs.writeFileSync(wf, workerCode);
    fs.writeFileSync(uf, uiCode);
    execFileSync("node", ["--check", wf]);
    execFileSync("node", ["--check", uf]);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // Test browser inspectIpaBlob + fixIpaBlob dryRun directly
  const ipaBytes = await buildSyntheticIpaBytes();
  const inspectStats = await browserInspectIpaBlob(new Blob([ipaBytes]), {
    stripExtensionKit: true,
  });
  assert.equal(inspectStats.binariesAffected, 2);

  const dryRes = await browserFixIpaBlob(new Blob([ipaBytes]), { dryRun: true });
  assert.equal(dryRes.blob, null);

  // Execute the ACTUAL embedded worker JS from web/index.html inside a sandboxed VM
  const posted = [];
  let resolveDone;
  let rejectDone;
  const donePromise = new Promise((res, rej) => {
    resolveDone = res;
    rejectDone = rej;
  });

  const sandbox = {
    Blob,
    File,
    CompressionStream,
    DecompressionStream,
    TransformStream,
    ReadableStream,
    AbortController,
    DOMException,
    TextDecoder,
    TextEncoder,
    Uint8Array,
    DataView,
    ArrayBuffer,
    BigInt,
    performance,
    Set,
    Map,
    Error,
    RangeError,
    Math,
    Number,
    String,
    Boolean,
    Array,
    Object,
    RegExp,
    postMessage(msg) {
      posted.push(msg);
      if (msg.type === "done") resolveDone(msg);
      if (msg.type === "error") rejectDone(new Error(msg.message));
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(workerCode, sandbox);

  assert.equal(typeof sandbox.onmessage, "function");

  const fakeFile = new File([ipaBytes], "demo.ipa", { type: "application/octet-stream" });
  sandbox.onmessage({
    data: {
      type: "start",
      file: fakeFile,
      options: {
        stripExtensionKit: true,
        stripPlugIns: false,
        cleanSignatures: true,
        dryRun: false,
        verbose: true,
      },
    },
  });

  const doneMsg = await donePromise;
  assert.equal(doneMsg.stats.binariesScanned, 3);
  assert.equal(doneMsg.stats.binariesAffected, 2);
  assert.equal(doneMsg.stats.extensionKitFoldersRemoved, 1);
  assert.ok(doneMsg.blob instanceof Blob);
  assert.ok(posted.some((m) => m.type === "progress" && m.event.type === "patch"));
  assert.ok(posted.some((m) => m.type === "progress" && m.event.type === "inspect"));

  const wSrc = browserCreateBlobSource(doneMsg.blob);
  const wEntries = await browserReadZipCentralDirectory(wSrc);
  assert.equal(wEntries.some((e) => e.fileName.includes("/Extensions/")), false);
  const demoEntry = wEntries.find((e) => e.fileName === "Payload/Demo.app/Demo");
  assert.ok(demoEntry);
  const range = await browserGetEntryDataRange(wSrc, demoEntry);
  const patchedBytes = await readStreamAll(
    browserOpenEntryDecompressedStream(wSrc, demoEntry, range.dataStart, range.dataEnd)
  );
  // Check strsize at offset 32 + 2*16 + 20 = 84 (0x54): expected 0x1500 - 0x1000 = 0x500
  assert.equal(new DataView(patchedBytes.buffer).getUint32(84, true), 0x500);

  // Also test worker cancel message
  let cancelResult;
  const cancelPromise = new Promise((res) => {
    cancelResult = res;
  });
  sandbox.postMessage = (msg) => {
    if (msg.type === "error" || msg.type === "done") cancelResult(msg);
  };
  sandbox.onmessage({
    data: {
      type: "start",
      file: fakeFile,
      options: {
        stripExtensionKit: false,
        stripPlugIns: false,
        cleanSignatures: true,
        dryRun: false,
        verbose: false,
      },
    },
  });
  sandbox.onmessage({ data: { type: "cancel" } });
  const cMsg = await cancelPromise;
  assert.equal(cMsg.type, "error");
  assert.equal(cMsg.aborted, true);
});

test("Cross-verification: Python CLI and Node CLI produce bit-for-bit identical patched Mach-O binary", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-cross-"));
  const inIpa = path.join(tmpDir, "demo.ipa");
  const nodeOut = path.join(tmpDir, "node_fixed.ipa");
  const pyOut = path.join(tmpDir, "py_fixed.ipa");

  try {
    fs.writeFileSync(inIpa, await buildSyntheticIpaBytes());

    const nodeRes = spawnSync(
      "node",
      [CLI_JS, inIpa, "--strip-extensions", "-o", nodeOut],
      { encoding: "utf8" }
    );
    assert.equal(nodeRes.status, 0, nodeRes.stderr);

    const pyRes = spawnSync(
      "python3",
      [PYTHON_CLI, inIpa, "--strip-extensions", "-o", pyOut],
      { encoding: "utf8" }
    );
    assert.equal(pyRes.status, 0, pyRes.stderr);

    assertValidZipWithPython(nodeOut);
    assertValidZipWithPython(pyOut);

    const extractDemo = async (ipaPath) => {
      const { source, close } = await openFileSource(ipaPath);
      try {
        const entries = await readZipCentralDirectory(source);
        const demoEntry = entries.find((e) => e.fileName === "Payload/Demo.app/Demo");
        assert.ok(demoEntry);
        const { dataStart, dataEnd } = await getEntryDataRange(source, demoEntry);
        return await readStreamAll(
          openEntryDecompressedStream(source, demoEntry, dataStart, dataEnd)
        );
      } finally {
        await close();
      }
    };

    const nodeDemo = await extractDemo(nodeOut);
    const pyDemo = await extractDemo(pyOut);
    assert.equal(nodeDemo.length, pyDemo.length);
    assert.equal(sha256(nodeDemo), sha256(pyDemo));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
