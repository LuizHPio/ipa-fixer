import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import {
  createBlobSource,
  fixIpaBlob,
  getEntryDataRange,
  inspectMachOStream,
  openEntryDecompressedStream,
  readZipCentralDirectory,
} from "../dist/index.js";
import { fixIpaFile, openFileSource } from "../dist/node.js";
import {
  assertValidZipWithPython,
  buildSyntheticIpaBytes,
  buildThinMachO,
  buildZipArchive,
  readStreamAll,
  sha256,
} from "./helpers.mjs";

test("ZIP edge cases: comments, corrupt/truncated ZIPs, mismatched LFH/CD extras, UTF-8, symlinks, unsupported compression", async () => {
  // 1. Corrupt / too-small / missing EOCD errors
  await assert.rejects(
    () => readZipCentralDirectory(createBlobSource(new Blob([new Uint8Array(10)]))),
    /too small/i
  );
  await assert.rejects(
    () => readZipCentralDirectory(createBlobSource(new Blob([new Uint8Array(100)]))),
    /End of Central Directory/i
  );

  // 2. Unsupported compression method (99) passes through untouched in fixIpaBlob,
  //    but fails cleanly if openEntryDecompressedStream is invoked directly.
  const customPayload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const unsupportedZip = await buildZipArchive(
    [
      {
        name: "Payload/Demo.app/custom.dat",
        bytes: customPayload,
        compressionMethod: 99,
        rawCompressedBytes: customPayload,
      },
    ],
    { comment: "eocd-comment-with-text" }
  );
  const resUnsupported = await fixIpaBlob(new Blob([unsupportedZip]));
  assert.ok(resUnsupported.blob !== null);
  const uSrc = createBlobSource(resUnsupported.blob);
  const uEntries = await readZipCentralDirectory(uSrc);
  assert.equal(uEntries.length, 1);
  assert.equal(uEntries[0].compressionMethod, 99);
  const uRange = await getEntryDataRange(uSrc, uEntries[0]);
  assert.throws(
    () => openEntryDecompressedStream(uSrc, uEntries[0], uRange.dataStart, uRange.dataEnd),
    /Unsupported ZIP compression method 99/
  );

  // 3. Synthetic IPA: verify comment archive parses, LFH != CD extra lengths handled,
  //    UTF-8 filename preserved, symlink untouched, and Python zipfile.testzip() passes.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-zip-edge-"));
  const inIpa = path.join(tmpDir, "in.ipa");
  const outIpa = path.join(tmpDir, "out.ipa");
  try {
    const ipaBytes = await buildSyntheticIpaBytes();
    fs.writeFileSync(inIpa, ipaBytes);

    const stats = await fixIpaFile(inIpa, outIpa);
    assert.equal(stats.binariesScanned, 4);
    assert.equal(stats.binariesAffected, 3);
    assert.equal(stats.offsetsFound, 3);
    assert.equal(stats.signaturesCleaned, 4);

    assertValidZipWithPython(outIpa);

    const { source, close } = await openFileSource(outIpa);
    try {
      const entries = await readZipCentralDirectory(source);

      // UTF-8 entry preserved
      const utf8Entry = entries.find((e) => e.fileName === "Payload/Demo.app/Assets/café-🚀.txt");
      assert.ok(utf8Entry);
      const utf8Range = await getEntryDataRange(source, utf8Entry);
      const utf8Bytes = await readStreamAll(
        openEntryDecompressedStream(source, utf8Entry, utf8Range.dataStart, utf8Range.dataEnd)
      );
      assert.equal(new TextDecoder().decode(utf8Bytes), "utf8-asset");

      // Symlink untouched and preserves S_IFLNK mode
      const symEntry = entries.find((e) => e.fileName === "Payload/Demo.app/MachoLink");
      assert.ok(symEntry);
      assert.equal(symEntry.isSymlink, true);
      assert.equal((symEntry.externalAttr >>> 16) & 0o170000, 0o120000);

      // Demo executable cleared bit-3 data descriptor and kept 0o755 executable permissions
      const demoEntry = entries.find((e) => e.fileName === "Payload/Demo.app/Demo");
      assert.ok(demoEntry);
      assert.equal(demoEntry.flags & 0x0008, 0);
      assert.equal((demoEntry.externalAttr >>> 16) & 0o777, 0o755);
    } finally {
      await close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Option matrix: cleanSignatures, stripExtensionKit, stripPlugIns, stripExtensions, scanAllFiles, and idempotency", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-matrix-"));
  const inIpa = path.join(tmpDir, "demo.ipa");
  fs.writeFileSync(inIpa, await buildSyntheticIpaBytes());

  try {
    // 1. cleanSignatures: false
    const keepSigOut = path.join(tmpDir, "keep_sig.ipa");
    const keepSigStats = await fixIpaFile(inIpa, keepSigOut, { cleanSignatures: false });
    assert.equal(keepSigStats.signaturesCleaned, 0);
    assertValidZipWithPython(keepSigOut);
    {
      const { source, close } = await openFileSource(keepSigOut);
      try {
        const entries = await readZipCentralDirectory(source);
        assert.equal(entries.filter((e) => e.fileName.includes("_CodeSignature")).length, 4);
      } finally {
        await close();
      }
    }

    // 2. stripExtensionKit: true
    const extKitOut = path.join(tmpDir, "strip_extkit.ipa");
    const extKitStats = await fixIpaFile(inIpa, extKitOut, { stripExtensionKit: true });
    assert.equal(extKitStats.extensionKitFoldersRemoved, 1);
    assert.equal(extKitStats.plugInsFoldersRemoved, 0);
    assert.equal(extKitStats.signaturesCleaned, 3);
    assert.equal(extKitStats.binariesScanned, 3);
    assert.equal(extKitStats.binariesAffected, 2);
    assertValidZipWithPython(extKitOut);

    // 3. stripPlugIns: true
    const plugInsOut = path.join(tmpDir, "strip_plugins.ipa");
    const plugInsStats = await fixIpaFile(inIpa, plugInsOut, { stripPlugIns: true });
    assert.equal(plugInsStats.extensionKitFoldersRemoved, 0);
    assert.equal(plugInsStats.plugInsFoldersRemoved, 1);
    assert.equal(plugInsStats.signaturesCleaned, 3);
    assert.equal(plugInsStats.binariesScanned, 3);
    assert.equal(plugInsStats.binariesAffected, 2);
    assertValidZipWithPython(plugInsOut);
    {
      const { source, close } = await openFileSource(plugInsOut);
      try {
        const entries = await readZipCentralDirectory(source);
        assert.equal(entries.some((e) => e.fileName.includes("/PlugIns/")), false);
        assert.equal(entries.some((e) => e.fileName.includes("/Extensions/")), true);
      } finally {
        await close();
      }
    }

    // 4. stripExtensions: true + idempotency re-run
    const stripAllOut = path.join(tmpDir, "strip_all.ipa");
    const stripAllStats = await fixIpaFile(inIpa, stripAllOut, { stripExtensions: true });
    assert.equal(stripAllStats.extensionKitFoldersRemoved, 1);
    assert.equal(stripAllStats.plugInsFoldersRemoved, 1);
    assert.equal(stripAllStats.signaturesCleaned, 2);
    assert.equal(stripAllStats.binariesScanned, 2);
    assert.equal(stripAllStats.binariesAffected, 1);
    assertValidZipWithPython(stripAllOut);

    const secondPassOut = path.join(tmpDir, "strip_all_2nd.ipa");
    const secondStats = await fixIpaFile(stripAllOut, secondPassOut);
    assert.equal(secondStats.binariesScanned, 2);
    assert.equal(secondStats.binariesAffected, 0);
    assert.equal(secondStats.offsetsFound, 0);
    assert.equal(secondStats.signaturesCleaned, 0);
    assertValidZipWithPython(secondPassOut);

    // Verify Demo binary SHA-256 didn't change on second pass
    const getDemoSha = async (p) => {
      const { source, close } = await openFileSource(p);
      try {
        const entries = await readZipCentralDirectory(source);
        const entry = entries.find((e) => e.fileName === "Payload/Demo.app/Demo");
        const { dataStart, dataEnd } = await getEntryDataRange(source, entry);
        return sha256(await readStreamAll(openEntryDecompressedStream(source, entry, dataStart, dataEnd)));
      } finally {
        await close();
      }
    };
    assert.equal(await getDemoSha(stripAllOut), await getDemoSha(secondPassOut));

    // 5. scanAllFiles: true detects disguised.png Mach-O
    const scanAllOut = path.join(tmpDir, "scan_all.ipa");
    const scanAllStats = await fixIpaFile(inIpa, scanAllOut, { scanAllFiles: true });
    assert.equal(scanAllStats.binariesScanned, 5);
    assert.equal(scanAllStats.binariesAffected, 4);
    assert.equal(scanAllStats.offsetsFound, 4);
    assert.ok(scanAllStats.details.some((d) => d.file === "Payload/Demo.app/disguised.png"));
    assertValidZipWithPython(scanAllOut);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Progress events (verbose vs default) and AbortSignal cleanup (zero leftover temp files)", async () => {
  const ipaBytes = await buildSyntheticIpaBytes();

  // 1. Verbose false: no 'inspect' events, stages in order, progress reaches total
  const eventsDefault = [];
  await fixIpaBlob(new Blob([ipaBytes]), {
    dryRun: true,
    stripExtensions: true,
    onProgress: (ev) => eventsDefault.push(ev),
  });
  const stages = eventsDefault.filter((e) => e.type === "stage").map((e) => e.stage);
  assert.deepEqual(stages, ["reading-index", "scanning", "done"]);
  assert.equal(eventsDefault.some((e) => e.type === "inspect"), false);
  const progressEvents = eventsDefault.filter((e) => e.type === "progress");
  assert.ok(progressEvents.length > 0);
  const lastProgress = progressEvents[progressEvents.length - 1];
  assert.equal(lastProgress.completed, lastProgress.total);

  // 2. Verbose true: emits 'inspect' events
  const eventsVerbose = [];
  await fixIpaBlob(new Blob([ipaBytes]), {
    dryRun: true,
    verbose: true,
    onProgress: (ev) => eventsVerbose.push(ev),
  });
  assert.equal(eventsVerbose.filter((e) => e.type === "inspect").length, 4);

  // 3. Pre-aborted signal throws AbortError immediately
  const preAborted = new AbortController();
  preAborted.abort(new DOMException("Pre-aborted", "AbortError"));
  await assert.rejects(
    () => fixIpaBlob(new Blob([ipaBytes]), { signal: preAborted.signal }),
    (err) => err instanceof Error && err.name === "AbortError"
  );

  // 4. Mid-flight abort during FileZipSink write leaves zero temp/partial files
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-abort-"));
  const inIpa = path.join(tmpDir, "demo.ipa");
  const outIpa = path.join(tmpDir, "aborted.ipa");
  fs.writeFileSync(inIpa, ipaBytes);

  try {
    const midAbort = new AbortController();
    await assert.rejects(
      () =>
        fixIpaFile(inIpa, outIpa, {
          signal: midAbort.signal,
          onProgress(ev) {
            if (ev.type === "patch") {
              midAbort.abort(new DOMException("Mid-flight cancel", "AbortError"));
            }
          },
        }),
      (err) => err instanceof Error && err.name === "AbortError"
    );

    const remainingFiles = fs.readdirSync(tmpDir);
    assert.deepEqual(remainingFiles, ["demo.ipa"]);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Node openFileSource rejects invalid readRange and streamRange bounds", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-bounds-"));
  const binPath = path.join(tmpDir, "sample.bin");
  fs.writeFileSync(binPath, buildThinMachO());

  try {
    const { source, close } = await openFileSource(binPath);
    try {
      await assert.rejects(() => source.readRange(-1, 4), RangeError);
      await assert.rejects(() => source.readRange(10, 5), RangeError);
      await assert.rejects(() => source.readRange(0, source.size + 1), RangeError);

      assert.throws(() => source.streamRange(-1, 4), RangeError);
      assert.throws(() => source.streamRange(10, 5), RangeError);
      assert.throws(() => source.streamRange(0, source.size + 1), RangeError);
    } finally {
      await close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
