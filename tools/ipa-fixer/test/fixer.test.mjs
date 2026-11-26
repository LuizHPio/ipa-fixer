import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import {
  CRC32_INIT,
  crc32,
  crc32Finalize,
  crc32Update,
  createPatchAndCrcTransform,
  getEntryDataRange,
  inspectMachOStream,
  openEntryDecompressedStream,
  parseMachOSliceHeader,
  readZipCentralDirectory,
} from "../dist/index.js";
import { fixIpaFile, openFileSource } from "../dist/node.js";
import {
  fixIpaBlob as browserFixIpaBlob,
  readZipCentralDirectory as browserReadZipCentralDirectory,
  createBlobSource as browserCreateBlobSource,
  getEntryDataRange as browserGetEntryDataRange,
  openEntryDecompressedStream as browserOpenEntryDecompressedStream,
} from "../../../web/ipa-fixer.esm.js";

async function readStreamAll(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

function buildThinMachO64({
  stroff = 0x1000,
  strsize = 0x100,
  sigDataoff = 0x1100,
  littleEndian = true,
} = {}) {
  const hdrSize = 32;
  const symtabSize = 24;
  const sigCmdSize = 16;
  const sizeofcmds = symtabSize + sigCmdSize;
  const buf = new Uint8Array(hdrSize + sizeofcmds);
  const view = new DataView(buf.buffer);

  view.setUint32(0, littleEndian ? 0xcffaedfe : 0xfeedfacf, false);
  view.setUint32(4, 0x0100000c, littleEndian);
  view.setUint32(8, 0, littleEndian);
  view.setUint32(12, 2, littleEndian);
  view.setUint32(16, 2, littleEndian);
  view.setUint32(20, sizeofcmds, littleEndian);

  view.setUint32(32, 0x2, littleEndian);
  view.setUint32(36, symtabSize, littleEndian);
  view.setUint32(40, 0x800, littleEndian);
  view.setUint32(44, 10, littleEndian);
  view.setUint32(48, stroff, littleEndian);
  view.setUint32(52, strsize, littleEndian);

  view.setUint32(56, 0x1d, littleEndian);
  view.setUint32(60, sigCmdSize, littleEndian);
  view.setUint32(64, sigDataoff, littleEndian);
  view.setUint32(68, 0x200, littleEndian);

  return buf;
}

function buildThinMachO32({
  stroff = 0x1000,
  strsize = 0x100,
  sigDataoff = 0x2000,
} = {}) {
  const hdrSize = 28;
  const symtabSize = 24;
  const sigCmdSize = 16;
  const sizeofcmds = symtabSize + sigCmdSize;
  const buf = new Uint8Array(hdrSize + sizeofcmds);
  const view = new DataView(buf.buffer);

  view.setUint32(0, 0xcefaedfe, false);
  view.setUint32(4, 12, true);
  view.setUint32(12, 2, true);
  view.setUint32(16, 2, true);
  view.setUint32(20, sizeofcmds, true);

  view.setUint32(28, 0x2, true);
  view.setUint32(32, symtabSize, true);
  view.setUint32(44, stroff, true);
  view.setUint32(48, strsize, true);

  view.setUint32(52, 0x1d, true);
  view.setUint32(56, sigCmdSize, true);
  view.setUint32(60, sigDataoff, true);
  view.setUint32(64, 0x100, true);

  return buf;
}

async function deflateRaw(bytes) {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return readStreamAll(cs.readable);
}

/**
 * Builds a valid multi-entry ZIP archive, optionally setting bit 3 data descriptors.
 */
async function buildZipArchive(items) {
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const item of items) {
    const nameBytes = new TextEncoder().encode(item.name);
    const rawPayload = item.bytes ?? new Uint8Array(0);
    const method = item.compress ? 8 : 0;
    const compressed = method === 8 ? await deflateRaw(rawPayload) : rawPayload;
    const crc = crc32(rawPayload);
    const flags = item.dataDescriptor ? 0x0008 : 0x0000;
    const externalAttr = item.externalAttr ?? (item.name.endsWith("/") ? 0x41ed0000 : 0x81a40000);

    const lfh = new Uint8Array(30 + nameBytes.length);
    const lfhView = new DataView(lfh.buffer);
    lfhView.setUint32(0, 0x04034b50, true);
    lfhView.setUint16(4, 20, true);
    lfhView.setUint16(6, flags, true);
    lfhView.setUint16(8, method, true);
    lfhView.setUint32(14, item.dataDescriptor ? 0 : crc, true);
    lfhView.setUint32(18, item.dataDescriptor ? 0 : compressed.length, true);
    lfhView.setUint32(22, item.dataDescriptor ? 0 : rawPayload.length, true);
    lfhView.setUint16(26, nameBytes.length, true);
    lfh.set(nameBytes, 30);

    localParts.push(lfh, compressed);

    let ddLen = 0;
    if (item.dataDescriptor) {
      const dd = new Uint8Array(16);
      const ddView = new DataView(dd.buffer);
      ddView.setUint32(0, 0x08074b50, true);
      ddView.setUint32(4, crc, true);
      ddView.setUint32(8, compressed.length, true);
      ddView.setUint32(12, rawPayload.length, true);
      localParts.push(dd);
      ddLen = dd.length;
    }

    const cd = new Uint8Array(46 + nameBytes.length);
    const cdView = new DataView(cd.buffer);
    cdView.setUint32(0, 0x02014b50, true);
    cdView.setUint16(4, 0x031e, true);
    cdView.setUint16(6, 20, true);
    cdView.setUint16(8, flags, true);
    cdView.setUint16(10, method, true);
    cdView.setUint32(16, crc, true);
    cdView.setUint32(20, compressed.length, true);
    cdView.setUint32(24, rawPayload.length, true);
    cdView.setUint16(28, nameBytes.length, true);
    cdView.setUint32(38, externalAttr >>> 0, true);
    cdView.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    cdParts.push(cd);

    offset += lfh.length + compressed.length + ddLen;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const cd of cdParts) cdSize += cd.length;

  const eocd = new Uint8Array(22);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, items.length, true);
  eocdView.setUint16(10, items.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdOffset, true);

  const total = cdOffset + cdSize + eocd.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of localParts) {
    out.set(p, pos);
    pos += p.length;
  }
  for (const p of cdParts) {
    out.set(p, pos);
    pos += p.length;
  }
  out.set(eocd, pos);
  return out;
}

async function buildSyntheticIpaBytes() {
  const brokenMain = buildThinMachO64({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1500 });
  const brokenExtKit = buildThinMachO64({ stroff: 0x800, strsize: 0x80, sigDataoff: 0x1000 });
  const brokenPlugIn = buildThinMachO64({ stroff: 0x900, strsize: 0x90, sigDataoff: 0x1200 });
  const healthyDylib = buildThinMachO64({ stroff: 0x500, strsize: 0x100, sigDataoff: 0x608 });
  const assetData = new TextEncoder().encode('{"CFBundleIdentifier":"com.example.Demo"}');
  const sigData = new TextEncoder().encode("dummy-code-resources");

  return buildZipArchive([
    { name: "Payload/", bytes: null },
    { name: "Payload/Demo.app/", bytes: null },
    { name: "Payload/Demo.app/Demo", bytes: brokenMain, compress: true, dataDescriptor: true, externalAttr: 0x81ed0000 },
    { name: "Payload/Demo.app/Frameworks/Healthy.dylib", bytes: healthyDylib, compress: true, externalAttr: 0x81ed0000 },
    { name: "Payload/Demo.app/Info.plist", bytes: assetData, compress: true, dataDescriptor: true },
    { name: "Payload/Demo.app/_CodeSignature/CodeResources", bytes: sigData, compress: true },
    { name: "Payload/Demo.app/Extensions/DemoMigration.appex/DemoMigration", bytes: brokenExtKit, compress: true, externalAttr: 0x81ed0000 },
    { name: "Payload/Demo.app/Extensions/DemoMigration.appex/_CodeSignature/CodeResources", bytes: sigData, compress: false },
    { name: "Payload/Demo.app/PlugIns/DemoShare.appex/DemoShare", bytes: brokenPlugIn, compress: true, externalAttr: 0x81ed0000 },
    { name: "Payload/Demo.app/PlugIns/DemoShare.appex/_CodeSignature/CodeResources", bytes: sigData, compress: false },
  ]);
}

test("crc32 standard test vector and streaming updates", () => {
  const input = new TextEncoder().encode("123456789");
  assert.equal(crc32(input), 0xcbf43926);

  let state = CRC32_INIT;
  state = crc32Update(state, input.subarray(0, 4));
  state = crc32Update(state, input.subarray(4, 7));
  state = crc32Update(state, input.subarray(7));
  assert.equal(crc32Finalize(state), 0xcbf43926);
});

test("createPatchAndCrcTransform handles patches straddling chunk boundaries", async () => {
  const src = new Uint8Array(32);
  for (let i = 0; i < src.length; i++) src[i] = i;

  const patch = {
    sliceOffset: 0,
    cputype: 0x0100000c,
    littleEndian: true,
    oldStrsize: 0x0d0c0b0a,
    newStrsize: 0x11223344,
    oldEnd: 0,
    newEnd: 0,
    gap: 100,
    strsizeFileOffset: 10,
  };

  const { transform, getResult } = createPatchAndCrcTransform([patch]);
  const chunkedInput = new ReadableStream({
    start(controller) {
      controller.enqueue(src.subarray(0, 11));
      controller.enqueue(src.subarray(11, 12));
      controller.enqueue(src.subarray(12, 14));
      controller.enqueue(src.subarray(14));
      controller.close();
    },
  });

  const out = await readStreamAll(chunkedInput.pipeThrough(transform));
  const { crc32: gotCrc, uncompressedSize } = getResult();

  const expected = new Uint8Array(src);
  new DataView(expected.buffer).setUint32(10, 0x11223344, true);

  assert.equal(uncompressedSize, 32);
  assert.deepEqual(out, expected);
  assert.equal(gotCrc, crc32(expected));
});

test("parseMachOSliceHeader and inspectMachOStream distinguish Thin32, Thin64, FAT, and Java .class", async () => {
  // 1. Healthy Thin64 (gap 8 bytes <= 0x10)
  const healthy64 = buildThinMachO64({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1108 });
  const hRes = parseMachOSliceHeader(healthy64, 0);
  assert.ok(hRes.sliceInfo !== null);
  assert.equal(hRes.sliceInfo.gap, 8);
  assert.equal(hRes.patch, null);

  // 2. Broken Thin32 (gap 0xf00 > 0x10)
  const broken32 = buildThinMachO32({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x2000 });
  const b32Stream = new Blob([broken32]).stream();
  const b32Inspect = await inspectMachOStream(b32Stream, broken32.length);
  assert.equal(b32Inspect.isMachO, true);
  assert.equal(b32Inspect.patches.length, 1);
  assert.equal(b32Inspect.patches[0].strsizeFileOffset, 48);
  assert.equal(b32Inspect.patches[0].newStrsize, 0x1000);

  // 3. FAT Mach-O with 2 slices at offsets 0x1000 and 0x2000
  const fatBuf = new Uint8Array(0x2200);
  const fatView = new DataView(fatBuf.buffer);
  fatView.setUint32(0, 0xcafebabe, false);
  fatView.setUint32(4, 2, false);
  fatView.setUint32(8, 0x0100000c, false);
  fatView.setUint32(16, 0x1000, false);
  fatView.setUint32(20, 0x500, false);
  fatView.setUint32(28, 0x01000007, false);
  fatView.setUint32(36, 0x2000, false);
  fatView.setUint32(40, 0x200, false);

  const slice0 = buildThinMachO64({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1100 });
  const slice1 = buildThinMachO64({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1200 });
  fatBuf.set(slice0, 0x1000);
  fatBuf.set(slice1, 0x2000);

  const fatInspect = await inspectMachOStream(new Blob([fatBuf]).stream(), fatBuf.length);
  assert.equal(fatInspect.isMachO, true);
  assert.equal(fatInspect.slices.length, 2);
  assert.equal(fatInspect.patches.length, 1);
  assert.equal(fatInspect.patches[0].sliceOffset, 0x2000);
  assert.equal(fatInspect.patches[0].strsizeFileOffset, 0x2000 + 32 + 20);

  // 4. Java .class file (0xCAFEBABE + version 52) must NOT be treated as FAT Mach-O
  const javaClass = new Uint8Array(128);
  const jView = new DataView(javaClass.buffer);
  jView.setUint32(0, 0xcafebabe, false);
  jView.setUint16(4, 0, false);
  jView.setUint16(6, 52, false);
  const javaInspect = await inspectMachOStream(new Blob([javaClass]).stream(), javaClass.length);
  assert.equal(javaInspect.isMachO, false);
  assert.equal(javaInspect.patches.length, 0);
});

test("Node fixIpaFile dry-run and stripExtensions produce valid ZIP with fixed executable", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-fixer-node1-"));
  const inIpa = path.join(tmpDir, "demo.ipa");
  const outIpa = path.join(tmpDir, "demo_fixed.ipa");

  try {
    fs.writeFileSync(inIpa, await buildSyntheticIpaBytes());

    const dryStats = await fixIpaFile(inIpa, null, { dryRun: true });
    assert.equal(dryStats.binariesScanned, 4);
    assert.equal(dryStats.binariesAffected, 3);
    assert.equal(dryStats.offsetsFound, 3);
    assert.equal(dryStats.signaturesCleaned, 3);

    const fixStats = await fixIpaFile(inIpa, outIpa, { stripExtensions: true });
    assert.equal(fixStats.binariesScanned, 2);
    assert.equal(fixStats.binariesAffected, 1);
    assert.equal(fixStats.offsetsFound, 1);
    assert.equal(fixStats.extensionKitFoldersRemoved, 1);
    assert.equal(fixStats.plugInsFoldersRemoved, 1);
    assert.equal(fixStats.signaturesCleaned, 1);

    const pyCheck = execFileSync(
      "python3",
      ["-c", "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); bad = z.testzip(); assert bad is None, f'Bad CRC: {bad}'; print('ZIP_OK')", outIpa],
      { encoding: "utf8" }
    ).trim();
    assert.equal(pyCheck, "ZIP_OK");

    const recheck = await fixIpaFile(outIpa, null, { dryRun: true });
    assert.equal(recheck.binariesAffected, 0);
    assert.equal(recheck.offsetsFound, 0);
    assert.equal(recheck.signaturesCleaned, 0);

    const { source, close } = await openFileSource(outIpa);
    try {
      const entries = await readZipCentralDirectory(source);
      assert.equal(entries.some((e) => e.fileName.includes("/Extensions/")), false);
      assert.equal(entries.some((e) => e.fileName.includes("/PlugIns/")), false);
      assert.equal(entries.some((e) => e.fileName.includes("_CodeSignature")), false);

      const demoEntry = entries.find((e) => e.fileName === "Payload/Demo.app/Demo");
      assert.ok(demoEntry);
      assert.equal(demoEntry.flags & 0x0008, 0);
      assert.equal((demoEntry.externalAttr >>> 16) & 0o777, 0o755);

      const { dataStart, dataEnd } = await getEntryDataRange(source, demoEntry);
      const patchedBytes = await readStreamAll(
        openEntryDecompressedStream(source, demoEntry, dataStart, dataEnd)
      );
      const inspectAfter = await inspectMachOStream(
        new Blob([patchedBytes]).stream(),
        patchedBytes.length
      );
      assert.equal(inspectAfter.isMachO, true);
      assert.equal(inspectAfter.patches.length, 0);
      assert.equal(inspectAfter.slices[0].strsize, 0x500);
    } finally {
      await close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Node fixIpaFile with stripExtensionKit removes Extensions/ while keeping & patching PlugIns/", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-fixer-node2-"));
  const inIpa = path.join(tmpDir, "demo.ipa");
  const outIpa = path.join(tmpDir, "demo_extkit.ipa");

  try {
    fs.writeFileSync(inIpa, await buildSyntheticIpaBytes());

    const fixStats = await fixIpaFile(inIpa, outIpa, { stripExtensionKit: true });
    assert.equal(fixStats.binariesScanned, 3);
    assert.equal(fixStats.binariesAffected, 2);
    assert.equal(fixStats.offsetsFound, 2);
    assert.equal(fixStats.extensionKitFoldersRemoved, 1);
    assert.equal(fixStats.plugInsFoldersRemoved, 0);
    assert.equal(fixStats.signaturesCleaned, 2);

    const recheck = await fixIpaFile(outIpa, null, { dryRun: true });
    assert.equal(recheck.binariesAffected, 0);
    assert.equal(recheck.offsetsFound, 0);

    const { source, close } = await openFileSource(outIpa);
    try {
      const entries = await readZipCentralDirectory(source);
      assert.equal(entries.some((e) => e.fileName.includes("/Extensions/")), false);
      assert.equal(
        entries.some((e) => e.fileName === "Payload/Demo.app/PlugIns/DemoShare.appex/DemoShare"),
        true
      );
    } finally {
      await close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Browser ESM bundle (web/ipa-fixer.esm.js) fixes synthetic IPA Blob client-side", async () => {
  const ipaBytes = await buildSyntheticIpaBytes();
  const result = await browserFixIpaBlob(new Blob([ipaBytes]), { stripExtensionKit: true });
  assert.equal(result.stats.binariesScanned, 3);
  assert.equal(result.stats.binariesAffected, 2);
  assert.equal(result.stats.offsetsFound, 2);
  assert.equal(result.stats.extensionKitFoldersRemoved, 1);
  assert.ok(result.blob !== null);

  const outSource = browserCreateBlobSource(result.blob);
  const outEntries = await browserReadZipCentralDirectory(outSource);
  assert.equal(outEntries.some((e) => e.fileName.includes("/Extensions/")), false);

  const demoEntry = outEntries.find((e) => e.fileName === "Payload/Demo.app/Demo");
  assert.ok(demoEntry);
  assert.equal(demoEntry.flags & 0x0008, 0);
  const range = await browserGetEntryDataRange(outSource, demoEntry);
  const patchedBytes = await readStreamAll(
    browserOpenEntryDecompressedStream(outSource, demoEntry, range.dataStart, range.dataEnd)
  );
  const check = await inspectMachOStream(new Blob([patchedBytes]).stream(), patchedBytes.length);
  assert.equal(check.patches.length, 0);
  assert.equal(check.slices[0].strsize, 0x500);
});
