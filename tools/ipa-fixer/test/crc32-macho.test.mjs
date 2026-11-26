import assert from "node:assert/strict";
import test from "node:test";

import {
  CRC32_INIT,
  crc32,
  crc32Finalize,
  crc32Update,
  createPatchAndCrcTransform,
  inspectMachOStream,
  parseMachOSliceHeader,
} from "../dist/index.js";
import { buildFatMachO, buildThinMachO, readStreamAll } from "./helpers.mjs";

test("CRC-32: empty, standard vector, full byte range, and chunked updates", () => {
  assert.equal(crc32(new Uint8Array(0)), 0x00000000);
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);

  const allBytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  assert.equal(crc32(allBytes), 0x29058c73);

  // 1 MB deterministic pseudo-random buffer split across prime chunk sizes
  const big = new Uint8Array(1024 * 1024);
  let seed = 0x12345678;
  for (let i = 0; i < big.length; i++) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    big[i] = (seed >>> 24) & 0xff;
  }

  const singlePass = crc32(big);
  assert.ok(singlePass >= 0 && singlePass <= 0xffffffff);

  const primes = [1, 7, 13, 1021, 65521];
  let state = CRC32_INIT;
  let pos = 0;
  let pIdx = 0;
  while (pos < big.length) {
    const step = primes[pIdx % primes.length];
    pIdx++;
    const end = Math.min(big.length, pos + step);
    state = crc32Update(state, big.subarray(pos, end));
    pos = end;
  }
  assert.equal(crc32Finalize(state), singlePass);
});

test("Mach-O ldid boundary conditions: exact 0x10 threshold, negative gap, zeroed symtab, missing commands", () => {
  // gap = 0 -> healthy
  let res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1100 }),
    0
  );
  assert.equal(res.sliceInfo.gap, 0);
  assert.equal(res.patch, null);

  // gap = 15 (0x0f) -> healthy
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x110f }),
    0
  );
  assert.equal(res.sliceInfo.gap, 15);
  assert.equal(res.patch, null);

  // gap = 16 (0x10) -> healthy (end >= size - 0x10)
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1110 }),
    0
  );
  assert.equal(res.sliceInfo.gap, 16);
  assert.equal(res.patch, null);

  // gap = 17 (0x11) -> MUST PATCH
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1111 }),
    0
  );
  assert.equal(res.sliceInfo.gap, 17);
  assert.ok(res.patch !== null);
  assert.equal(res.patch.oldStrsize, 0x100);
  assert.equal(res.patch.newStrsize, 0x111);
  assert.equal(res.patch.newEnd, 0x1111);

  // Large gap (1,283,648 bytes) -> MUST PATCH
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x99af930, strsize: 0x250160, sigDataoff: 0x9d390d0 }),
    0
  );
  assert.ok(res.patch !== null);
  assert.equal(res.patch.gap, 1283648);
  assert.equal(res.patch.newStrsize, 0x3897a0);

  // Negative gap (end > size) -> no bogus patch
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0x1000, strsize: 0x500, sigDataoff: 0x1200 }),
    0
  );
  assert.equal(res.sliceInfo.gap, -0x300);
  assert.equal(res.patch, null);

  // stroff == 0 && strsize == 0 -> skipped (matches ldid.cpp)
  res = parseMachOSliceHeader(
    buildThinMachO({ stroff: 0, strsize: 0, sigDataoff: 0x5000 }),
    0
  );
  assert.equal(res.sliceInfo, null);
  assert.equal(res.patch, null);

  // Missing LC_SYMTAB or LC_CODE_SIGNATURE
  const noSymtab = buildThinMachO({ includeSymtab: false, sigDataoff: 0x5000 });
  assert.deepEqual(parseMachOSliceHeader(noSymtab, 0), { sliceInfo: null, patch: null });

  const noSig = buildThinMachO({ includeSignature: false });
  assert.deepEqual(parseMachOSliceHeader(noSig, 0), { sliceInfo: null, patch: null });
});

test("Mach-O variants: 32/64-bit, little/big endian, leading dummy cmds, and reversed LC ordering", async () => {
  const variants = [
    { is64: true, littleEndian: true, hdrSize: 32 },
    { is64: true, littleEndian: false, hdrSize: 32 },
    { is64: false, littleEndian: true, hdrSize: 28 },
    { is64: false, littleEndian: false, hdrSize: 28 },
  ];

  for (const v of variants) {
    const leadingDummyCmds = 3;
    // Place LC_CODE_SIGNATURE (16 bytes) BEFORE LC_SYMTAB
    const bin = buildThinMachO({
      is64: v.is64,
      littleEndian: v.littleEndian,
      stroff: 0x1000,
      strsize: 0x200,
      sigDataoff: 0x2000,
      sigBeforeSymtab: true,
      leadingDummyCmds,
    });
    const inspect = await inspectMachOStream(new Blob([bin]).stream(), bin.length);
    assert.equal(inspect.isMachO, true);
    assert.equal(inspect.patches.length, 1);

    const expectedOffset = v.hdrSize + leadingDummyCmds * 16 + 16 + 20;
    assert.equal(inspect.patches[0].littleEndian, v.littleEndian);
    assert.equal(inspect.patches[0].strsizeFileOffset, expectedOffset);
    assert.equal(inspect.patches[0].newStrsize, 0x1000);
  }
});

test("FAT Mach-O: 32-bit, 64-bit, little-endian FAT, and unsorted slice offsets", async () => {
  const sHealthy = buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1100 });
  const sBroken1 = buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1400 });
  const sBroken2 = buildThinMachO({ is64: false, stroff: 0x800, strsize: 0x80, sigDataoff: 0x1000 });

  // 1. Unsorted offsets in 32-bit FAT (slice 0 at 0x3000, slice 1 at 0x1000)
  const fatUnsorted = buildFatMachO({
    isFat64: false,
    littleEndian: false,
    slices: [
      { offset: 0x3000, cputype: 0x0100000c, bytes: sBroken1 },
      { offset: 0x1000, cputype: 0x01000007, bytes: sHealthy },
    ],
  });
  const r1 = await inspectMachOStream(new Blob([fatUnsorted]).stream(), fatUnsorted.length);
  assert.equal(r1.isMachO, true);
  assert.equal(r1.slices.length, 2);
  assert.equal(r1.patches.length, 1);
  assert.equal(r1.patches[0].sliceOffset, 0x3000);
  assert.equal(r1.patches[0].strsizeFileOffset, 0x3000 + 32 + 20);

  // 2. FAT 64-bit with both slices broken
  const fat64 = buildFatMachO({
    isFat64: true,
    littleEndian: false,
    slices: [
      { offset: 0x1000, bytes: sBroken1 },
      { offset: 0x2000, bytes: sBroken2 },
    ],
  });
  const r2 = await inspectMachOStream(new Blob([fat64]).stream(), fat64.length);
  assert.equal(r2.isMachO, true);
  assert.equal(r2.patches.length, 2);
  assert.equal(r2.patches[0].strsizeFileOffset, 0x1000 + 32 + 20);
  assert.equal(r2.patches[1].strsizeFileOffset, 0x2000 + 28 + 20);

  // 3. Little-endian FAT (0xbebafeca)
  const fatLe = buildFatMachO({
    isFat64: false,
    littleEndian: true,
    slices: [{ offset: 0x1000, bytes: sBroken1 }],
  });
  const r3 = await inspectMachOStream(new Blob([fatLe]).stream(), fatLe.length);
  assert.equal(r3.isMachO, true);
  assert.equal(r3.patches.length, 1);
});

test("Malformed and non-Mach-O streams fail safely without infinite loops or false positives", async () => {
  // Empty stream
  assert.deepEqual(await inspectMachOStream(new Blob([]).stream(), 0), {
    isMachO: false,
    slices: [],
    patches: [],
  });

  // 3-byte stream
  assert.deepEqual(
    await inspectMachOStream(new Blob([new Uint8Array([0xcf, 0xfa, 0xed])]).stream(), 3),
    { isMachO: false, slices: [], patches: [] }
  );

  // Truncated Thin Mach-O header
  assert.deepEqual(
    await inspectMachOStream(new Blob([new Uint8Array([0xcf, 0xfa, 0xed, 0xfe, 0, 0])]).stream(), 6),
    { isMachO: false, slices: [], patches: [] }
  );

  // cmdsize == 0 must not loop infinitely
  const zeroCmd = buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1500 });
  new DataView(zeroCmd.buffer).setUint32(36, 0, true); // set first cmdsize = 0
  const zeroRes = parseMachOSliceHeader(zeroCmd, 0);
  assert.equal(zeroRes.patch, null);

  // sizeofcmds > 16MB rejected safely
  const hugeCmds = buildThinMachO({ stroff: 0x1000, strsize: 0x100, sigDataoff: 0x1500 });
  new DataView(hugeCmds.buffer).setUint32(20, 32 * 1024 * 1024, true);
  const hugeRes = await inspectMachOStream(new Blob([hugeCmds]).stream(), hugeCmds.length);
  assert.equal(hugeRes.isMachO, false);

  // FAT with out-of-bounds slice offset
  const badFat = new Uint8Array(64);
  const bfv = new DataView(badFat.buffer);
  bfv.setUint32(0, 0xcafebabe, false);
  bfv.setUint32(4, 1, false);
  bfv.setUint32(16, 0x999999, false);
  bfv.setUint32(20, 0x100, false);
  assert.deepEqual(await inspectMachOStream(new Blob([badFat]).stream(), badFat.length), {
    isMachO: false,
    slices: [],
    patches: [],
  });

  // Java .class (0xCAFEBABE + major version 52)
  const javaClass = new Uint8Array(128);
  const jv = new DataView(javaClass.buffer);
  jv.setUint32(0, 0xcafebabe, false);
  jv.setUint16(4, 0, false);
  jv.setUint16(6, 52, false);
  assert.deepEqual(await inspectMachOStream(new Blob([javaClass]).stream(), javaClass.length), {
    isMachO: false,
    slices: [],
    patches: [],
  });

  // Random plain text
  const text = new TextEncoder().encode("Not a Mach-O binary at all!");
  assert.deepEqual(await inspectMachOStream(new Blob([text]).stream(), text.length), {
    isMachO: false,
    slices: [],
    patches: [],
  });
});

test("createPatchAndCrcTransform: 1-byte chunks with empty chunks & multi-patch LE+BE stream", async () => {
  const src = new Uint8Array(64);
  for (let i = 0; i < src.length; i++) src[i] = (i * 7) & 0xff;

  const patches = [
    {
      sliceOffset: 0,
      cputype: 0x0100000c,
      littleEndian: true,
      oldStrsize: 0,
      newStrsize: 0x12345678,
      oldEnd: 0,
      newEnd: 0,
      gap: 100,
      strsizeFileOffset: 5,
    },
    {
      sliceOffset: 32,
      cputype: 12,
      littleEndian: false,
      oldStrsize: 0,
      newStrsize: 0xdeadbeef,
      oldEnd: 0,
      newEnd: 0,
      gap: 100,
      strsizeFileOffset: 47,
    },
  ];

  const { transform, getResult } = createPatchAndCrcTransform(patches);
  const stream = new ReadableStream({
    start(controller) {
      for (let i = 0; i < src.length; i++) {
        if (i % 5 === 0) controller.enqueue(new Uint8Array(0)); // empty chunk
        controller.enqueue(src.subarray(i, i + 1)); // 1-byte chunk
      }
      controller.close();
    },
  });

  const out = await readStreamAll(stream.pipeThrough(transform));
  const { crc32: gotCrc, uncompressedSize } = getResult();

  const expected = new Uint8Array(src);
  const ev = new DataView(expected.buffer);
  ev.setUint32(5, 0x12345678, true);
  ev.setUint32(47, 0xdeadbeef, false);

  assert.equal(uncompressedSize, 64);
  assert.deepEqual(out, expected);
  assert.equal(gotCrc, crc32(expected));
});
