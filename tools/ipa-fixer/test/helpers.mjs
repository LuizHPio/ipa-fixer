import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { crc32 } from "../dist/index.js";

export async function readStreamAll(stream) {
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

export function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export async function deflateRaw(bytes) {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return readStreamAll(cs.readable);
}

export function assertValidZipWithPython(zipPath) {
  const res = execFileSync(
    "python3",
    [
      "-c",
      "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); bad = z.testzip(); assert bad is None, f'Bad CRC: {bad}'; print('ZIP_OK')",
      zipPath,
    ],
    { encoding: "utf8" }
  ).trim();
  assert.equal(res, "ZIP_OK");
}

/**
 * Builds a Thin 32-bit or 64-bit Mach-O header + load commands buffer,
 * optionally including leading dummy commands and arbitrary ordering of LC_SYMTAB / LC_CODE_SIGNATURE.
 */
export function buildThinMachO({
  is64 = true,
  littleEndian = true,
  cputype = is64 ? 0x0100000c : 12,
  stroff = 0x1000,
  strsize = 0x100,
  sigDataoff = 0x1100,
  sigDatasize = 0x200,
  includeSymtab = true,
  includeSignature = true,
  sigBeforeSymtab = false,
  leadingDummyCmds = 0,
  totalSize = 0,
} = {}) {
  const hdrSize = is64 ? 32 : 28;
  const dummyCmdSize = 16;
  const symtabSize = 24;
  const sigCmdSize = 16;

  let ncmds = leadingDummyCmds;
  let sizeofcmds = leadingDummyCmds * dummyCmdSize;
  if (includeSymtab) {
    ncmds += 1;
    sizeofcmds += symtabSize;
  }
  if (includeSignature) {
    ncmds += 1;
    sizeofcmds += sigCmdSize;
  }

  const bufLen = Math.max(totalSize, hdrSize + sizeofcmds);
  const buf = new Uint8Array(bufLen);
  const view = new DataView(buf.buffer);

  // On-disk magic bytes (read big-endian by parser)
  let diskMagic;
  if (is64) {
    diskMagic = littleEndian ? 0xcffaedfe : 0xfeedfacf;
  } else {
    diskMagic = littleEndian ? 0xcefaedfe : 0xfeedface;
  }

  view.setUint32(0, diskMagic, false);
  view.setUint32(4, cputype >>> 0, littleEndian);
  view.setUint32(8, 0, littleEndian);
  view.setUint32(12, 2, littleEndian); // MH_EXECUTE
  view.setUint32(16, ncmds, littleEndian);
  view.setUint32(20, sizeofcmds, littleEndian);

  let pos = hdrSize;
  for (let i = 0; i < leadingDummyCmds; i++) {
    view.setUint32(pos, 0x1b, littleEndian); // LC_UUID
    view.setUint32(pos + 4, dummyCmdSize, littleEndian);
    pos += dummyCmdSize;
  }

  const writeSymtab = () => {
    view.setUint32(pos, 0x2, littleEndian); // LC_SYMTAB
    view.setUint32(pos + 4, symtabSize, littleEndian);
    view.setUint32(pos + 8, Math.max(0, stroff - 0x100), littleEndian);
    view.setUint32(pos + 12, 10, littleEndian);
    view.setUint32(pos + 16, stroff >>> 0, littleEndian);
    view.setUint32(pos + 20, strsize >>> 0, littleEndian);
    pos += symtabSize;
  };

  const writeSignature = () => {
    view.setUint32(pos, 0x1d, littleEndian); // LC_CODE_SIGNATURE
    view.setUint32(pos + 4, sigCmdSize, littleEndian);
    view.setUint32(pos + 8, sigDataoff >>> 0, littleEndian);
    view.setUint32(pos + 12, sigDatasize >>> 0, littleEndian);
    pos += sigCmdSize;
  };

  if (sigBeforeSymtab) {
    if (includeSignature) writeSignature();
    if (includeSymtab) writeSymtab();
  } else {
    if (includeSymtab) writeSymtab();
    if (includeSignature) writeSignature();
  }

  return buf;
}

/**
 * Builds a 32-bit or 64-bit FAT Mach-O binary containing the given slices:
 * slices: Array<{ offset: number, cputype?: number, bytes: Uint8Array }>
 */
export function buildFatMachO({ isFat64 = false, littleEndian = false, slices = [] } = {}) {
  const archSize = isFat64 ? 32 : 20;
  let maxEnd = 8 + slices.length * archSize;
  for (const s of slices) {
    maxEnd = Math.max(maxEnd, s.offset + s.bytes.length);
  }

  const buf = new Uint8Array(maxEnd);
  const view = new DataView(buf.buffer);

  let magic;
  if (isFat64) {
    magic = littleEndian ? 0xbfbafeca : 0xcafebabf;
  } else {
    magic = littleEndian ? 0xbebafeca : 0xcafebabe;
  }
  view.setUint32(0, magic, false);
  view.setUint32(4, slices.length, littleEndian);

  for (let i = 0; i < slices.length; i++) {
    const s = slices[i];
    const ep = 8 + i * archSize;
    view.setUint32(ep, (s.cputype ?? 0x0100000c) >>> 0, littleEndian);
    view.setUint32(ep + 4, 0, littleEndian);
    if (isFat64) {
      view.setBigUint64(ep + 8, BigInt(s.offset), littleEndian);
      view.setBigUint64(ep + 16, BigInt(s.bytes.length), littleEndian);
      view.setUint32(ep + 24, 14, littleEndian);
      view.setUint32(ep + 28, 0, littleEndian);
    } else {
      view.setUint32(ep + 8, s.offset >>> 0, littleEndian);
      view.setUint32(ep + 12, s.bytes.length >>> 0, littleEndian);
      view.setUint32(ep + 16, 14, littleEndian);
    }
    buf.set(s.bytes, s.offset);
  }

  return buf;
}

/**
 * Builds a ZIP archive with fine-grained control over compression method, flags, LFH vs CD extras,
 * UTF-8 flags, external attributes, and EOCD comment.
 */
export async function buildZipArchive(items, { comment = "" } = {}) {
  const encoder = new TextEncoder();
  const localParts = [];
  const cdParts = [];
  let offset = 0;

  for (const item of items) {
    const nameBytes = encoder.encode(item.name);
    const rawPayload = item.bytes ?? new Uint8Array(0);
    const method = item.compressionMethod ?? (item.compress ? 8 : 0);
    const compressed =
      item.rawCompressedBytes !== undefined
        ? item.rawCompressedBytes
        : method === 8
          ? await deflateRaw(rawPayload)
          : rawPayload;
    const crc = item.crc32 ?? crc32(rawPayload);
    let flags = item.flags ?? 0;
    if (item.dataDescriptor) flags |= 0x0008;
    if (item.utf8 !== false && /[^\x00-\x7f]/.test(item.name)) flags |= 0x0800;

    const lfhExtra = item.lfhExtra ?? new Uint8Array(0);
    const cdExtra = item.cdExtra ?? new Uint8Array(0);
    const externalAttr =
      item.externalAttr ?? (item.name.endsWith("/") ? 0x41ed0000 : 0x81a40000);

    const lfh = new Uint8Array(30 + nameBytes.length + lfhExtra.length);
    const lfhView = new DataView(lfh.buffer);
    lfhView.setUint32(0, 0x04034b50, true);
    lfhView.setUint16(4, 20, true);
    lfhView.setUint16(6, flags, true);
    lfhView.setUint16(8, method, true);
    lfhView.setUint32(14, item.dataDescriptor ? 0 : crc, true);
    lfhView.setUint32(18, item.dataDescriptor ? 0 : compressed.length, true);
    lfhView.setUint32(22, item.dataDescriptor ? 0 : rawPayload.length, true);
    lfhView.setUint16(26, nameBytes.length, true);
    lfhView.setUint16(28, lfhExtra.length, true);
    lfh.set(nameBytes, 30);
    lfh.set(lfhExtra, 30 + nameBytes.length);

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

    const cd = new Uint8Array(46 + nameBytes.length + cdExtra.length);
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
    cdView.setUint16(30, cdExtra.length, true);
    cdView.setUint32(38, externalAttr >>> 0, true);
    cdView.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    cd.set(cdExtra, 46 + nameBytes.length);
    cdParts.push(cd);

    offset += lfh.length + compressed.length + ddLen;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const cd of cdParts) cdSize += cd.length;

  const commentBytes = encoder.encode(comment);
  const eocd = new Uint8Array(22 + commentBytes.length);
  const eocdView = new DataView(eocd.buffer);
  eocdView.setUint32(0, 0x06054b50, true);
  eocdView.setUint16(8, items.length, true);
  eocdView.setUint16(10, items.length, true);
  eocdView.setUint32(12, cdSize, true);
  eocdView.setUint32(16, cdOffset, true);
  eocdView.setUint16(20, commentBytes.length, true);
  eocd.set(commentBytes, 22);

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

export async function buildSyntheticIpaBytes() {
  const brokenMain = buildThinMachO({
    is64: true,
    littleEndian: true,
    stroff: 0x1000,
    strsize: 0x100,
    sigDataoff: 0x1500,
    leadingDummyCmds: 2,
    totalSize: 0x1800,
  });
  const brokenExtKit = buildThinMachO({
    is64: true,
    littleEndian: true,
    stroff: 0x800,
    strsize: 0x80,
    sigDataoff: 0x1000,
  });
  const brokenPlugIn = buildThinMachO({
    is64: true,
    littleEndian: true,
    stroff: 0x900,
    strsize: 0x90,
    sigDataoff: 0x1200,
  });
  const healthyDylib = buildThinMachO({
    is64: true,
    littleEndian: true,
    stroff: 0x500,
    strsize: 0x100,
    sigDataoff: 0x608,
  });

  // Disguised Mach-O inside a .png extension (ignored unless scanAllFiles: true)
  const disguisedMacho = buildThinMachO({
    is64: true,
    littleEndian: true,
    stroff: 0x400,
    strsize: 0x100,
    sigDataoff: 0x900,
  });

  // Symlink whose target string happens to start with Mach-O magic bytes (must not be patched)
  const fakeSymlinkTarget = new Uint8Array(40);
  fakeSymlinkTarget.set(brokenMain.subarray(0, 40));

  const encoder = new TextEncoder();
  const assetData = encoder.encode('{"CFBundleIdentifier":"com.example.Demo"}');
  const appexptData = encoder.encode("extensionkit-metadata");
  const sigData = encoder.encode("dummy-code-resources");

  // Valid TLV ZIP extra fields with different LFH vs CD extra lengths (tag 0xfeed)
  const lfhExtra = new Uint8Array(28);
  new DataView(lfhExtra.buffer).setUint16(0, 0xfeed, true);
  new DataView(lfhExtra.buffer).setUint16(2, 24, true);
  lfhExtra.fill(0xaa, 4);

  const cdExtra = new Uint8Array(8);
  new DataView(cdExtra.buffer).setUint16(0, 0xfeed, true);
  new DataView(cdExtra.buffer).setUint16(2, 4, true);
  cdExtra.fill(0xbb, 4);

  return buildZipArchive(
    [
      { name: "Payload/", bytes: null },
      { name: "Payload/Demo.app/", bytes: null },
      {
        name: "Payload/Demo.app/Demo",
        bytes: brokenMain,
        compress: true,
        dataDescriptor: true,
        lfhExtra,
        cdExtra,
        externalAttr: 0x81ed0000,
      },
      {
        name: "Payload/Demo.app/Frameworks/Healthy.dylib",
        bytes: healthyDylib,
        compress: true,
        externalAttr: 0x81ed0000,
      },
      {
        name: "Payload/Demo.app/Info.plist",
        bytes: assetData,
        compress: true,
        dataDescriptor: true,
      },
      {
        name: "Payload/Demo.app/Assets/café-🚀.txt",
        bytes: encoder.encode("utf8-asset"),
        compress: true,
      },
      {
        name: "Payload/Demo.app/disguised.png",
        bytes: disguisedMacho,
        compress: true,
      },
      {
        name: "Payload/Demo.app/MachoLink",
        bytes: fakeSymlinkTarget,
        compress: false,
        externalAttr: 0xa1ff0000, // S_IFLNK (0o120777)
      },
      {
        name: "Payload/Demo.app/_CodeSignature/CodeResources",
        bytes: sigData,
        compress: true,
      },
      {
        name: "Payload/Demo.app/Frameworks/Healthy.framework/_CodeSignature/CodeResources",
        bytes: sigData,
        compress: false,
      },
      {
        name: "Payload/Demo.app/Extensions/DemoMigration.appex/DemoMigration",
        bytes: brokenExtKit,
        compress: true,
        externalAttr: 0x81ed0000,
      },
      {
        name: "Payload/Demo.app/Extensions/DemoMigration.appex/_CodeSignature/CodeResources",
        bytes: sigData,
        compress: false,
      },
      {
        name: "Payload/Demo.app/Extensions/com.example.Demo.appexpt",
        bytes: appexptData,
        compress: false,
      },
      {
        name: "Payload/Demo.app/PlugIns/DemoShare.appex/DemoShare",
        bytes: brokenPlugIn,
        compress: true,
        externalAttr: 0x81ed0000,
      },
      {
        name: "Payload/Demo.app/PlugIns/DemoShare.appex/_CodeSignature/CodeResources",
        bytes: sigData,
        compress: false,
      },
    ],
    { comment: "synthetic-ipa-test-comment" }
  );
}
