import { CRC32_INIT, crc32Finalize, crc32Update } from "./crc32.js";
import type { MachOPatch, MachOSliceInfo } from "./types.js";

// Mach-O magic constants (big-endian u32 read of first 4 bytes on disk)
export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;
export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const LC_SYMTAB = 0x2;
export const LC_CODE_SIGNATURE = 0x1d;

function isThinMachOMagic(magic: number): boolean {
  return (
    magic === MH_MAGIC ||
    magic === MH_CIGAM ||
    magic === MH_MAGIC_64 ||
    magic === MH_CIGAM_64
  );
}

function getHeaderInfo(magic: number): { is64: boolean; littleEndian: boolean; hdrSize: number } | null {
  if (magic === MH_MAGIC || magic === MH_CIGAM) {
    return { is64: false, littleEndian: magic === MH_CIGAM, hdrSize: 28 };
  }
  if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) {
    return { is64: true, littleEndian: magic === MH_CIGAM_64, hdrSize: 32 };
  }
  return null;
}

/**
 * Parses a single Thin Mach-O slice header + load commands buffer (starting at slice byte 0).
 * Checks the ldid constraint: end >= size - 0x10 where size = LC_CODE_SIGNATURE.dataoff
 * and end = LC_SYMTAB.stroff + LC_SYMTAB.strsize.
 */
export function parseMachOSliceHeader(
  headerAndCmds: Uint8Array,
  sliceOffset: number
): { sliceInfo: MachOSliceInfo | null; patch: MachOPatch | null } {
  if (headerAndCmds.length < 28) {
    return { sliceInfo: null, patch: null };
  }

  const view = new DataView(
    headerAndCmds.buffer,
    headerAndCmds.byteOffset,
    headerAndCmds.byteLength
  );
  const magic = view.getUint32(0, false);
  const info = getHeaderInfo(magic);
  if (info === null || headerAndCmds.length < info.hdrSize) {
    return { sliceInfo: null, patch: null };
  }

  const { littleEndian, hdrSize } = info;
  const cputype = view.getUint32(4, littleEndian);
  const ncmds = view.getUint32(16, littleEndian);
  const sizeofcmds = view.getUint32(20, littleEndian);
  const cmdEnd = Math.min(headerAndCmds.length, hdrSize + sizeofcmds);

  let pos = hdrSize;
  let symtabCmdOffset: number | null = null;
  let symtabStroff: number | null = null;
  let symtabStrsize: number | null = null;
  let sigDataoff: number | null = null;

  for (let i = 0; i < ncmds; i++) {
    if (pos + 8 > cmdEnd) {
      break;
    }
    const cmd = view.getUint32(pos, littleEndian);
    const cmdsize = view.getUint32(pos + 4, littleEndian);
    if (cmdsize < 8 || pos + cmdsize > cmdEnd) {
      break;
    }

    if (cmd === LC_SYMTAB && cmdsize >= 24) {
      symtabCmdOffset = pos;
      symtabStroff = view.getUint32(pos + 16, littleEndian);
      symtabStrsize = view.getUint32(pos + 20, littleEndian);
    } else if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
      sigDataoff = view.getUint32(pos + 8, littleEndian);
    }

    pos += cmdsize;
  }

  if (
    symtabCmdOffset === null ||
    symtabStroff === null ||
    symtabStrsize === null ||
    sigDataoff === null
  ) {
    return { sliceInfo: null, patch: null };
  }

  // Matches ldid.cpp: if stroff == 0 && strsize == 0, ldid skips the check.
  if (symtabStroff === 0 && symtabStrsize === 0) {
    return { sliceInfo: null, patch: null };
  }

  const size = sigDataoff;
  const end = symtabStroff + symtabStrsize;
  const gap = size - end;

  const sliceInfo: MachOSliceInfo = {
    sliceOffset,
    cputype,
    littleEndian,
    stroff: symtabStroff,
    strsize: symtabStrsize,
    sigDataoff,
    end,
    gap,
  };

  if (end < size - 0x10) {
    const newStrsize = size - symtabStroff;
    const strsizeFileOffset = sliceOffset + symtabCmdOffset + 20;
    const patch: MachOPatch = {
      sliceOffset,
      cputype,
      littleEndian,
      oldStrsize: symtabStrsize,
      newStrsize,
      oldEnd: end,
      newEnd: size,
      gap,
      strsizeFileOffset,
    };
    return { sliceInfo, patch };
  }

  return { sliceInfo, patch: null };
}

class StreamCursor {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private head: Uint8Array | null = null;
  private headOffset = 0;
  private position = 0;
  private ended = false;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  get bytesRead(): number {
    return this.position;
  }

  private async ensureHead(): Promise<boolean> {
    while (this.head === null || this.headOffset >= this.head.length) {
      if (this.ended) {
        return false;
      }
      const { value, done } = await this.reader.read();
      if (done || value === undefined) {
        this.ended = true;
        this.head = null;
        this.headOffset = 0;
        return false;
      }
      if (value.length > 0) {
        this.head = value;
        this.headOffset = 0;
        return true;
      }
    }
    return true;
  }

  async readExact(n: number): Promise<Uint8Array<ArrayBuffer> | null> {
    if (n === 0) {
      return new Uint8Array(0);
    }
    const out = new Uint8Array(n);
    let written = 0;
    while (written < n) {
      const ok = await this.ensureHead();
      if (!ok || this.head === null) {
        return null;
      }
      const avail = this.head.length - this.headOffset;
      const take = Math.min(avail, n - written);
      out.set(this.head.subarray(this.headOffset, this.headOffset + take), written);
      this.headOffset += take;
      this.position += take;
      written += take;
    }
    return out;
  }

  async skipTo(targetPos: number): Promise<boolean> {
    if (targetPos < this.position) {
      return false;
    }
    while (this.position < targetPos) {
      const ok = await this.ensureHead();
      if (!ok || this.head === null) {
        return false;
      }
      const avail = this.head.length - this.headOffset;
      const needed = targetPos - this.position;
      const skip = Math.min(avail, needed);
      this.headOffset += skip;
      this.position += skip;
    }
    return true;
  }

  async close(): Promise<void> {
    try {
      await this.reader.cancel();
    } catch {
      // Ignore cancel errors on already closed/errored streams
    } finally {
      try {
        this.reader.releaseLock();
      } catch {
        // Ignore if already released
      }
    }
  }
}

async function inspectThinSliceFromCursor(
  cursor: StreamCursor,
  magicBytes: Uint8Array,
  sliceOffset: number
): Promise<{ valid: boolean; sliceInfo: MachOSliceInfo | null; patch: MachOPatch | null }> {
  const magicView = new DataView(
    magicBytes.buffer,
    magicBytes.byteOffset,
    magicBytes.byteLength
  );
  const magic = magicView.getUint32(0, false);
  const hdrInfo = getHeaderInfo(magic);
  if (hdrInfo === null) {
    return { valid: false, sliceInfo: null, patch: null };
  }

  const restHdr = await cursor.readExact(hdrInfo.hdrSize - 4);
  if (restHdr === null) {
    return { valid: false, sliceInfo: null, patch: null };
  }

  const hdrBuf = new Uint8Array(hdrInfo.hdrSize);
  hdrBuf.set(magicBytes, 0);
  hdrBuf.set(restHdr, 4);

  const hdrView = new DataView(hdrBuf.buffer, hdrBuf.byteOffset, hdrBuf.byteLength);
  const sizeofcmds = hdrView.getUint32(20, hdrInfo.littleEndian);
  if (sizeofcmds > 16 * 1024 * 1024) {
    return { valid: false, sliceInfo: null, patch: null };
  }

  const cmdsBuf = await cursor.readExact(sizeofcmds);
  if (cmdsBuf === null) {
    return { valid: false, sliceInfo: null, patch: null };
  }

  const fullHdrAndCmds = new Uint8Array(hdrInfo.hdrSize + sizeofcmds);
  fullHdrAndCmds.set(hdrBuf, 0);
  fullHdrAndCmds.set(cmdsBuf, hdrInfo.hdrSize);

  const parsed = parseMachOSliceHeader(fullHdrAndCmds, sliceOffset);
  return { valid: true, ...parsed };
}

/**
 * Inspects a decompressed binary stream for Thin or FAT Mach-O headers and any ldid assertion defects.
 * Cancels the stream immediately after reading headers to avoid inflating entire multi-hundred-MB binaries.
 */
export async function inspectMachOStream(
  stream: ReadableStream<Uint8Array>,
  fileSize: number
): Promise<{ isMachO: boolean; slices: MachOSliceInfo[]; patches: MachOPatch[] }> {
  const cursor = new StreamCursor(stream);
  try {
    const magicBytes = await cursor.readExact(4);
    if (magicBytes === null) {
      return { isMachO: false, slices: [], patches: [] };
    }

    const magicView = new DataView(
      magicBytes.buffer,
      magicBytes.byteOffset,
      magicBytes.byteLength
    );
    const magic = magicView.getUint32(0, false);

    if (isThinMachOMagic(magic)) {
      const res = await inspectThinSliceFromCursor(cursor, magicBytes, 0);
      if (!res.valid) {
        return { isMachO: false, slices: [], patches: [] };
      }
      return {
        isMachO: true,
        slices: res.sliceInfo ? [res.sliceInfo] : [],
        patches: res.patch ? [res.patch] : [],
      };
    }

    if (
      magic === FAT_MAGIC ||
      magic === FAT_CIGAM ||
      magic === FAT_MAGIC_64 ||
      magic === FAT_CIGAM_64
    ) {
      const isFat64 = magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64;
      const fatLittleEndian = magic === FAT_CIGAM || magic === FAT_CIGAM_64;

      const countBytes = await cursor.readExact(4);
      if (countBytes === null) {
        return { isMachO: false, slices: [], patches: [] };
      }
      const nfatArch = new DataView(
        countBytes.buffer,
        countBytes.byteOffset,
        countBytes.byteLength
      ).getUint32(0, fatLittleEndian);

      // Reject Java .class files (0xCAFEBABE + major version >= 45 in nfat_arch) and bogus counts
      if (nfatArch < 1 || nfatArch > 20) {
        return { isMachO: false, slices: [], patches: [] };
      }

      const archSize = isFat64 ? 32 : 20;
      const tableEnd = 8 + nfatArch * archSize;
      const archTable = await cursor.readExact(nfatArch * archSize);
      if (archTable === null) {
        return { isMachO: false, slices: [], patches: [] };
      }

      const tableView = new DataView(
        archTable.buffer,
        archTable.byteOffset,
        archTable.byteLength
      );

      const offsets: number[] = [];
      for (let i = 0; i < nfatArch; i++) {
        const entryOff = i * archSize;
        let offset: number;
        let size: number;
        if (isFat64) {
          const offsetBig = tableView.getBigUint64(entryOff + 8, fatLittleEndian);
          const sizeBig = tableView.getBigUint64(entryOff + 16, fatLittleEndian);
          if (offsetBig > BigInt(Number.MAX_SAFE_INTEGER) || sizeBig > BigInt(Number.MAX_SAFE_INTEGER)) {
            return { isMachO: false, slices: [], patches: [] };
          }
          offset = Number(offsetBig);
          size = Number(sizeBig);
        } else {
          offset = tableView.getUint32(entryOff + 8, fatLittleEndian);
          size = tableView.getUint32(entryOff + 12, fatLittleEndian);
        }

        if (offset < tableEnd || offset + 28 > fileSize || offset + size > fileSize) {
          return { isMachO: false, slices: [], patches: [] };
        }
        offsets.push(offset);
      }

      offsets.sort((a, b) => a - b);

      const slices: MachOSliceInfo[] = [];
      const patches: MachOPatch[] = [];
      let validMachOCount = 0;

      for (const sliceOffset of offsets) {
        const skipped = await cursor.skipTo(sliceOffset);
        if (!skipped) {
          break;
        }
        const sliceMagic = await cursor.readExact(4);
        if (sliceMagic === null) {
          break;
        }
        const res = await inspectThinSliceFromCursor(cursor, sliceMagic, sliceOffset);
        if (res.valid) {
          validMachOCount++;
          if (res.sliceInfo) {
            slices.push(res.sliceInfo);
          }
          if (res.patch) {
            patches.push(res.patch);
          }
        }
      }

      return {
        isMachO: validMachOCount > 0,
        slices,
        patches,
      };
    }

    return { isMachO: false, slices: [], patches: [] };
  } finally {
    await cursor.close();
  }
}

interface EncodedPatch {
  offset: number;
  bytes: Uint8Array;
}

/**
 * Creates a streaming TransformStream that applies 4-byte Mach-O patches at their exact byte offsets
 * (handling arbitrary stream chunk splits) and computes the patched stream's CRC-32 and uncompressed size.
 */
export function createPatchAndCrcTransform(patches: readonly MachOPatch[]): {
  transform: TransformStream<Uint8Array, Uint8Array<ArrayBuffer>>;
  getResult: () => { crc32: number; uncompressedSize: number };
} {
  const encoded: EncodedPatch[] = patches.map((p) => {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, p.newStrsize, p.littleEndian);
    return { offset: p.strsizeFileOffset, bytes: buf };
  });

  let streamOffset = 0;
  let crc = CRC32_INIT;

  const transform = new TransformStream<Uint8Array, Uint8Array<ArrayBuffer>>({
    transform(chunk, controller) {
      const chunkStart = streamOffset;
      const chunkEnd = chunkStart + chunk.length;
      streamOffset = chunkEnd;

      let outChunk: Uint8Array<ArrayBuffer> | null = null;

      for (const ep of encoded) {
        const patchStart = ep.offset;
        const patchEnd = ep.offset + 4;
        if (chunkStart < patchEnd && chunkEnd > patchStart) {
          if (outChunk === null) {
            outChunk = new Uint8Array(chunk.length);
            outChunk.set(chunk);
          }
          const copyStart = Math.max(chunkStart, patchStart);
          const copyEnd = Math.min(chunkEnd, patchEnd);
          for (let pos = copyStart; pos < copyEnd; pos++) {
            outChunk[pos - chunkStart] = ep.bytes[pos - patchStart]!;
          }
        }
      }

      const finalChunk: Uint8Array<ArrayBuffer> =
        outChunk !== null
          ? outChunk
          : (() => {
              const copy = new Uint8Array(chunk.length);
              copy.set(chunk);
              return copy;
            })();

      crc = crc32Update(crc, finalChunk);
      controller.enqueue(finalChunk);
    },
  });

  return {
    transform,
    getResult: () => ({
      crc32: crc32Finalize(crc),
      uncompressedSize: streamOffset,
    }),
  };
}
