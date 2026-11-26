import type { RandomAccessSource, ZipOutputSink } from "./types.js";

const SIG_LFH = 0x04034b50;
const SIG_CD = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

const FLAG_DATA_DESCRIPTOR = 0x0008;
const FLAG_UTF8 = 0x0800;

const ZIP64_MAGIC_32 = 0xffffffff;
const ZIP64_MAGIC_16 = 0xffff;

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });

export interface ZipEntry {
  fileName: string;
  fileNameBytes: Uint8Array<ArrayBuffer>;
  versionMadeBy: number;
  versionNeeded: number;
  flags: number;
  compressionMethod: number;
  modTime: number;
  modDate: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  internalAttr: number;
  externalAttr: number;
  localHeaderOffset: number;
  isDirectory: boolean;
  isSymlink: boolean;
}

interface WrittenCdRecord {
  entry: ZipEntry;
  flags: number;
  compressionMethod: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

function toSafeNumber(val: bigint, label: string): number {
  if (val > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`ZIP ${label} exceeds MAX_SAFE_INTEGER`);
  }
  return Number(val);
}

/**
 * Reads and parses the ZIP Central Directory from the end of a RandomAccessSource.
 * Supports standard ZIP and ZIP64 records.
 */
export async function readZipCentralDirectory(source: RandomAccessSource): Promise<ZipEntry[]> {
  if (source.size < 22) {
    throw new Error("File is too small to be a valid ZIP/IPA archive.");
  }

  const tailLen = Math.min(source.size, 65557);
  const tailStart = source.size - tailLen;
  const tail = await source.readRange(tailStart, source.size);
  const tailView = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);

  let eocdPos = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tailView.getUint32(i, true) === SIG_EOCD) {
      const commentLen = tailView.getUint16(i + 20, true);
      if (i + 22 + commentLen === tail.length) {
        eocdPos = i;
        break;
      }
    }
  }

  if (eocdPos < 0) {
    throw new Error("Could not find ZIP End of Central Directory (EOCD) record.");
  }

  let totalEntries = tailView.getUint16(eocdPos + 10, true);
  let cdSize = tailView.getUint32(eocdPos + 12, true);
  let cdOffset = tailView.getUint32(eocdPos + 16, true);

  if (
    totalEntries === ZIP64_MAGIC_16 ||
    cdSize === ZIP64_MAGIC_32 ||
    cdOffset === ZIP64_MAGIC_32
  ) {
    const locPos = eocdPos - 20;
    if (locPos < 0 || tailView.getUint32(locPos, true) !== SIG_ZIP64_LOCATOR) {
      throw new Error("ZIP64 indicator set without valid ZIP64 EOCD Locator.");
    }
    const zip64EocdOffset = toSafeNumber(
      tailView.getBigUint64(locPos + 8, true),
      "ZIP64 EOCD offset"
    );
    const z64 = await source.readRange(zip64EocdOffset, zip64EocdOffset + 56);
    if (z64.length < 56) {
      throw new Error("Truncated ZIP64 EOCD record.");
    }
    const z64View = new DataView(z64.buffer, z64.byteOffset, z64.byteLength);
    if (z64View.getUint32(0, true) !== SIG_ZIP64_EOCD) {
      throw new Error("Invalid ZIP64 EOCD signature.");
    }
    totalEntries = toSafeNumber(z64View.getBigUint64(32, true), "totalEntries");
    cdSize = toSafeNumber(z64View.getBigUint64(40, true), "cdSize");
    cdOffset = toSafeNumber(z64View.getBigUint64(48, true), "cdOffset");
  }

  if (cdOffset < 0 || cdOffset + cdSize > source.size) {
    throw new Error("Central Directory bounds exceed archive size.");
  }

  const cdBuf = await source.readRange(cdOffset, cdOffset + cdSize);
  const cdView = new DataView(cdBuf.buffer, cdBuf.byteOffset, cdBuf.byteLength);

  const entries: ZipEntry[] = [];
  let pos = 0;

  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > cdBuf.length) {
      throw new Error("Truncated ZIP Central Directory entry.");
    }
    if (cdView.getUint32(pos, true) !== SIG_CD) {
      throw new Error(`Invalid Central Directory signature at offset ${cdOffset + pos}.`);
    }

    const versionMadeBy = cdView.getUint16(pos + 4, true);
    const versionNeeded = cdView.getUint16(pos + 6, true);
    const flags = cdView.getUint16(pos + 8, true);
    const compressionMethod = cdView.getUint16(pos + 10, true);
    const modTime = cdView.getUint16(pos + 12, true);
    const modDate = cdView.getUint16(pos + 14, true);
    const crc32 = cdView.getUint32(pos + 16, true);
    let compressedSize = cdView.getUint32(pos + 20, true);
    let uncompressedSize = cdView.getUint32(pos + 24, true);
    const nameLen = cdView.getUint16(pos + 28, true);
    const extraLen = cdView.getUint16(pos + 30, true);
    const commentLen = cdView.getUint16(pos + 32, true);
    const internalAttr = cdView.getUint16(pos + 36, true);
    const externalAttr = cdView.getUint32(pos + 38, true);
    let localHeaderOffset = cdView.getUint32(pos + 42, true);

    const recordEnd = pos + 46 + nameLen + extraLen + commentLen;
    if (recordEnd > cdBuf.length) {
      throw new Error("Truncated Central Directory variable-length fields.");
    }

    const fileNameBytes = new Uint8Array(nameLen);
    fileNameBytes.set(cdBuf.subarray(pos + 46, pos + 46 + nameLen));
    const fileName = UTF8_DECODER.decode(fileNameBytes);

    if (
      uncompressedSize === ZIP64_MAGIC_32 ||
      compressedSize === ZIP64_MAGIC_32 ||
      localHeaderOffset === ZIP64_MAGIC_32
    ) {
      const extraStart = pos + 46 + nameLen;
      const extraEnd = extraStart + extraLen;
      let ep = extraStart;
      while (ep + 4 <= extraEnd) {
        const tag = cdView.getUint16(ep, true);
        const size = cdView.getUint16(ep + 2, true);
        if (tag === 0x0001 && ep + 4 + size <= extraEnd) {
          let zp = ep + 4;
          if (uncompressedSize === ZIP64_MAGIC_32 && zp + 8 <= ep + 4 + size) {
            uncompressedSize = toSafeNumber(cdView.getBigUint64(zp, true), "uncompressedSize");
            zp += 8;
          }
          if (compressedSize === ZIP64_MAGIC_32 && zp + 8 <= ep + 4 + size) {
            compressedSize = toSafeNumber(cdView.getBigUint64(zp, true), "compressedSize");
            zp += 8;
          }
          if (localHeaderOffset === ZIP64_MAGIC_32 && zp + 8 <= ep + 4 + size) {
            localHeaderOffset = toSafeNumber(cdView.getBigUint64(zp, true), "localHeaderOffset");
          }
          break;
        }
        ep += 4 + size;
      }
    }

    const unixMode = (externalAttr >>> 16) & 0o170000;
    const isDirectory = fileName.endsWith("/");
    const isSymlink = unixMode === 0o120000;

    entries.push({
      fileName,
      fileNameBytes,
      versionMadeBy,
      versionNeeded,
      flags,
      compressionMethod,
      modTime,
      modDate,
      crc32,
      compressedSize,
      uncompressedSize,
      internalAttr,
      externalAttr,
      localHeaderOffset,
      isDirectory,
      isSymlink,
    });

    pos = recordEnd;
  }

  return entries;
}

/**
 * Resolves the exact compressed payload byte range [dataStart, dataEnd) from the entry's Local File Header.
 */
export async function getEntryDataRange(
  source: RandomAccessSource,
  entry: ZipEntry
): Promise<{ dataStart: number; dataEnd: number }> {
  const lfh = await source.readRange(entry.localHeaderOffset, entry.localHeaderOffset + 30);
  if (lfh.length < 30) {
    throw new Error(`Truncated Local File Header for ${entry.fileName}`);
  }
  const view = new DataView(lfh.buffer, lfh.byteOffset, lfh.byteLength);
  if (view.getUint32(0, true) !== SIG_LFH) {
    throw new Error(`Invalid Local File Header signature for ${entry.fileName}`);
  }

  const lfhNameLen = view.getUint16(26, true);
  const lfhExtraLen = view.getUint16(28, true);
  const dataStart = entry.localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > source.size) {
    throw new Error(`Entry payload exceeds archive bounds for ${entry.fileName}`);
  }
  return { dataStart, dataEnd };
}

/**
 * Opens a decompressed stream for a ZIP entry (supports STORE=0 and DEFLATE=8).
 */
export function openEntryDecompressedStream(
  source: RandomAccessSource,
  entry: ZipEntry,
  dataStart: number,
  dataEnd: number
): ReadableStream<Uint8Array<ArrayBuffer>> {
  const rawStream = source.streamRange(dataStart, dataEnd);
  if (entry.compressionMethod === 0) {
    return rawStream;
  }
  if (entry.compressionMethod === 8) {
    return rawStream.pipeThrough(new DecompressionStream("deflate-raw"));
  }
  throw new Error(
    `Unsupported ZIP compression method ${entry.compressionMethod} on ${entry.fileName}`
  );
}

/**
 * Sequential ZIP writer supporting raw pass-through entries and recompressed entries.
 */
export class ZipStreamWriter {
  private offset = 0;
  private readonly records: WrittenCdRecord[] = [];
  private readonly sink: ZipOutputSink;

  constructor(sink: ZipOutputSink) {
    this.sink = sink;
  }

  get bytesWritten(): number {
    return this.offset;
  }

  private async writeHeaderAndRecord(
    entry: ZipEntry,
    crc32Val: number,
    compressedSize: number,
    uncompressedSize: number,
    compressionMethod: number
  ): Promise<void> {
    const localHeaderOffset = this.offset;
    // Clear bit 3 (data descriptor) since exact CRC and sizes are always written in LFH,
    // and ensure UTF-8 bit 11 is preserved as-is.
    const cleanFlags = entry.flags & ~FLAG_DATA_DESCRIPTOR;
    const needsZip64Lfh =
      compressedSize >= ZIP64_MAGIC_32 || uncompressedSize >= ZIP64_MAGIC_32;
    const extraLen = needsZip64Lfh ? 20 : 0;
    const versionNeeded = needsZip64Lfh ? Math.max(entry.versionNeeded, 45) : entry.versionNeeded;

    const lfh = new Uint8Array(30 + entry.fileNameBytes.length + extraLen);
    const view = new DataView(lfh.buffer);

    view.setUint32(0, SIG_LFH, true);
    view.setUint16(4, versionNeeded, true);
    view.setUint16(6, cleanFlags, true);
    view.setUint16(8, compressionMethod, true);
    view.setUint16(10, entry.modTime, true);
    view.setUint16(12, entry.modDate, true);
    view.setUint32(14, crc32Val >>> 0, true);
    view.setUint32(18, needsZip64Lfh ? ZIP64_MAGIC_32 : compressedSize >>> 0, true);
    view.setUint32(22, needsZip64Lfh ? ZIP64_MAGIC_32 : uncompressedSize >>> 0, true);
    view.setUint16(26, entry.fileNameBytes.length, true);
    view.setUint16(28, extraLen, true);
    lfh.set(entry.fileNameBytes, 30);

    if (needsZip64Lfh) {
      const ep = 30 + entry.fileNameBytes.length;
      view.setUint16(ep, 0x0001, true);
      view.setUint16(ep + 2, 16, true);
      view.setBigUint64(ep + 4, BigInt(uncompressedSize), true);
      view.setBigUint64(ep + 12, BigInt(compressedSize), true);
    }

    await this.sink.writeBytes(lfh);
    this.offset += lfh.length;

    this.records.push({
      entry: { ...entry, versionNeeded: needsZip64Lfh ? versionNeeded : entry.versionNeeded },
      flags: cleanFlags | (entry.flags & FLAG_UTF8),
      compressionMethod,
      crc32: crc32Val >>> 0,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });
  }

  /**
   * Copies an untouched compressed (or stored) entry straight from source without recompression.
   */
  async writeRawEntry(
    source: RandomAccessSource,
    entry: ZipEntry,
    dataStart: number,
    dataEnd: number
  ): Promise<void> {
    await this.writeHeaderAndRecord(
      entry,
      entry.crc32,
      entry.compressedSize,
      entry.uncompressedSize,
      entry.compressionMethod
    );
    const payloadLen = dataEnd - dataStart;
    if (payloadLen > 0) {
      await this.sink.copySourceRange(source, dataStart, dataEnd);
      this.offset += payloadLen;
    }
  }

  /**
   * Writes a recompressed (or newly generated) entry from already-compressed byte chunks.
   */
  async writeCompressedChunksEntry(
    entry: ZipEntry,
    chunks: readonly Uint8Array<ArrayBuffer>[],
    crc32Val: number,
    compressedSize: number,
    uncompressedSize: number,
    compressionMethod: number
  ): Promise<void> {
    await this.writeHeaderAndRecord(
      entry,
      crc32Val,
      compressedSize,
      uncompressedSize,
      compressionMethod
    );
    for (const chunk of chunks) {
      if (chunk.length > 0) {
        await this.sink.writeBytes(chunk);
        this.offset += chunk.length;
      }
    }
  }

  /**
   * Writes the ZIP Central Directory and End of Central Directory records.
   */
  async finalize(): Promise<void> {
    const cdOffset = this.offset;
    const cdParts: Uint8Array<ArrayBuffer>[] = [];
    let cdSize = 0;

    for (const rec of this.records) {
      const { entry } = rec;
      const needUncomp64 = rec.uncompressedSize >= ZIP64_MAGIC_32;
      const needComp64 = rec.compressedSize >= ZIP64_MAGIC_32;
      const needOffset64 = rec.localHeaderOffset >= ZIP64_MAGIC_32;

      let zip64PayloadLen = 0;
      if (needUncomp64) zip64PayloadLen += 8;
      if (needComp64) zip64PayloadLen += 8;
      if (needOffset64) zip64PayloadLen += 8;
      const extraLen = zip64PayloadLen > 0 ? 4 + zip64PayloadLen : 0;

      const cd = new Uint8Array(46 + entry.fileNameBytes.length + extraLen);
      const view = new DataView(cd.buffer);
      const versionNeeded =
        zip64PayloadLen > 0 ? Math.max(entry.versionNeeded, 45) : entry.versionNeeded;

      view.setUint32(0, SIG_CD, true);
      view.setUint16(4, entry.versionMadeBy, true);
      view.setUint16(6, versionNeeded, true);
      view.setUint16(8, rec.flags, true);
      view.setUint16(10, rec.compressionMethod, true);
      view.setUint16(12, entry.modTime, true);
      view.setUint16(14, entry.modDate, true);
      view.setUint32(16, rec.crc32 >>> 0, true);
      view.setUint32(20, needComp64 ? ZIP64_MAGIC_32 : rec.compressedSize >>> 0, true);
      view.setUint32(24, needUncomp64 ? ZIP64_MAGIC_32 : rec.uncompressedSize >>> 0, true);
      view.setUint16(28, entry.fileNameBytes.length, true);
      view.setUint16(30, extraLen, true);
      view.setUint16(32, 0, true);
      view.setUint16(34, 0, true);
      view.setUint16(36, entry.internalAttr, true);
      view.setUint32(38, entry.externalAttr >>> 0, true);
      view.setUint32(42, needOffset64 ? ZIP64_MAGIC_32 : rec.localHeaderOffset >>> 0, true);

      cd.set(entry.fileNameBytes, 46);

      if (extraLen > 0) {
        let ep = 46 + entry.fileNameBytes.length;
        view.setUint16(ep, 0x0001, true);
        view.setUint16(ep + 2, zip64PayloadLen, true);
        ep += 4;
        if (needUncomp64) {
          view.setBigUint64(ep, BigInt(rec.uncompressedSize), true);
          ep += 8;
        }
        if (needComp64) {
          view.setBigUint64(ep, BigInt(rec.compressedSize), true);
          ep += 8;
        }
        if (needOffset64) {
          view.setBigUint64(ep, BigInt(rec.localHeaderOffset), true);
        }
      }

      cdParts.push(cd);
      cdSize += cd.length;
    }

    // Batch CD parts into reasonable ~512KB buffers for efficient I/O
    const BATCH_LIMIT = 512 * 1024;
    let batch: Uint8Array<ArrayBuffer>[] = [];
    let batchBytes = 0;

    const flushBatch = async (): Promise<void> => {
      if (batchBytes === 0) return;
      const merged = new Uint8Array(batchBytes);
      let cursor = 0;
      for (const part of batch) {
        merged.set(part, cursor);
        cursor += part.length;
      }
      await this.sink.writeBytes(merged);
      this.offset += merged.length;
      batch = [];
      batchBytes = 0;
    };

    for (const part of cdParts) {
      batch.push(part);
      batchBytes += part.length;
      if (batchBytes >= BATCH_LIMIT) {
        await flushBatch();
      }
    }
    await flushBatch();

    const totalEntries = this.records.length;
    const needsZip64Eocd =
      totalEntries >= ZIP64_MAGIC_16 ||
      cdSize >= ZIP64_MAGIC_32 ||
      cdOffset >= ZIP64_MAGIC_32;

    if (needsZip64Eocd) {
      const z64EocdOffset = this.offset;
      const z64 = new Uint8Array(56);
      const z64View = new DataView(z64.buffer);
      z64View.setUint32(0, SIG_ZIP64_EOCD, true);
      z64View.setBigUint64(4, 44n, true);
      z64View.setUint16(12, 45, true);
      z64View.setUint16(14, 45, true);
      z64View.setUint32(16, 0, true);
      z64View.setUint32(20, 0, true);
      z64View.setBigUint64(24, BigInt(totalEntries), true);
      z64View.setBigUint64(32, BigInt(totalEntries), true);
      z64View.setBigUint64(40, BigInt(cdSize), true);
      z64View.setBigUint64(48, BigInt(cdOffset), true);
      await this.sink.writeBytes(z64);
      this.offset += z64.length;

      const loc = new Uint8Array(20);
      const locView = new DataView(loc.buffer);
      locView.setUint32(0, SIG_ZIP64_LOCATOR, true);
      locView.setUint32(4, 0, true);
      locView.setBigUint64(8, BigInt(z64EocdOffset), true);
      locView.setUint32(16, 1, true);
      await this.sink.writeBytes(loc);
      this.offset += loc.length;
    }

    const eocd = new Uint8Array(22);
    const eocdView = new DataView(eocd.buffer);
    eocdView.setUint32(0, SIG_EOCD, true);
    eocdView.setUint16(4, 0, true);
    eocdView.setUint16(6, 0, true);
    eocdView.setUint16(8, totalEntries >= ZIP64_MAGIC_16 ? ZIP64_MAGIC_16 : totalEntries, true);
    eocdView.setUint16(10, totalEntries >= ZIP64_MAGIC_16 ? ZIP64_MAGIC_16 : totalEntries, true);
    eocdView.setUint32(12, cdSize >= ZIP64_MAGIC_32 ? ZIP64_MAGIC_32 : cdSize >>> 0, true);
    eocdView.setUint32(16, cdOffset >= ZIP64_MAGIC_32 ? ZIP64_MAGIC_32 : cdOffset >>> 0, true);
    eocdView.setUint16(20, 0, true);
    await this.sink.writeBytes(eocd);
    this.offset += eocd.length;
  }
}

/**
 * Creates a RandomAccessSource backed by a browser/Node File or Blob.
 */
export function createBlobSource(blob: Blob): RandomAccessSource {
  return {
    size: blob.size,
    async readRange(start: number, end: number): Promise<Uint8Array<ArrayBuffer>> {
      const ab = await blob.slice(start, end).arrayBuffer();
      return new Uint8Array(ab);
    },
    sliceBlob(start: number, end: number): Blob {
      return blob.slice(start, end);
    },
    streamRange(start: number, end: number): ReadableStream<Uint8Array<ArrayBuffer>> {
      return blob.slice(start, end).stream();
    },
  };
}

/**
 * In-memory Blob-part accumulator for browsers.
 * Untouched ZIP payloads are stored as zero-copy Blob slices from the original File.
 */
export class BlobZipSink implements ZipOutputSink {
  private readonly parts: BlobPart[] = [];

  async writeBytes(data: Uint8Array<ArrayBuffer>): Promise<void> {
    this.parts.push(data);
  }

  async copySourceRange(
    source: RandomAccessSource,
    start: number,
    end: number
  ): Promise<void> {
    if (source.sliceBlob !== undefined) {
      this.parts.push(source.sliceBlob(start, end));
      return;
    }
    const chunkSize = 1024 * 1024;
    for (let pos = start; pos < end; pos += chunkSize) {
      const chunkEnd = Math.min(end, pos + chunkSize);
      this.parts.push(await source.readRange(pos, chunkEnd));
    }
  }

  toBlob(): Blob {
    return new Blob(this.parts, { type: "application/octet-stream" });
  }
}
