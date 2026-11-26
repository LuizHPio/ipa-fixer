// src/crc32.ts
var CRC32_INIT = 4294967295;
var CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = (c & 1) !== 0 ? 3988292384 ^ c >>> 1 : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}
function crc32Update(crc, data) {
  let current = crc >>> 0;
  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    current = (CRC_TABLE[(current ^ byte) & 255] ^ current >>> 8) >>> 0;
  }
  return current >>> 0;
}
function crc32Finalize(crc) {
  return (crc ^ 4294967295) >>> 0;
}
function crc32(data) {
  return crc32Finalize(crc32Update(CRC32_INIT, data));
}

// src/macho.ts
var MH_MAGIC = 4277009102;
var MH_CIGAM = 3472551422;
var MH_MAGIC_64 = 4277009103;
var MH_CIGAM_64 = 3489328638;
var FAT_MAGIC = 3405691582;
var FAT_CIGAM = 3199925962;
var FAT_MAGIC_64 = 3405691583;
var FAT_CIGAM_64 = 3216703178;
var LC_SYMTAB = 2;
var LC_CODE_SIGNATURE = 29;
function isThinMachOMagic(magic) {
  return magic === MH_MAGIC || magic === MH_CIGAM || magic === MH_MAGIC_64 || magic === MH_CIGAM_64;
}
function getHeaderInfo(magic) {
  if (magic === MH_MAGIC || magic === MH_CIGAM) {
    return { is64: false, littleEndian: magic === MH_CIGAM, hdrSize: 28 };
  }
  if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) {
    return { is64: true, littleEndian: magic === MH_CIGAM_64, hdrSize: 32 };
  }
  return null;
}
function parseMachOSliceHeader(headerAndCmds, sliceOffset) {
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
  let symtabCmdOffset = null;
  let symtabStroff = null;
  let symtabStrsize = null;
  let sigDataoff = null;
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
  if (symtabCmdOffset === null || symtabStroff === null || symtabStrsize === null || sigDataoff === null) {
    return { sliceInfo: null, patch: null };
  }
  if (symtabStroff === 0 && symtabStrsize === 0) {
    return { sliceInfo: null, patch: null };
  }
  const size = sigDataoff;
  const end = symtabStroff + symtabStrsize;
  const gap = size - end;
  const sliceInfo = {
    sliceOffset,
    cputype,
    littleEndian,
    stroff: symtabStroff,
    strsize: symtabStrsize,
    sigDataoff,
    end,
    gap
  };
  if (end < size - 16) {
    const newStrsize = size - symtabStroff;
    const strsizeFileOffset = sliceOffset + symtabCmdOffset + 20;
    const patch = {
      sliceOffset,
      cputype,
      littleEndian,
      oldStrsize: symtabStrsize,
      newStrsize,
      oldEnd: end,
      newEnd: size,
      gap,
      strsizeFileOffset
    };
    return { sliceInfo, patch };
  }
  return { sliceInfo, patch: null };
}
var StreamCursor = class {
  reader;
  head = null;
  headOffset = 0;
  position = 0;
  ended = false;
  constructor(stream) {
    this.reader = stream.getReader();
  }
  get bytesRead() {
    return this.position;
  }
  async ensureHead() {
    while (this.head === null || this.headOffset >= this.head.length) {
      if (this.ended) {
        return false;
      }
      const { value, done } = await this.reader.read();
      if (done || value === void 0) {
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
  async readExact(n) {
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
  async skipTo(targetPos) {
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
  async close() {
    try {
      await this.reader.cancel();
    } catch {
    } finally {
      try {
        this.reader.releaseLock();
      } catch {
      }
    }
  }
};
async function inspectThinSliceFromCursor(cursor, magicBytes, sliceOffset) {
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
async function inspectMachOStream(stream, fileSize) {
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
        patches: res.patch ? [res.patch] : []
      };
    }
    if (magic === FAT_MAGIC || magic === FAT_CIGAM || magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64) {
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
      const offsets = [];
      for (let i = 0; i < nfatArch; i++) {
        const entryOff = i * archSize;
        let offset;
        let size;
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
      const slices = [];
      const patches = [];
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
        patches
      };
    }
    return { isMachO: false, slices: [], patches: [] };
  } finally {
    await cursor.close();
  }
}
function createPatchAndCrcTransform(patches) {
  const encoded = patches.map((p) => {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, p.newStrsize, p.littleEndian);
    return { offset: p.strsizeFileOffset, bytes: buf };
  });
  let streamOffset = 0;
  let crc = CRC32_INIT;
  const transform = new TransformStream({
    transform(chunk, controller) {
      const chunkStart = streamOffset;
      const chunkEnd = chunkStart + chunk.length;
      streamOffset = chunkEnd;
      let outChunk = null;
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
            outChunk[pos - chunkStart] = ep.bytes[pos - patchStart];
          }
        }
      }
      const finalChunk = outChunk !== null ? outChunk : (() => {
        const copy = new Uint8Array(chunk.length);
        copy.set(chunk);
        return copy;
      })();
      crc = crc32Update(crc, finalChunk);
      controller.enqueue(finalChunk);
    }
  });
  return {
    transform,
    getResult: () => ({
      crc32: crc32Finalize(crc),
      uncompressedSize: streamOffset
    })
  };
}

// src/zip.ts
var SIG_LFH = 67324752;
var SIG_CD = 33639248;
var SIG_EOCD = 101010256;
var SIG_ZIP64_EOCD = 101075792;
var SIG_ZIP64_LOCATOR = 117853008;
var FLAG_DATA_DESCRIPTOR = 8;
var FLAG_UTF8 = 2048;
var ZIP64_MAGIC_32 = 4294967295;
var ZIP64_MAGIC_16 = 65535;
var UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
function toSafeNumber(val, label) {
  if (val > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`ZIP ${label} exceeds MAX_SAFE_INTEGER`);
  }
  return Number(val);
}
async function readZipCentralDirectory(source) {
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
  if (totalEntries === ZIP64_MAGIC_16 || cdSize === ZIP64_MAGIC_32 || cdOffset === ZIP64_MAGIC_32) {
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
  const entries = [];
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
    const crc322 = cdView.getUint32(pos + 16, true);
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
    if (uncompressedSize === ZIP64_MAGIC_32 || compressedSize === ZIP64_MAGIC_32 || localHeaderOffset === ZIP64_MAGIC_32) {
      const extraStart = pos + 46 + nameLen;
      const extraEnd = extraStart + extraLen;
      let ep = extraStart;
      while (ep + 4 <= extraEnd) {
        const tag = cdView.getUint16(ep, true);
        const size = cdView.getUint16(ep + 2, true);
        if (tag === 1 && ep + 4 + size <= extraEnd) {
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
    const unixMode = externalAttr >>> 16 & 61440;
    const isDirectory = fileName.endsWith("/");
    const isSymlink = unixMode === 40960;
    entries.push({
      fileName,
      fileNameBytes,
      versionMadeBy,
      versionNeeded,
      flags,
      compressionMethod,
      modTime,
      modDate,
      crc32: crc322,
      compressedSize,
      uncompressedSize,
      internalAttr,
      externalAttr,
      localHeaderOffset,
      isDirectory,
      isSymlink
    });
    pos = recordEnd;
  }
  return entries;
}
async function getEntryDataRange(source, entry) {
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
function openEntryDecompressedStream(source, entry, dataStart, dataEnd) {
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
var ZipStreamWriter = class {
  offset = 0;
  records = [];
  sink;
  constructor(sink) {
    this.sink = sink;
  }
  get bytesWritten() {
    return this.offset;
  }
  async writeHeaderAndRecord(entry, crc32Val, compressedSize, uncompressedSize, compressionMethod) {
    const localHeaderOffset = this.offset;
    const cleanFlags = entry.flags & ~FLAG_DATA_DESCRIPTOR;
    const needsZip64Lfh = compressedSize >= ZIP64_MAGIC_32 || uncompressedSize >= ZIP64_MAGIC_32;
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
      view.setUint16(ep, 1, true);
      view.setUint16(ep + 2, 16, true);
      view.setBigUint64(ep + 4, BigInt(uncompressedSize), true);
      view.setBigUint64(ep + 12, BigInt(compressedSize), true);
    }
    await this.sink.writeBytes(lfh);
    this.offset += lfh.length;
    this.records.push({
      entry: { ...entry, versionNeeded: needsZip64Lfh ? versionNeeded : entry.versionNeeded },
      flags: cleanFlags | entry.flags & FLAG_UTF8,
      compressionMethod,
      crc32: crc32Val >>> 0,
      compressedSize,
      uncompressedSize,
      localHeaderOffset
    });
  }
  /**
   * Copies an untouched compressed (or stored) entry straight from source without recompression.
   */
  async writeRawEntry(source, entry, dataStart, dataEnd) {
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
  async writeCompressedChunksEntry(entry, chunks, crc32Val, compressedSize, uncompressedSize, compressionMethod) {
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
  async finalize() {
    const cdOffset = this.offset;
    const cdParts = [];
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
      const versionNeeded = zip64PayloadLen > 0 ? Math.max(entry.versionNeeded, 45) : entry.versionNeeded;
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
        view.setUint16(ep, 1, true);
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
    const BATCH_LIMIT = 512 * 1024;
    let batch = [];
    let batchBytes = 0;
    const flushBatch = async () => {
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
    const needsZip64Eocd = totalEntries >= ZIP64_MAGIC_16 || cdSize >= ZIP64_MAGIC_32 || cdOffset >= ZIP64_MAGIC_32;
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
};
function createBlobSource(blob) {
  return {
    size: blob.size,
    async readRange(start, end) {
      const ab = await blob.slice(start, end).arrayBuffer();
      return new Uint8Array(ab);
    },
    sliceBlob(start, end) {
      return blob.slice(start, end);
    },
    streamRange(start, end) {
      return blob.slice(start, end).stream();
    }
  };
}
var BlobZipSink = class {
  parts = [];
  async writeBytes(data) {
    this.parts.push(data);
  }
  async copySourceRange(source, start, end) {
    if (source.sliceBlob !== void 0) {
      this.parts.push(source.sliceBlob(start, end));
      return;
    }
    const chunkSize = 1024 * 1024;
    for (let pos = start; pos < end; pos += chunkSize) {
      const chunkEnd = Math.min(end, pos + chunkSize);
      this.parts.push(await source.readRange(pos, chunkEnd));
    }
  }
  toBlob() {
    return new Blob(this.parts, { type: "application/octet-stream" });
  }
};

// src/fixer.ts
var NON_MACHO_EXTENSIONS = /* @__PURE__ */ new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".svg",
  ".car",
  ".nib",
  ".strings",
  ".plist",
  ".json",
  ".xml",
  ".html",
  ".htm",
  ".css",
  ".js",
  ".m4a",
  ".m4r",
  ".caf",
  ".mp3",
  ".mp4",
  ".mov",
  ".wav",
  ".ttf",
  ".otf",
  ".woff",
  ".woff2",
  ".pdf",
  ".txt",
  ".md",
  ".zip",
  ".xcprivacy",
  ".metallib",
  ".values",
  ".argo",
  ".appexpt",
  ".mobileprovision",
  ".cer",
  ".pem",
  ".crt",
  ".der",
  ".mom",
  ".omo",
  ".icns",
  ".ico",
  ".h",
  ".m",
  ".swift",
  ".tbd",
  ".modulemap",
  ".storyboard",
  ".xib",
  ".stringsdict"
]);
var RE_EXTENSIONKIT = /^(Payload\/[^/]+\.app\/Extensions)(?:\/|$)/;
var RE_PLUGINS = /^(Payload\/[^/]+\.app\/PlugIns)(?:\/|$)/;
var RE_CODESIGNATURE = /^(.*?_CodeSignature)(?:\/|$)/;
function shouldCheckAsMachO(fileName) {
  const slashIdx = fileName.lastIndexOf("/");
  const baseName = slashIdx >= 0 ? fileName.slice(slashIdx + 1) : fileName;
  const dotIdx = baseName.lastIndexOf(".");
  if (dotIdx <= 0) {
    return true;
  }
  const ext = baseName.slice(dotIdx).toLowerCase();
  return !NON_MACHO_EXTENSIONS.has(ext);
}
function throwIfAborted(signal) {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new DOMException("Operation aborted", "AbortError");
  }
}
async function recompressPatchedStream(decompressedStream, patchTransform, signal) {
  const compressedStream = decompressedStream.pipeThrough(patchTransform.transform).pipeThrough(new CompressionStream("deflate-raw"));
  const reader = compressedStream.getReader();
  const chunks = [];
  let compressedSize = 0;
  try {
    while (true) {
      throwIfAborted(signal);
      const { value, done } = await reader.read();
      if (done || value === void 0) {
        break;
      }
      if (value.length > 0) {
        const copy = new Uint8Array(value.length);
        copy.set(value);
        chunks.push(copy);
        compressedSize += copy.length;
      }
    }
  } catch (err) {
    try {
      await reader.cancel();
    } catch {
    }
    throw err;
  } finally {
    try {
      reader.releaseLock();
    } catch {
    }
  }
  const { crc32: crc322, uncompressedSize } = patchTransform.getResult();
  return { chunks, compressedSize, crc32: crc322, uncompressedSize };
}
async function fixIpa(source, sink, options = {}) {
  const startedAt = performance.now();
  const stripExtensionKit = Boolean(options.stripExtensionKit || options.stripExtensions);
  const stripPlugIns = Boolean(options.stripPlugIns || options.stripExtensions);
  const cleanSignatures = options.cleanSignatures ?? true;
  const dryRun = Boolean(options.dryRun || sink === null);
  const scanAllFiles = Boolean(options.scanAllFiles);
  const verbose = Boolean(options.verbose);
  const signal = options.signal;
  const emit = (event) => {
    options.onProgress?.(event);
  };
  throwIfAborted(signal);
  emit({ type: "stage", stage: "reading-index", message: "Reading ZIP Central Directory..." });
  const entries = await readZipCentralDirectory(source);
  throwIfAborted(signal);
  const removedExtKitFolders = /* @__PURE__ */ new Set();
  const removedPlugInsFolders = /* @__PURE__ */ new Set();
  const removedSigFolders = /* @__PURE__ */ new Set();
  const keptEntries = [];
  let entriesRemoved = 0;
  for (const entry of entries) {
    throwIfAborted(signal);
    const name = entry.fileName;
    if (stripExtensionKit) {
      const m = RE_EXTENSIONKIT.exec(name);
      if (m?.[1] !== void 0) {
        const folder = m[1];
        if (!removedExtKitFolders.has(folder)) {
          removedExtKitFolders.add(folder);
          emit({ type: "remove", category: "extensionkit", path: folder, dryRun });
        }
        entriesRemoved++;
        continue;
      }
    }
    if (stripPlugIns) {
      const m = RE_PLUGINS.exec(name);
      if (m?.[1] !== void 0) {
        const folder = m[1];
        if (!removedPlugInsFolders.has(folder)) {
          removedPlugInsFolders.add(folder);
          emit({ type: "remove", category: "plugins", path: folder, dryRun });
        }
        entriesRemoved++;
        continue;
      }
    }
    if (cleanSignatures) {
      const m = RE_CODESIGNATURE.exec(name);
      if (m?.[1] !== void 0) {
        const folder = m[1];
        if (!removedSigFolders.has(folder)) {
          removedSigFolders.add(folder);
          emit({ type: "remove", category: "signature", path: folder, dryRun });
        }
        entriesRemoved++;
        continue;
      }
    }
    keptEntries.push(entry);
  }
  emit({
    type: "stage",
    stage: "scanning",
    message: dryRun ? `Scanning ${keptEntries.length} entries for ldid assertion defects...` : `Scanning & repackaging ${keptEntries.length} entries...`
  });
  const writer = !dryRun && sink !== null ? new ZipStreamWriter(sink) : null;
  let binariesScanned = 0;
  let binariesAffected = 0;
  let offsetsFound = 0;
  const details = [];
  for (let i = 0; i < keptEntries.length; i++) {
    throwIfAborted(signal);
    const entry = keptEntries[i];
    emit({
      type: "progress",
      completed: i,
      total: keptEntries.length,
      currentFile: entry.fileName
    });
    const isCandidate = !entry.isDirectory && !entry.isSymlink && entry.uncompressedSize >= 28 && (entry.compressionMethod === 0 || entry.compressionMethod === 8) && (scanAllFiles || shouldCheckAsMachO(entry.fileName));
    if (isCandidate) {
      const { dataStart, dataEnd } = await getEntryDataRange(source, entry);
      const inspectStream = openEntryDecompressedStream(source, entry, dataStart, dataEnd);
      const result = await inspectMachOStream(inspectStream, entry.uncompressedSize);
      if (result.isMachO) {
        binariesScanned++;
        if (verbose) {
          emit({ type: "inspect", file: entry.fileName, slices: result.slices });
        }
      }
      if (result.patches.length > 0) {
        binariesAffected++;
        offsetsFound += result.patches.length;
        for (const p of result.patches) {
          const detail = {
            file: entry.fileName,
            offset: p.strsizeFileOffset,
            oldVal: p.oldStrsize,
            newVal: p.newStrsize,
            gap: p.gap,
            sliceOffset: p.sliceOffset
          };
          details.push(detail);
          emit({ type: "patch", detail, dryRun });
        }
        if (writer !== null) {
          const patchStream = openEntryDecompressedStream(source, entry, dataStart, dataEnd);
          const patchTransform = createPatchAndCrcTransform(result.patches);
          const { chunks, compressedSize, crc32: crc322, uncompressedSize } = await recompressPatchedStream(patchStream, patchTransform, signal);
          if (uncompressedSize !== entry.uncompressedSize) {
            throw new Error(
              `Uncompressed size mismatch after patching ${entry.fileName}: expected ${entry.uncompressedSize}, got ${uncompressedSize}`
            );
          }
          await writer.writeCompressedChunksEntry(
            entry,
            chunks,
            crc322,
            compressedSize,
            uncompressedSize,
            8
          );
        }
        continue;
      }
      if (writer !== null) {
        await writer.writeRawEntry(source, entry, dataStart, dataEnd);
      }
      continue;
    }
    if (writer !== null) {
      const { dataStart, dataEnd } = await getEntryDataRange(source, entry);
      await writer.writeRawEntry(source, entry, dataStart, dataEnd);
    }
  }
  emit({
    type: "progress",
    completed: keptEntries.length,
    total: keptEntries.length,
    currentFile: ""
  });
  if (writer !== null) {
    emit({ type: "stage", stage: "writing", message: "Finalizing ZIP Central Directory..." });
    await writer.finalize();
  }
  const elapsedMs = Math.round(performance.now() - startedAt);
  emit({ type: "stage", stage: "done", message: "Complete" });
  return {
    binariesScanned,
    binariesAffected,
    offsetsFound,
    extensionKitFoldersRemoved: removedExtKitFolders.size,
    plugInsFoldersRemoved: removedPlugInsFolders.size,
    entriesRemoved,
    signaturesCleaned: removedSigFolders.size,
    totalEntriesIn: entries.length,
    totalEntriesOut: writer !== null ? keptEntries.length : 0,
    elapsedMs,
    details
  };
}
async function fixIpaBlob(blob, options = {}) {
  const source = createBlobSource(blob);
  const dryRun = Boolean(options.dryRun);
  const sink = dryRun ? null : new BlobZipSink();
  const stats = await fixIpa(source, sink, options);
  return {
    stats,
    blob: sink !== null ? sink.toBlob() : null
  };
}
async function inspectIpaBlob(blob, options = {}) {
  const source = createBlobSource(blob);
  return fixIpa(source, null, { ...options, dryRun: true });
}
export {
  BlobZipSink,
  CRC32_INIT,
  ZipStreamWriter,
  crc32,
  crc32Finalize,
  crc32Update,
  createBlobSource,
  createPatchAndCrcTransform,
  fixIpa,
  fixIpaBlob,
  getEntryDataRange,
  inspectIpaBlob,
  inspectMachOStream,
  openEntryDecompressedStream,
  parseMachOSliceHeader,
  readZipCentralDirectory
};
