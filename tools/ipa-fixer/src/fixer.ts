import {
  createPatchAndCrcTransform,
  inspectMachOStream,
} from "./macho.js";
import type {
  FixIpaBlobResult,
  FixIpaOptions,
  PatchDetail,
  ProgressEvent,
  RandomAccessSource,
  ScanStats,
  ZipOutputSink,
} from "./types.js";
import {
  BlobZipSink,
  ZipStreamWriter,
  createBlobSource,
  getEntryDataRange,
  openEntryDecompressedStream,
  readZipCentralDirectory,
  type ZipEntry,
} from "./zip.js";

const NON_MACHO_EXTENSIONS = new Set<string>([
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
  ".stringsdict",
]);

const RE_EXTENSIONKIT = /^(Payload\/[^/]+\.app\/Extensions)(?:\/|$)/;
const RE_PLUGINS = /^(Payload\/[^/]+\.app\/PlugIns)(?:\/|$)/;
const RE_CODESIGNATURE = /^(.*?_CodeSignature)(?:\/|$)/;

function shouldCheckAsMachO(fileName: string): boolean {
  const slashIdx = fileName.lastIndexOf("/");
  const baseName = slashIdx >= 0 ? fileName.slice(slashIdx + 1) : fileName;
  const dotIdx = baseName.lastIndexOf(".");
  if (dotIdx <= 0) {
    return true;
  }
  const ext = baseName.slice(dotIdx).toLowerCase();
  return !NON_MACHO_EXTENSIONS.has(ext);
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DOMException("Operation aborted", "AbortError");
  }
}

async function recompressPatchedStream(
  decompressedStream: ReadableStream<Uint8Array<ArrayBuffer>>,
  patchTransform: ReturnType<typeof createPatchAndCrcTransform>,
  signal: AbortSignal | undefined
): Promise<{
  chunks: Uint8Array<ArrayBuffer>[];
  compressedSize: number;
  crc32: number;
  uncompressedSize: number;
}> {
  const compressedStream = decompressedStream
    .pipeThrough(patchTransform.transform)
    .pipeThrough(new CompressionStream("deflate-raw"));

  const reader = compressedStream.getReader();
  const chunks: Uint8Array<ArrayBuffer>[] = [];
  let compressedSize = 0;

  try {
    while (true) {
      throwIfAborted(signal);
      const { value, done } = await reader.read();
      if (done || value === undefined) {
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
      // Ignore cancel errors
    }
    throw err;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Ignore lock release errors
    }
  }

  const { crc32, uncompressedSize } = patchTransform.getResult();
  return { chunks, compressedSize, crc32, uncompressedSize };
}

/**
 * Inspects and optionally repairs + repackages an IPA from any RandomAccessSource into a ZipOutputSink.
 * Untouched assets and healthy binaries are passed through as raw compressed byte ranges without recompression.
 */
export async function fixIpa(
  source: RandomAccessSource,
  sink: ZipOutputSink | null,
  options: FixIpaOptions = {}
): Promise<ScanStats> {
  const startedAt = performance.now();
  const stripExtensionKit = Boolean(options.stripExtensionKit || options.stripExtensions);
  const stripPlugIns = Boolean(options.stripPlugIns || options.stripExtensions);
  const cleanSignatures = options.cleanSignatures ?? true;
  const dryRun = Boolean(options.dryRun || sink === null);
  const scanAllFiles = Boolean(options.scanAllFiles);
  const verbose = Boolean(options.verbose);
  const signal = options.signal;

  const emit = (event: ProgressEvent): void => {
    options.onProgress?.(event);
  };

  throwIfAborted(signal);
  emit({ type: "stage", stage: "reading-index", message: "Reading ZIP Central Directory..." });

  const entries = await readZipCentralDirectory(source);
  throwIfAborted(signal);

  const removedExtKitFolders = new Set<string>();
  const removedPlugInsFolders = new Set<string>();
  const removedSigFolders = new Set<string>();
  const keptEntries: ZipEntry[] = [];
  let entriesRemoved = 0;

  for (const entry of entries) {
    throwIfAborted(signal);
    const name = entry.fileName;

    if (stripExtensionKit) {
      const m = RE_EXTENSIONKIT.exec(name);
      if (m?.[1] !== undefined) {
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
      if (m?.[1] !== undefined) {
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
      if (m?.[1] !== undefined) {
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
    message: dryRun
      ? `Scanning ${keptEntries.length} entries for ldid assertion defects...`
      : `Scanning & repackaging ${keptEntries.length} entries...`,
  });

  const writer = !dryRun && sink !== null ? new ZipStreamWriter(sink) : null;

  let binariesScanned = 0;
  let binariesAffected = 0;
  let offsetsFound = 0;
  const details: PatchDetail[] = [];

  for (let i = 0; i < keptEntries.length; i++) {
    throwIfAborted(signal);
    const entry = keptEntries[i]!;
    emit({
      type: "progress",
      completed: i,
      total: keptEntries.length,
      currentFile: entry.fileName,
    });

    const isCandidate =
      !entry.isDirectory &&
      !entry.isSymlink &&
      entry.uncompressedSize >= 28 &&
      (entry.compressionMethod === 0 || entry.compressionMethod === 8) &&
      (scanAllFiles || shouldCheckAsMachO(entry.fileName));

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
          const detail: PatchDetail = {
            file: entry.fileName,
            offset: p.strsizeFileOffset,
            oldVal: p.oldStrsize,
            newVal: p.newStrsize,
            gap: p.gap,
            sliceOffset: p.sliceOffset,
          };
          details.push(detail);
          emit({ type: "patch", detail, dryRun });
        }

        if (writer !== null) {
          const patchStream = openEntryDecompressedStream(source, entry, dataStart, dataEnd);
          const patchTransform = createPatchAndCrcTransform(result.patches);
          const { chunks, compressedSize, crc32, uncompressedSize } =
            await recompressPatchedStream(patchStream, patchTransform, signal);

          if (uncompressedSize !== entry.uncompressedSize) {
            throw new Error(
              `Uncompressed size mismatch after patching ${entry.fileName}: expected ${entry.uncompressedSize}, got ${uncompressedSize}`
            );
          }

          await writer.writeCompressedChunksEntry(
            entry,
            chunks,
            crc32,
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
    currentFile: "",
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
    details,
  };
}

/**
 * Inspects and fixes an IPA File or Blob completely client-side, returning stats and the patched Blob.
 */
export async function fixIpaBlob(
  blob: Blob,
  options: FixIpaOptions = {}
): Promise<FixIpaBlobResult> {
  const source = createBlobSource(blob);
  const dryRun = Boolean(options.dryRun);
  const sink = dryRun ? null : new BlobZipSink();
  const stats = await fixIpa(source, sink, options);
  return {
    stats,
    blob: sink !== null ? sink.toBlob() : null,
  };
}

/**
 * Convenience wrapper that inspects an IPA Blob without modifying or repackaging it.
 */
export async function inspectIpaBlob(
  blob: Blob,
  options: Omit<FixIpaOptions, "dryRun"> = {}
): Promise<ScanStats> {
  const source = createBlobSource(blob);
  return fixIpa(source, null, { ...options, dryRun: true });
}
